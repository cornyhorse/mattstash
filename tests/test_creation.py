"""
Database creation, password precedence and the `setup` command.

Covers docs/security-review.md H-4 (data-loss paths), H-7 (file modes, precedence) and the
"only explicit setup creates a database" decision.
"""

import io
import os
import stat
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from pykeepass import PyKeePass

from mattstash import MattStash
from mattstash import delete as module_delete
from mattstash import get as module_get
from mattstash import put as module_put
from mattstash.cli import exit_codes
from mattstash.cli.main import main
from mattstash.core.bootstrap import DatabaseBootstrapper
from mattstash.core.password_resolver import PasswordResolver
from mattstash.utils.exceptions import (
    DatabaseAccessError,
    DatabaseExistsError,
    DatabaseNotFoundError,
    MattStashError,
)


def mode(path: Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def opens_with(path: Path, password: str) -> bool:
    try:
        PyKeePass(str(path), password=password)
        return True
    except Exception:
        return False


class FakeTTY(io.StringIO):
    def isatty(self) -> bool:
        return True


# ---------------------------------------------------------------------------
# Nothing creates a database implicitly (H-4b)
# ---------------------------------------------------------------------------


def test_constructor_never_creates(missing_db: Path):
    MattStash(path=str(missing_db), password="pw")
    assert list(missing_db.parent.iterdir()) == []


@pytest.mark.parametrize(
    "operation",
    [
        lambda ms: ms.get("x"),
        lambda ms: ms.list(),
        lambda ms: ms.list_versions("x"),
        lambda ms: ms.put("x", value="v"),
        lambda ms: ms.delete("x"),
        lambda ms: ms.hydrate_env({"x:FIELD": "SOME_ENV"}),
        lambda ms: ms.get_db_url("x"),
    ],
    ids=["get", "list", "versions", "put", "delete", "hydrate_env", "db_url"],
)
def test_no_operation_creates_a_missing_database(missing_db: Path, operation):
    ms = MattStash(path=str(missing_db), password="pw")
    with pytest.raises(DatabaseNotFoundError) as excinfo:
        operation(ms)
    assert str(missing_db) in str(excinfo.value)
    assert "setup" in str(excinfo.value)
    # neither database, sidecar nor lock file appeared
    assert list(missing_db.parent.iterdir()) == []


def test_missing_directory_reports_not_found_not_lock_error(tmp_path: Path):
    ms = MattStash(path=str(tmp_path / "no" / "such" / "dir" / "db.kdbx"), password="pw")
    with pytest.raises(DatabaseNotFoundError):
        ms.put("x", value="v")
    assert not (tmp_path / "no").exists()


def test_module_functions_never_create(missing_db: Path):
    for call in (
        lambda: module_get("x", path=str(missing_db), password="pw"),
        lambda: module_put("x", path=str(missing_db), db_password="pw", value="v"),
        lambda: module_delete("x", path=str(missing_db), password="pw"),
    ):
        with pytest.raises(DatabaseNotFoundError):
            call()
    assert list(missing_db.parent.iterdir()) == []


def test_cli_get_on_missing_db_exits_6_and_creates_nothing(missing_db: Path, caplog):
    rc = main(["--db", str(missing_db), "--password", "pw", "get", "x"])
    assert rc == exit_codes.DB_NOT_FOUND
    assert "mattstash setup" in caplog.text
    assert list(missing_db.parent.iterdir()) == []


def test_cli_put_on_missing_db_exits_6(missing_db: Path):
    assert main(["--db", str(missing_db), "--password", "pw", "put", "x", "--value", "v"]) == exit_codes.DB_NOT_FOUND
    assert list(missing_db.parent.iterdir()) == []


def test_cli_wrong_password_exits_7_not_2(temp_db: Path):
    assert main(["--db", str(temp_db), "--password", "wrong", "get", "x"]) == exit_codes.DB_ACCESS


def test_cli_missing_secret_is_still_exit_2(temp_db: Path):
    assert main(["--db", str(temp_db), "get", "no-such-secret"]) == exit_codes.NOT_FOUND


# ---------------------------------------------------------------------------
# MattStash.create / DatabaseBootstrapper.create (H-4a, H-4d, H-7a, H-7b)
# ---------------------------------------------------------------------------


def test_create_makes_private_files_and_opens(tmp_path: Path):
    db = tmp_path / "newdir" / "db.kdbx"
    ms, info = MattStash.create_with_info(str(db), sidecar=True)

    assert mode(db.parent) == 0o700  # we created the directory, so we lock it down
    assert mode(db) == 0o600
    assert info.sidecar_path and mode(Path(info.sidecar_path)) == 0o600
    assert info.generated is True
    assert ms.password == Path(info.sidecar_path).read_text()
    assert ms.list() == []
    # no temp/leftover files
    assert sorted(p.name for p in db.parent.iterdir()) == [".mattstash.txt", "db.kdbx"]


def test_create_does_not_change_permissions_of_an_existing_directory(tmp_path: Path):
    d = tmp_path / "shared"
    d.mkdir(mode=0o755)
    os.chmod(d, 0o755)  # noqa: S103 - deliberately permissive: create() must not tighten a pre-existing directory
    MattStash.create(str(d / "db.kdbx"), password="pw")
    assert mode(d) == 0o755


def test_create_without_sidecar_writes_no_password_file(tmp_path: Path):
    db = tmp_path / "db.kdbx"
    ms, info = MattStash.create_with_info(str(db), password="my-password")
    assert info.sidecar_path is None
    assert not (tmp_path / ".mattstash.txt").exists()
    assert info.generated is False
    assert opens_with(db, "my-password")
    assert ms.list() == []


def test_create_generates_a_password_when_none_given(tmp_path: Path):
    db = tmp_path / "db.kdbx"
    _, info = MattStash.create_with_info(str(db))
    assert info.generated is True and len(info.password) >= 32
    assert opens_with(db, info.password)


def test_create_honours_kdbx_password_env_and_writes_no_sidecar(tmp_path: Path, monkeypatch):
    """H-4d: an operator-supplied password must not be replaced by a random one."""
    monkeypatch.setenv("KDBX_PASSWORD", "operator-supplied")
    db = tmp_path / "db.kdbx"
    _, info = MattStash.create_with_info(str(db))
    assert info.generated is False and info.sidecar_path is None
    assert opens_with(db, "operator-supplied")
    assert not (tmp_path / ".mattstash.txt").exists()
    # and the library then opens it with that same password
    assert MattStash(path=str(db)).list() == []


def test_create_honours_kdbx_password_file_env(tmp_path: Path, monkeypatch):
    pwfile = tmp_path / "pw.txt"
    pwfile.write_text("from-a-file\n")
    monkeypatch.setenv("KDBX_PASSWORD_FILE", str(pwfile))
    db = tmp_path / "db.kdbx"
    MattStash.create(str(db))
    assert opens_with(db, "from-a-file")


def test_create_refuses_to_overwrite(temp_db: Path):
    before = temp_db.read_bytes()
    with pytest.raises(DatabaseExistsError):
        MattStash.create(str(temp_db), password="x")
    assert temp_db.read_bytes() == before


def test_create_refuses_when_only_a_sidecar_exists(missing_db: Path):
    (missing_db.parent / ".mattstash.txt").write_text("stale")
    with pytest.raises(DatabaseExistsError):
        MattStash.create(str(missing_db), password="x")


def test_force_backs_up_old_files_and_replaces_them(temp_db: Path):
    sidecar = temp_db.parent / ".mattstash.txt"
    old_password = sidecar.read_text()
    MattStash(path=str(temp_db)).put("important", value="hunter2")
    old_db = temp_db.read_bytes()

    _, info = MattStash.create_with_info(str(temp_db), password="new-pw", force=True, sidecar=True)

    # backups are reported in the order [database, sidecar]
    backup_db, backup_sidecar = (Path(b) for b in info.backups)
    assert ".bak-" in backup_db.name and ".bak-" in backup_sidecar.name
    assert backup_db.read_bytes() == old_db
    assert backup_sidecar.read_text() == old_password
    assert mode(backup_db) == 0o600 and mode(backup_sidecar) == 0o600
    # old data is recoverable from the backup; the new DB is empty and uses the new password
    assert [e.title for e in PyKeePass(str(backup_db), password=old_password).entries] == ["important@0000000001"]
    assert MattStash(path=str(temp_db)).list() == []
    assert sidecar.read_text() == "new-pw"


def test_force_without_sidecar_removes_the_stale_sidecar(temp_db: Path):
    sidecar = temp_db.parent / ".mattstash.txt"
    assert sidecar.exists()
    _, info = MattStash.create_with_info(str(temp_db), password="new-pw", force=True)
    assert not sidecar.exists()  # it held the OLD password and would mislead the resolver
    assert len(info.backups) == 2 and all(".bak-" in b for b in info.backups)
    assert opens_with(temp_db, "new-pw")


def test_failed_force_creation_leaves_existing_files_untouched(temp_db: Path):
    """H-4a: a failure must never lose the old DB *or* the old sidecar."""
    sidecar = temp_db.parent / ".mattstash.txt"
    before = (temp_db.read_bytes(), sidecar.read_bytes())

    with patch("mattstash.core.bootstrap._kp_create_database", side_effect=Exception("disk full")):
        with pytest.raises(MattStashError):
            MattStash.create(str(temp_db), password="new", force=True, sidecar=True)

    assert (temp_db.read_bytes(), sidecar.read_bytes()) == before
    assert sorted(p.name for p in temp_db.parent.iterdir() if ".bak-" not in p.name) == [".mattstash.txt", "test.kdbx"]


def test_force_no_backup(temp_db: Path):
    _, info = MattStash.create_with_info(str(temp_db), password="p", force=True, backup=False)
    assert info.backups == []
    assert not [p for p in temp_db.parent.iterdir() if ".bak-" in p.name]


def test_bootstrapper_lists_existing_files(temp_db: Path):
    assert len(DatabaseBootstrapper(str(temp_db)).existing_files()) == 2


# ---------------------------------------------------------------------------
# Password precedence (H-7d) and KDBX_PASSWORD_FILE
# ---------------------------------------------------------------------------


def test_precedence_explicit_env_file_sidecar(temp_db: Path, tmp_path: Path, monkeypatch):
    sidecar_pw = (temp_db.parent / ".mattstash.txt").read_text()
    resolver = PasswordResolver(str(temp_db))
    assert resolver.resolve_password() == sidecar_pw  # only the sidecar is available

    pwfile = tmp_path / "pw.txt"
    pwfile.write_text("file-pw\n")
    monkeypatch.setenv("KDBX_PASSWORD_FILE", str(pwfile))
    assert resolver.resolve_password() == "file-pw"  # file beats sidecar

    monkeypatch.setenv("KDBX_PASSWORD", "env-pw")
    assert resolver.resolve_password() == "env-pw"  # env beats file

    assert MattStash(path=str(temp_db), password="explicit").password == "explicit"  # explicit beats all
    assert MattStash(path=str(temp_db)).password == "env-pw"


def test_empty_env_var_is_ignored(temp_db: Path, monkeypatch):
    monkeypatch.setenv("KDBX_PASSWORD", "")
    assert MattStash(path=str(temp_db)).password == (temp_db.parent / ".mattstash.txt").read_text()


def test_unreadable_password_file_is_an_error_not_a_silent_fallback(temp_db: Path, tmp_path: Path, monkeypatch):
    monkeypatch.setenv("KDBX_PASSWORD_FILE", str(tmp_path / "does-not-exist"))
    with pytest.raises(DatabaseAccessError, match="KDBX_PASSWORD_FILE"):
        MattStash(path=str(temp_db))


def test_operator_password_beats_stale_sidecar(tmp_path: Path, monkeypatch):
    """The old order let a stale sidecar silently win over KDBX_PASSWORD."""
    db = tmp_path / "db.kdbx"
    MattStash.create(str(db), password="right")
    (tmp_path / ".mattstash.txt").write_text("stale-and-wrong")
    monkeypatch.setenv("KDBX_PASSWORD", "right")
    assert MattStash(path=str(db)).list() == []


def test_insecure_sidecar_permissions_warn(temp_db: Path, caplog):
    os.chmod(temp_db.parent / ".mattstash.txt", 0o644)
    with caplog.at_level("WARNING"):
        MattStash(path=str(temp_db))
    assert "insecure permissions" in caplog.text


def test_insecure_database_permissions_warn(temp_db: Path, caplog):
    os.chmod(temp_db, 0o644)
    with caplog.at_level("WARNING"):
        MattStash(path=str(temp_db)).list()
    assert "Database file has insecure permissions" in caplog.text


# ---------------------------------------------------------------------------
# `mattstash setup`
# ---------------------------------------------------------------------------


def run_setup(db: Path, *extra: str) -> int:
    return main(["--db", str(db), "setup", *extra])


def test_setup_sidecar(missing_db: Path):
    assert run_setup(missing_db, "--sidecar") == exit_codes.OK
    assert (missing_db.parent / ".mattstash.txt").exists()
    assert MattStash(path=str(missing_db)).list() == []
    assert mode(missing_db) == 0o600


def test_setup_password_file(missing_db: Path, tmp_path: Path):
    pwfile = tmp_path / "secret.txt"
    pwfile.write_text("file-secret\n")
    assert run_setup(missing_db, "--password-file", str(pwfile)) == exit_codes.OK
    assert opens_with(missing_db, "file-secret")
    assert not (missing_db.parent / ".mattstash.txt").exists()


def test_setup_password_stdin(missing_db: Path, monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.StringIO("stdin-secret\n"))
    assert run_setup(missing_db, "--password-stdin") == exit_codes.OK
    assert opens_with(missing_db, "stdin-secret")


def test_setup_empty_stdin_password_is_rejected(missing_db: Path, monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.StringIO("\n"))
    assert run_setup(missing_db, "--password-stdin") == exit_codes.ERROR
    assert not missing_db.exists()


def test_setup_prompts_by_default(missing_db: Path, monkeypatch):
    monkeypatch.setattr(sys, "stdin", FakeTTY())
    answers = iter(["typed-secret", "typed-secret"])
    with patch("mattstash.cli.handlers.setup.getpass.getpass", lambda prompt="": next(answers)):
        assert run_setup(missing_db) == exit_codes.OK
    assert opens_with(missing_db, "typed-secret")
    assert not (missing_db.parent / ".mattstash.txt").exists()


def test_setup_prompt_mismatch_creates_nothing(missing_db: Path, monkeypatch):
    monkeypatch.setattr(sys, "stdin", FakeTTY())
    answers = iter(["one", "two"])
    with patch("mattstash.cli.handlers.setup.getpass.getpass", lambda prompt="": next(answers)):
        assert run_setup(missing_db) == exit_codes.ERROR
    assert not missing_db.exists()


def test_setup_non_interactive_without_a_password_source_fails(missing_db: Path, monkeypatch, caplog):
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    assert run_setup(missing_db) == exit_codes.ERROR
    assert "--sidecar" in caplog.text
    assert not missing_db.exists()


def test_setup_generate_prints_the_password_once(missing_db: Path, capsys):
    assert run_setup(missing_db, "--generate") == exit_codes.OK
    out = capsys.readouterr().out
    password = out.split("store it safely): ")[1].split()[0]
    assert opens_with(missing_db, password)
    assert not (missing_db.parent / ".mattstash.txt").exists()


def test_setup_uses_kdbx_password_env(missing_db: Path, monkeypatch):
    monkeypatch.setenv("KDBX_PASSWORD", "from-env")
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    assert run_setup(missing_db) == exit_codes.OK
    assert opens_with(missing_db, "from-env")


def test_setup_refuses_existing_without_force(temp_db: Path):
    before = temp_db.read_bytes()
    assert run_setup(temp_db, "--sidecar") == exit_codes.WOULD_OVERWRITE
    assert temp_db.read_bytes() == before


def test_setup_force_non_interactive_needs_yes(temp_db: Path, monkeypatch):
    before = temp_db.read_bytes()
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    assert run_setup(temp_db, "--force", "--sidecar") == exit_codes.WOULD_OVERWRITE
    assert temp_db.read_bytes() == before


def test_setup_force_yes_replaces_and_backs_up(temp_db: Path, capsys):
    MattStash(path=str(temp_db)).put("important", value="hunter2")
    assert run_setup(temp_db, "--force", "--yes", "--sidecar") == exit_codes.OK
    assert "Backed up previous file" in capsys.readouterr().out
    assert len([p for p in temp_db.parent.iterdir() if ".bak-" in p.name]) == 2
    assert MattStash(path=str(temp_db)).list() == []


def test_setup_force_interactive_confirmation_declined(temp_db: Path, monkeypatch):
    before = temp_db.read_bytes()
    monkeypatch.setattr(sys, "stdin", FakeTTY())
    with patch("builtins.input", return_value="no"):
        assert run_setup(temp_db, "--force", "--sidecar") == exit_codes.WOULD_OVERWRITE
    assert temp_db.read_bytes() == before


def test_setup_force_interactive_confirmation_accepted(temp_db: Path, monkeypatch):
    monkeypatch.setattr(sys, "stdin", FakeTTY())
    with patch("builtins.input", return_value="yes"):
        assert run_setup(temp_db, "--force", "--sidecar") == exit_codes.OK
    assert MattStash(path=str(temp_db)).list() == []


def test_setup_creation_failure_is_reported_and_leaves_old_files(temp_db: Path, caplog):
    before = temp_db.read_bytes()
    with patch("mattstash.core.bootstrap._kp_create_database", side_effect=Exception("boom")):
        rc = run_setup(temp_db, "--force", "--yes", "--sidecar")
    assert rc == exit_codes.ERROR
    assert temp_db.read_bytes() == before
    assert "boom" in caplog.text
