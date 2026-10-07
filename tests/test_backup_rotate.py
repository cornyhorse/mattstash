"""``backup`` and ``rotate-password`` (docs/security-review.md G-2): library and CLI."""

import errno
import io
import os
import re
import stat
import sys
import threading
from pathlib import Path
from typing import List
from unittest.mock import patch

import pytest
from dbhelpers import create_db
from fake_server import FakeServer
from pykeepass import PyKeePass

from mattstash import MattStash
from mattstash.cli import exit_codes
from mattstash.cli.main import main
from mattstash.credential_store import CredentialStore
from mattstash.utils.exceptions import (
    DatabaseAccessError,
    DatabaseExistsError,
    DatabaseLockError,
    DatabaseNotFoundError,
    InvalidCredentialError,
    MattStashError,
    SidecarUpdateError,
)
from mattstash.utils.filelock import FileLock

OLD = "old-master-pw"
NEW = "new-master-pw"


def mode(path: Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def opens_with(path: Path, password: str) -> bool:
    try:
        PyKeePass(str(path), password=password)
        return True
    except Exception:
        return False


def titles(path: Path, password: str) -> List[str]:
    return sorted(e.title for e in PyKeePass(str(path), password=password).entries)


def siblings(db: Path) -> List[str]:
    return sorted(p.name for p in db.parent.iterdir())


def backups(db: Path) -> List[Path]:
    return sorted(db.parent.glob(db.name + ".bak-*"))


class FakeTTY(io.StringIO):
    def isatty(self) -> bool:
        return True


@pytest.fixture()
def seeded(tmp_path: Path) -> Path:
    """Database with master password OLD, a sidecar holding OLD, and two entries."""
    return create_db(
        tmp_path / "data" / "s.kdbx",
        [
            {"title": "a", "password": "A-secret"},
            {"title": "b", "username": "u", "password": "B-secret", "url": "h:1"},
        ],
        password=OLD,
    )


@pytest.fixture()
def seeded_no_sidecar(tmp_path: Path) -> Path:
    return create_db(tmp_path / "ns" / "s.kdbx", [{"title": "a", "password": "A-secret"}], password=OLD, sidecar=False)


def sidecar_of(db: Path) -> Path:
    return db.parent / ".mattstash.txt"


# ---------------------------------------------------------------------------
# MattStash.backup
# ---------------------------------------------------------------------------


def test_backup_default_destination_contents_and_mode(seeded: Path):
    ms = MattStash(path=str(seeded))
    dest = Path(ms.backup())
    assert dest.parent == seeded.parent
    assert re.fullmatch(r"s\.kdbx\.bak-\d{8}T\d{12}Z", dest.name)  # UTC, microsecond resolution
    assert mode(dest) == 0o600
    assert dest.read_bytes() == seeded.read_bytes()
    assert opens_with(dest, OLD)
    assert titles(dest, OLD) == ["a", "b"]
    assert siblings(seeded) == sorted([".mattstash.txt", "s.kdbx", "s.kdbx.lock", dest.name]), "no temp files left"


def test_backup_is_private_whatever_the_source_and_umask(seeded: Path, tmp_path: Path):
    seeded.chmod(0o644)
    old_umask = os.umask(0)
    try:
        dest = Path(MattStash(path=str(seeded)).backup(str(tmp_path / "out.bak")))
    finally:
        os.umask(old_umask)
    assert mode(dest) == 0o600


def test_backup_to_explicit_file_and_directory(seeded: Path, tmp_path: Path):
    ms = MattStash(path=str(seeded))
    explicit = tmp_path / "elsewhere.bak"
    assert ms.backup(str(explicit)) == str(explicit)
    assert opens_with(explicit, OLD)

    target_dir = tmp_path / "backups"
    target_dir.mkdir()
    inside = Path(ms.backup(str(target_dir)))
    assert inside.parent == target_dir and inside.name.startswith("s.kdbx.bak-")
    assert opens_with(inside, OLD)


def test_backup_refuses_to_overwrite_without_force(seeded: Path, tmp_path: Path):
    ms = MattStash(path=str(seeded))
    dest = tmp_path / "keep.bak"
    dest.write_text("precious")
    with pytest.raises(DatabaseExistsError, match="use force"):
        ms.backup(str(dest))
    assert dest.read_text() == "precious"
    assert not [p for p in tmp_path.iterdir() if ".tmp-" in p.name], "temp file cleaned up"


def test_backup_force_replaces_atomically_and_privately(seeded: Path, tmp_path: Path):
    ms = MattStash(path=str(seeded))
    dest = tmp_path / "replace.bak"
    dest.write_text("old content")
    dest.chmod(0o644)
    assert ms.backup(str(dest), force=True) == str(dest)
    assert dest.read_bytes() == seeded.read_bytes()
    assert mode(dest) == 0o600


def test_backup_failure_leaves_nothing_behind_and_keeps_the_old_file(
    seeded: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    def explode(*args, **kwargs):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr("mattstash.utils.fileops.shutil.copyfileobj", explode)
    ms = MattStash(path=str(seeded))
    with pytest.raises(MattStashError, match="No space left"):
        ms.backup(str(tmp_path / "never.bak"))
    assert not (tmp_path / "never.bak").exists()
    existing = tmp_path / "existing.bak"
    existing.write_text("still here")
    with pytest.raises(MattStashError):
        ms.backup(str(existing), force=True)
    assert existing.read_text() == "still here"
    assert not [p for p in tmp_path.iterdir() if ".tmp-" in p.name]


def test_backup_works_on_filesystems_without_hard_links(seeded: Path, tmp_path: Path, monkeypatch):
    def no_link(src, dst, **kwargs):
        raise OSError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr("mattstash.utils.fileops.os.link", no_link)
    ms = MattStash(path=str(seeded))
    dest = tmp_path / "nolink.bak"
    assert ms.backup(str(dest)) == str(dest) and opens_with(dest, OLD)
    with pytest.raises(DatabaseExistsError):  # still refuses to overwrite
        ms.backup(str(dest))


def test_backup_default_names_never_collide(seeded: Path):
    """Two backups in the same instant (``backup`` then ``rotate-password`` in a script) get distinct names."""
    from datetime import UTC, datetime

    ms = MattStash(path=str(seeded))
    frozen = datetime(2026, 10, 7, 12, 0, 0, 123456, tzinfo=UTC)
    with patch("mattstash.core.mattstash.datetime") as fake:
        fake.now.return_value = frozen
        first, second = ms.backup(), ms.backup()
    assert first.endswith(".bak-20261007T120000123456Z")
    assert second.endswith(".bak-20261007T120000123456Z-1")
    assert Path(first).exists() and Path(second).exists()


def test_backup_does_not_need_the_password(seeded: Path):
    dest = MattStash(path=str(seeded), password="definitely-wrong").backup()
    assert opens_with(Path(dest), OLD), "it is a plain copy of the encrypted file"


def test_backup_errors(seeded: Path, tmp_path: Path):
    ms = MattStash(path=str(seeded))
    with pytest.raises(MattStashError, match="directory does not exist"):
        ms.backup(str(tmp_path / "no-such-dir" / "x.bak"))
    for protected in (str(seeded), str(seeded) + ".lock", str(sidecar_of(seeded))):
        with pytest.raises(MattStashError, match="Refusing to write the backup over"):
            ms.backup(protected, force=True)
    assert opens_with(seeded, OLD) and sidecar_of(seeded).read_text() == OLD
    missing = MattStash(path=str(tmp_path / "gone.kdbx"), password="x")
    with pytest.raises(DatabaseNotFoundError):
        missing.backup()
    assert not (tmp_path / "gone.kdbx.lock").exists()


def test_backup_waits_for_the_write_lock(seeded: Path, tmp_path: Path):
    ms = MattStash(path=str(seeded), lock_timeout=0.3)
    dest = tmp_path / "locked.bak"
    with FileLock(str(seeded) + ".lock", timeout=5):  # another writer is mid-transaction
        with pytest.raises(DatabaseLockError):
            ms.backup(str(dest))
    assert not dest.exists()
    assert ms.backup(str(dest)) == str(dest)  # lock released: works


def test_backup_taken_while_another_instance_writes_is_always_a_consistent_database(seeded: Path, tmp_path: Path):
    writer = MattStash(path=str(seeded))
    errors: List[BaseException] = []

    def write() -> None:
        try:
            for i in range(3):
                writer.put(f"w{i}", value="v", autoincrement=False)
        except BaseException as exc:  # pragma: no cover
            errors.append(exc)

    thread = threading.Thread(target=write)
    thread.start()
    copies = []
    reader = MattStash(path=str(seeded))
    for i in range(3):
        copies.append(Path(reader.backup(str(tmp_path / f"c{i}.bak"))))
    thread.join(timeout=120)
    assert not errors
    seen = []
    for copy in copies:
        names = titles(copy, OLD)  # every copy is a complete, decryptable database
        assert {"a", "b"} <= set(names)
        seen.append(len([n for n in names if n.startswith("w")]))
    assert seen == sorted(seen), "later backups never contain fewer writes than earlier ones"


# ---------------------------------------------------------------------------
# MattStash.rotate_password
# ---------------------------------------------------------------------------


def test_rotate_new_password_opens_old_fails_entries_intact(seeded: Path):
    ms = MattStash(path=str(seeded))
    assert ms.rotate_password(NEW) is None
    assert opens_with(seeded, NEW)
    assert not opens_with(seeded, OLD)
    assert titles(seeded, NEW) == ["a", "b"]
    assert PyKeePass(str(seeded), password=NEW).find_entries(title="b", first=True).password == "B-secret"
    assert ms.password == NEW
    assert mode(seeded) == 0o600


def test_rotate_keeps_the_instance_usable_and_other_instances_with_the_new_password(seeded: Path):
    ms = MattStash(path=str(seeded))
    ms.rotate_password(NEW)
    assert ms.get("a", show_password=True)["value"] == "A-secret"  # type: ignore[index]
    ms.put("c", value="C-secret", autoincrement=False)  # a write after the rotation uses the new password
    assert opens_with(seeded, NEW)
    # a fresh instance picks the new password up from the (updated) sidecar
    assert MattStash(path=str(seeded)).get("c", show_password=True)["value"] == "C-secret"  # type: ignore[index]


def test_rotate_updates_the_sidecar_atomically_with_mode_0600(seeded: Path):
    sidecar = sidecar_of(seeded)
    sidecar.chmod(0o644)
    MattStash(path=str(seeded)).rotate_password(NEW)
    assert sidecar.read_text() == NEW
    assert mode(sidecar) == 0o600
    assert siblings(seeded) == sorted([".mattstash.txt", "s.kdbx", "s.kdbx.lock"]), "no temp files left"


def test_rotate_without_a_sidecar_does_not_create_one(seeded_no_sidecar: Path):
    ms = MattStash(path=str(seeded_no_sidecar), password=OLD)
    ms.rotate_password(NEW)
    assert not sidecar_of(seeded_no_sidecar).exists()
    assert opens_with(seeded_no_sidecar, NEW) and not opens_with(seeded_no_sidecar, OLD)


def test_rotate_with_backup_keeps_the_old_password_copy(seeded: Path):
    ms = MattStash(path=str(seeded))
    backup = ms.rotate_password(NEW, backup=True)
    assert backup is not None
    copy = Path(backup)
    assert copy.parent == seeded.parent and ".bak-" in copy.name and mode(copy) == 0o600
    assert opens_with(copy, OLD) and not opens_with(copy, NEW)
    assert titles(copy, OLD) == ["a", "b"]
    assert opens_with(seeded, NEW)


def test_rotate_with_wrong_current_password_changes_nothing_and_makes_no_backup(seeded: Path):
    before = seeded.read_bytes()
    ms = MattStash(path=str(seeded), password="not-the-password")
    with pytest.raises(DatabaseAccessError):
        ms.rotate_password(NEW, backup=True)
    assert seeded.read_bytes() == before
    assert sidecar_of(seeded).read_text() == OLD
    assert backups(seeded) == []


def test_rotate_without_any_current_password_is_an_access_error(seeded_no_sidecar: Path):
    with pytest.raises(DatabaseAccessError, match="No database password"):
        MattStash(path=str(seeded_no_sidecar)).rotate_password(NEW)


def test_rotate_rejects_unusable_new_passwords_before_touching_anything(seeded: Path):
    ms = MattStash(path=str(seeded))
    before = seeded.read_bytes()
    for bad in ("", None, 123):
        with pytest.raises(InvalidCredentialError, match="empty"):
            ms.rotate_password(bad)  # type: ignore[arg-type]
    for bad in (" padded", "trailing\n", "x "):  # a sidecar cannot hold these (it is read back stripped)
        with pytest.raises(InvalidCredentialError, match="whitespace"):
            ms.rotate_password(bad)
    assert seeded.read_bytes() == before and sidecar_of(seeded).read_text() == OLD


def test_rotate_allows_edge_whitespace_when_there_is_no_sidecar(seeded_no_sidecar: Path):
    MattStash(path=str(seeded_no_sidecar), password=OLD).rotate_password(" spaced pw ")
    assert opens_with(seeded_no_sidecar, " spaced pw ")


def test_rotate_save_failure_leaves_database_sidecar_and_instance_untouched(
    seeded: Path, monkeypatch: pytest.MonkeyPatch
):
    def explode(self):
        raise OSError(errno.EIO, "disk error")

    monkeypatch.setattr(CredentialStore, "save", explode)
    ms = MattStash(path=str(seeded))
    with pytest.raises(OSError, match="disk error"):
        ms.rotate_password(NEW, backup=True)
    monkeypatch.undo()
    assert opens_with(seeded, OLD) and not opens_with(seeded, NEW)
    assert sidecar_of(seeded).read_text() == OLD
    assert ms.password == OLD
    assert ms.get("a") is not None, "the instance still works with the old password"
    assert not [n for n in siblings(seeded) if ".tmp-" in n], "staged sidecar removed"


def test_rotate_sidecar_replace_failure_after_rekey_is_reported_clearly(seeded: Path, monkeypatch: pytest.MonkeyPatch):
    real_replace = os.replace

    def selective(src, dst, *args, **kwargs):
        if str(dst).endswith(".mattstash.txt"):
            raise OSError(errno.EACCES, "Permission denied")
        return real_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr("mattstash.core.mattstash.os.replace", selective)
    ms = MattStash(path=str(seeded))
    with pytest.raises(SidecarUpdateError, match="now uses the new password") as excinfo:
        ms.rotate_password(NEW)
    monkeypatch.undo()
    assert opens_with(seeded, NEW), "the database is re-keyed"
    assert sidecar_of(seeded).read_text() == OLD, "the sidecar still holds the old password"
    assert ms.password == NEW
    # the staged file is NOT thrown away: it is the only other record of the new password
    staged = [n for n in siblings(seeded) if ".tmp-" in n]
    assert len(staged) == 1 and excinfo.value.staged_path.endswith(staged[0])
    assert (seeded.parent / staged[0]).read_text() == NEW and mode(seeded.parent / staged[0]) == 0o600
    assert excinfo.value.staged_path in str(excinfo.value)


def test_rotate_waits_for_the_write_lock_and_changes_nothing_on_timeout(seeded: Path):
    before = seeded.read_bytes()
    ms = MattStash(path=str(seeded), lock_timeout=0.3)
    with FileLock(str(seeded) + ".lock", timeout=5):  # a concurrent writer holds the lock
        with pytest.raises(DatabaseLockError):
            ms.rotate_password(NEW, backup=True)
    assert seeded.read_bytes() == before
    assert sidecar_of(seeded).read_text() == OLD
    assert backups(seeded) == []


def test_rotate_serialises_with_a_concurrent_writer(seeded: Path):
    """A put and a rotation racing on the same file both take effect; nothing is lost."""
    ms_writer = MattStash(path=str(seeded))
    ms_rotator = MattStash(path=str(seeded))
    errors: List[BaseException] = []

    def write() -> None:
        try:
            ms_writer.put("raced", value="r", autoincrement=False)
        except BaseException as exc:  # pragma: no cover - the writer may lose the password race
            errors.append(exc)

    thread = threading.Thread(target=write)
    thread.start()
    ms_rotator.rotate_password(NEW)
    thread.join(timeout=120)
    if errors:  # the writer started after the re-key with the old password: it must fail cleanly, not corrupt
        assert isinstance(errors[0], DatabaseAccessError)
        assert titles(seeded, NEW) == ["a", "b"]
    else:
        assert titles(seeded, NEW) == ["a", "b", "raced"]


def test_instance_holding_the_old_password_is_locked_out_after_a_rotation(seeded: Path):
    stale = MattStash(path=str(seeded), password=OLD)  # e.g. a server that was started with KDBX_PASSWORD=<old>
    assert stale.get("a") is not None
    MattStash(path=str(seeded)).rotate_password(NEW)
    with pytest.raises(DatabaseAccessError):
        stale.get("a")
    assert stale.password == OLD, "a failed attempt must not change the password it was given"


# ---------------------------------------------------------------------------
# CLI: backup
# ---------------------------------------------------------------------------


def run(db: Path, *argv: str) -> int:
    return main(["--db", str(db), *argv])


def test_cli_backup_prints_only_the_path(seeded: Path, capsys: pytest.CaptureFixture[str]):
    assert run(seeded, "backup") == 0
    out = capsys.readouterr().out
    (path,) = out.splitlines()
    assert Path(path) in backups(seeded) and opens_with(Path(path), OLD) and mode(Path(path)) == 0o600


def test_cli_backup_dest_force_and_refusal(seeded: Path, tmp_path: Path, capsys, caplog):
    dest = tmp_path / "mine.bak"
    assert run(seeded, "backup", str(dest)) == 0
    assert capsys.readouterr().out.strip() == str(dest)
    first = dest.read_bytes()
    assert run(seeded, "backup", str(dest)) == exit_codes.WOULD_OVERWRITE
    assert "use force" in caplog.text
    assert capsys.readouterr().out == "" and dest.read_bytes() == first
    dest.write_text("stale")
    assert run(seeded, "backup", str(dest), "--force") == 0
    assert opens_with(dest, OLD)


def test_cli_backup_missing_database(tmp_path: Path, capsys):
    assert main(["--db", str(tmp_path / "gone.kdbx"), "backup"]) == exit_codes.DB_NOT_FOUND
    assert capsys.readouterr().out == ""


def test_cli_backup_lock_timeout_is_a_db_error(seeded: Path, tmp_path: Path, capsys):
    with patch("mattstash.cli.handlers.backup.MattStash") as cls:
        cls.return_value.backup.side_effect = DatabaseLockError("busy")
        assert run(seeded, "backup") == exit_codes.DB_ACCESS
    assert capsys.readouterr().out == ""


def test_cli_backup_not_supported_in_server_mode(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
):
    server = FakeServer(api_key="k").install(monkeypatch)
    assert main(["--server-url", "http://localhost:8000", "--api-key", "k", "backup"]) == exit_codes.ERROR
    assert "not supported in server mode" in caplog.text
    assert server.requests == [] and capsys.readouterr().out == ""


# ---------------------------------------------------------------------------
# CLI: rotate-password
# ---------------------------------------------------------------------------


def write_file(path: Path, content: str) -> Path:
    path.write_text(content)
    path.chmod(0o600)
    return path


def test_cli_rotate_with_password_file(seeded: Path, tmp_path: Path, capsys, caplog):
    new_file = write_file(tmp_path / "new-pw", f"{NEW}\n")
    assert run(seeded, "rotate-password", "--new-password-file", str(new_file)) == 0
    out = capsys.readouterr().out
    assert "Master password rotated" in out and "Sidecar password file updated" in out
    assert NEW not in out and NEW not in caplog.text, "a password supplied by the user is never echoed"
    assert opens_with(seeded, NEW) and not opens_with(seeded, OLD)
    assert sidecar_of(seeded).read_text() == NEW
    (copy,) = backups(seeded)  # a backup is taken first by default
    assert opens_with(copy, OLD)
    assert str(copy) in out
    # the whole CLI keeps working through the updated sidecar
    assert run(seeded, "get", "a", "--raw") == 0
    assert capsys.readouterr().out == "A-secret\n"


def test_cli_rotate_no_backup(seeded: Path, tmp_path: Path):
    new_file = write_file(tmp_path / "new-pw", NEW)
    assert run(seeded, "rotate-password", "--new-password-file", str(new_file), "--no-backup") == 0
    assert backups(seeded) == []
    assert opens_with(seeded, NEW)


def test_cli_rotate_new_password_from_stdin_first_line(
    seeded: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    monkeypatch.setattr(sys, "stdin", io.StringIO(f"{NEW}\nignored second line\n"))
    assert run(seeded, "rotate-password", "--new-password-stdin", "--no-backup") == 0
    assert opens_with(seeded, NEW)
    assert NEW not in capsys.readouterr().out


@pytest.mark.parametrize("content", ["", "\n", "\r\n"])
def test_cli_rotate_empty_new_password_is_rejected(
    seeded: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, content: str, caplog
):
    assert run(seeded, "rotate-password", "--new-password-file", str(write_file(tmp_path / "e", content))) == 1
    monkeypatch.setattr(sys, "stdin", io.StringIO(content))
    assert run(seeded, "rotate-password", "--new-password-stdin") == 1
    assert caplog.text.count("empty") >= 2
    assert opens_with(seeded, OLD) and backups(seeded) == []


def test_cli_rotate_generate_prints_the_password_once_and_it_works(seeded: Path, capsys: pytest.CaptureFixture[str]):
    assert run(seeded, "rotate-password", "--generate", "--no-backup") == 0
    out = capsys.readouterr().out
    match = re.search(r"Generated new master password \(shown once, store it safely\): (\S+)", out)
    assert match is not None
    generated = match.group(1)
    assert len(generated) >= 40 and out.count(generated) == 1
    assert opens_with(seeded, generated) and not opens_with(seeded, OLD)
    assert sidecar_of(seeded).read_text() == generated


def test_cli_rotate_prompts_twice_when_interactive(seeded: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(sys, "stdin", FakeTTY(""))
    answers = iter([NEW, NEW])
    with patch("mattstash.cli.handlers.rotate.getpass.getpass", side_effect=lambda prompt: next(answers)) as asked:
        assert run(seeded, "rotate-password", "--no-backup") == 0
    assert asked.call_count == 2
    assert opens_with(seeded, NEW)


def test_cli_rotate_prompt_mismatch_or_empty_changes_nothing(seeded: Path, monkeypatch: pytest.MonkeyPatch, caplog):
    monkeypatch.setattr(sys, "stdin", FakeTTY(""))
    for answers in ([NEW, "different"], [""]):
        it = iter(answers)
        with patch("mattstash.cli.handlers.rotate.getpass.getpass", side_effect=lambda prompt, it=it: next(it)):
            assert run(seeded, "rotate-password") == exit_codes.ERROR
    assert "do not match" in caplog.text and "cannot be empty" in caplog.text
    assert opens_with(seeded, OLD) and backups(seeded) == []


def test_cli_rotate_non_interactive_without_a_source_is_an_error(seeded: Path, monkeypatch, caplog):
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    assert run(seeded, "rotate-password") == exit_codes.ERROR
    assert "No source for the new password" in caplog.text
    assert opens_with(seeded, OLD) and backups(seeded) == []


def test_cli_rotate_sources_are_mutually_exclusive(seeded: Path, tmp_path: Path):
    with pytest.raises(SystemExit):
        run(seeded, "rotate-password", "--generate", "--new-password-stdin")
    with pytest.raises(SystemExit):
        run(seeded, "rotate-password", "--generate", "--new-password-file", str(tmp_path / "f"))
    assert opens_with(seeded, OLD)


def test_cli_rotate_wrong_current_password_is_exit_7_with_no_backup(seeded: Path, tmp_path: Path):
    new_file = write_file(tmp_path / "n", NEW)
    rc = main(["--db", str(seeded), "--password", "wrong", "rotate-password", "--new-password-file", str(new_file)])
    assert rc == exit_codes.DB_ACCESS
    assert opens_with(seeded, OLD) and backups(seeded) == []


def test_cli_rotate_uses_the_old_password_from_any_usual_source(seeded_no_sidecar: Path, tmp_path: Path, monkeypatch):
    db = seeded_no_sidecar
    old_file = write_file(tmp_path / "old", f"{OLD}\n")
    new_file = write_file(tmp_path / "new", NEW)
    rc = run(db, "--db-password-file", str(old_file), "rotate-password", "--new-password-file", str(new_file))
    assert rc == 0 and opens_with(db, NEW)
    assert not sidecar_of(db).exists()
    # next rotation: old password through the environment
    monkeypatch.setenv("KDBX_PASSWORD", NEW)
    newer = write_file(tmp_path / "newer", "newer-pw")
    assert run(db, "rotate-password", "--new-password-file", str(newer), "--no-backup") == 0
    assert opens_with(db, "newer-pw")


def test_cli_rotate_warns_when_the_environment_still_holds_the_old_password(
    seeded_no_sidecar: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
):
    monkeypatch.setenv("KDBX_PASSWORD", OLD)
    new_file = write_file(tmp_path / "n", NEW)
    assert run(seeded_no_sidecar, "rotate-password", "--new-password-file", str(new_file), "--no-backup") == 0
    assert "KDBX_PASSWORD is set and still provides the OLD password" in caplog.text
    assert OLD not in caplog.text


def test_cli_rotate_sidecar_failure_still_reports_the_new_password(
    seeded: Path, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
):
    with patch.object(MattStash, "rotate_password", side_effect=SidecarUpdateError("sidecar not writable")):
        assert run(seeded, "rotate-password", "--generate") == exit_codes.ERROR
    out = capsys.readouterr().out
    assert "Generated new master password" in out, "the generated password must not be lost"
    assert "sidecar not writable" in caplog.text


def test_cli_rotate_not_supported_in_server_mode(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
):
    server = FakeServer(api_key="k").install(monkeypatch)
    rc = main(["--server-url", "http://localhost:8000", "--api-key", "k", "rotate-password", "--generate"])
    assert rc == exit_codes.ERROR
    assert "not supported in server mode" in caplog.text
    assert server.requests == [] and "Generated" not in capsys.readouterr().out


def test_cli_help_for_the_new_commands(capsys: pytest.CaptureFixture[str]):
    for argv, expected in (
        (["backup", "--help"], ["DEST", "--force", "0600", "write lock"]),
        (
            ["rotate-password", "--help"],
            ["--new-password-file", "--new-password-stdin", "--generate", "--no-backup", "sidecar"],
        ),
    ):
        with pytest.raises(SystemExit):
            main(argv)
        text = " ".join(capsys.readouterr().out.split())
        for fragment in expected:
            assert fragment in text, fragment
