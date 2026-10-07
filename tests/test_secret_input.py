"""
Secrets without argv (docs/security-review.md L-1, L-2).

``put --value -`` / ``--value-file`` / ``--entry-password*``, the explicit ``--db-password*`` options,
the deprecated ``put --fields --password`` alias and the shared input helpers.
"""

import io
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

import pytest
from fake_server import FakeServer

from mattstash import MattStash
from mattstash.cli import exit_codes
from mattstash.cli.inputs import (
    MAX_SECRET_BYTES,
    InputError,
    StdinClaim,
    read_credential_file,
    read_secret_file,
    read_stdin_secret,
    strip_one_newline,
)
from mattstash.cli.main import main

SERVER = "http://localhost:8000"
KEY = "api-key-value"


def feed_stdin(monkeypatch: pytest.MonkeyPatch, data: bytes, tty: bool = False) -> None:
    class Stdin(io.TextIOWrapper):
        def isatty(self) -> bool:
            return tty

    monkeypatch.setattr(sys, "stdin", Stdin(io.BytesIO(data), encoding="utf-8"))


def secret_of(db: Path, title: str, password: Optional[str] = None) -> Optional[str]:
    """The stored password/value of ``title`` (simple secret or full credential)."""
    found = MattStash(path=str(db), password=password).get(title, show_password=True)
    if found is None:
        return None
    return found["value"] if isinstance(found, dict) else found.password


def titles_in(db: Path) -> list[str]:
    return sorted(c.credential_name for c in MattStash(path=str(db)).list())


def write(path: Path, content: str) -> Path:
    path.write_text(content)
    path.chmod(0o600)
    return path


@pytest.fixture()
def pw_db(tmp_path: Path) -> Path:
    """A database with an explicit master password and NO sidecar (so a wrong password cannot be rescued)."""
    path = tmp_path / "pw" / "pw.kdbx"
    path.parent.mkdir()
    MattStash.create(str(path), password="master-pw-1")
    return path


# ---------------------------------------------------------------------------
# input helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("a\n", "a"),
        ("a\r\n", "a"),
        ("a\n\n", "a\n"),
        ("a\r\n\r\n", "a\r\n"),
        ("a", "a"),
        ("", ""),
        ("\n", ""),
        ("  pw  \n", "  pw  "),
        ("a\nb", "a\nb"),
        ("a\r", "a\r"),
    ],
)
def test_strip_exactly_one_newline(raw: str, expected: str):
    assert strip_one_newline(raw) == expected


def test_read_stdin_secret_strips_one_newline_and_keeps_inner_content():
    value = read_stdin_secret("--value -", io.BytesIO("pässword  \nline2\n\n".encode()))
    assert value == "pässword  \nline2\n"


@pytest.mark.parametrize("data", [b"", b"\n", b"\r\n"])
def test_read_stdin_secret_rejects_empty(data: bytes):
    with pytest.raises(InputError, match="empty value"):
        read_stdin_secret("--value -", io.BytesIO(data))


def test_read_stdin_secret_rejects_binary_without_echoing_it():
    with pytest.raises(InputError) as excinfo:
        read_stdin_secret("--value -", io.BytesIO(b"\xff\xfe-secret-bytes"))
    assert "not valid UTF-8" in str(excinfo.value) and "secret-bytes" not in str(excinfo.value)


def test_read_stdin_secret_rejects_oversized_input():
    with pytest.raises(InputError, match="larger than"):
        read_stdin_secret("--value -", io.BytesIO(b"x" * (MAX_SECRET_BYTES + 1)))


def test_read_stdin_secret_from_text_only_stdin(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(sys, "stdin", io.StringIO("from-stringio\n"))
    assert read_stdin_secret("--value -") == "from-stringio"


def test_read_stdin_secret_hints_on_terminal(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]):
    feed_stdin(monkeypatch, b"typed\n", tty=True)
    assert read_stdin_secret("--value -") == "typed"
    assert "Ctrl-D" in capsys.readouterr().err


def test_read_secret_file(tmp_path: Path):
    pem = "-----BEGIN KEY-----\nabc\n-----END KEY-----\n"
    assert read_secret_file("--value-file", str(write(tmp_path / "k", pem))) == pem[:-1]


def test_read_secret_file_errors_name_the_file_not_its_content(tmp_path: Path):
    with pytest.raises(InputError, match="cannot read") as missing:
        read_secret_file("--value-file", str(tmp_path / "nope"))
    assert "nope" in str(missing.value)
    with pytest.raises(InputError, match="is empty"):
        read_secret_file("--value-file", str(write(tmp_path / "empty", "")))
    with pytest.raises(InputError, match="is empty"):
        read_secret_file("--value-file", str(write(tmp_path / "nl", "\n")))
    with pytest.raises(InputError, match="cannot read"):
        read_secret_file("--value-file", str(tmp_path))  # a directory
    binary = tmp_path / "bin"
    binary.write_bytes(b"\xff\xfeTOPSECRET")
    with pytest.raises(InputError) as bad:
        read_secret_file("--value-file", str(binary))
    assert "TOPSECRET" not in str(bad.value)


def test_read_credential_file_strips_all_surrounding_whitespace(tmp_path: Path):
    assert read_credential_file("--db-password-file", str(write(tmp_path / "p", "  hunter2 \r\n\n"))) == "hunter2"
    with pytest.raises(InputError, match="is empty"):
        read_credential_file("--db-password-file", str(write(tmp_path / "e", " \n")))


def test_stdin_claim_allows_one_owner_only():
    claim = StdinClaim()
    claim.claim("--value -")
    claim.claim("--value -")  # the same option again is fine
    with pytest.raises(InputError, match="both read from stdin"):
        claim.claim("--entry-password-stdin")


# ---------------------------------------------------------------------------
# put --value - / --value-file / empty values
# ---------------------------------------------------------------------------


def test_put_value_from_stdin(temp_db: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]):
    feed_stdin(monkeypatch, "s3cr3t-ünï\nsecond line\n\n".encode())
    assert main(["--db", str(temp_db), "put", "k", "--value", "-"]) == 0
    assert secret_of(temp_db, "k") == "s3cr3t-ünï\nsecond line\n"  # exactly one trailing newline removed
    out = capsys.readouterr().out
    assert "s3cr3t" not in out, "the stored value is never echoed"


def test_put_value_from_file(temp_db: Path, tmp_path: Path):
    path = write(tmp_path / "value.txt", "from-a-file\n")
    assert main(["--db", str(temp_db), "put", "k", "--value-file", str(path)]) == 0
    assert secret_of(temp_db, "k") == "from-a-file"


def test_put_value_literal_still_works(temp_db: Path):
    assert main(["--db", str(temp_db), "put", "k", "--value", "plain"]) == 0
    assert secret_of(temp_db, "k") == "plain"


@pytest.mark.parametrize("data", [b"", b"\n"])
def test_put_rejects_empty_stdin(
    temp_db: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, data: bytes
):
    feed_stdin(monkeypatch, data)
    assert main(["--db", str(temp_db), "put", "k", "--value", "-"]) == exit_codes.ERROR
    assert "empty" in caplog.text
    assert titles_in(temp_db) == []


def test_put_rejects_empty_file_and_empty_literal(temp_db: Path, tmp_path: Path, caplog: pytest.LogCaptureFixture):
    assert main(["--db", str(temp_db), "put", "k", "--value-file", str(write(tmp_path / "e", "\n"))]) == 1
    assert main(["--db", str(temp_db), "put", "k", "--value", ""]) == 1
    assert caplog.text.count("empty") >= 2
    assert titles_in(temp_db) == []


def test_put_missing_value_file(temp_db: Path, tmp_path: Path, caplog: pytest.LogCaptureFixture):
    assert main(["--db", str(temp_db), "put", "k", "--value-file", str(tmp_path / "nope")]) == exit_codes.ERROR
    assert "nope" in caplog.text
    assert titles_in(temp_db) == []


def test_value_and_value_file_are_mutually_exclusive(temp_db: Path, tmp_path: Path):
    with pytest.raises(SystemExit):
        main(["--db", str(temp_db), "put", "k", "--value", "a", "--value-file", str(tmp_path / "f")])
    with pytest.raises(SystemExit):
        main(["--db", str(temp_db), "put", "k", "--value-file", str(tmp_path / "f"), "--fields"])


def test_put_value_json_output_masks_the_value(
    temp_db: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    feed_stdin(monkeypatch, b"topsecret\n")
    assert main(["--db", str(temp_db), "put", "k", "--value", "-", "--json"]) == 0
    assert "topsecret" not in capsys.readouterr().out


# ---------------------------------------------------------------------------
# put --entry-password*  (auto-selects fields mode)
# ---------------------------------------------------------------------------


def test_entry_password_file_selects_fields_mode(temp_db: Path, tmp_path: Path):
    path = write(tmp_path / "pw", "entry-pw-1\n")
    rc = main(["--db", str(temp_db), "put", "svc", "--username", "alice", "--entry-password-file", str(path)])
    assert rc == 0
    cred = MattStash(path=str(temp_db)).get("svc", show_password=True)
    assert cred is not None and not isinstance(cred, dict)
    assert (cred.username, cred.password) == ("alice", "entry-pw-1")


def test_entry_password_stdin_selects_fields_mode(temp_db: Path, monkeypatch: pytest.MonkeyPatch):
    feed_stdin(monkeypatch, b"entry-pw-2\n")
    assert main(["--db", str(temp_db), "put", "svc", "--entry-password-stdin", "--url", "db:5432"]) == 0
    cred = MattStash(path=str(temp_db)).get("svc", show_password=True)
    assert cred is not None and not isinstance(cred, dict)
    assert (cred.password, cred.url) == ("entry-pw-2", "db:5432")


def test_entry_password_without_other_field_args_still_selects_fields_mode(
    temp_db: Path, monkeypatch: pytest.MonkeyPatch
):
    feed_stdin(monkeypatch, b"only-pw\n")
    assert main(["--db", str(temp_db), "put", "svc", "--entry-password-stdin"]) == 0
    assert secret_of(temp_db, "svc") == "only-pw"


def test_entry_password_literal_selects_fields_mode_and_is_not_the_db_password(temp_db: Path):
    assert main(["--db", str(temp_db), "put", "svc", "--username", "u", "--entry-password", "lit-pw"]) == 0
    assert secret_of(temp_db, "svc") == "lit-pw"


@pytest.mark.parametrize(
    "extra",
    [
        ["--value", "v", "--entry-password", "x"],
        ["--value", "v", "--entry-password-stdin"],
        ["--value-file", "{file}", "--entry-password-file", "{file}"],
    ],
)
def test_entry_password_cannot_be_combined_with_value(
    temp_db: Path, tmp_path: Path, caplog: pytest.LogCaptureFixture, extra: list[str]
):
    path = str(write(tmp_path / "f", "x\n"))
    argv = [a.replace("{file}", path) for a in extra]
    assert main(["--db", str(temp_db), "put", "k", *argv]) == exit_codes.ERROR
    assert "cannot be combined" in caplog.text
    assert titles_in(temp_db) == []


def test_value_with_username_or_url_is_an_error_not_silently_dropped(temp_db: Path, caplog: pytest.LogCaptureFixture):
    assert main(["--db", str(temp_db), "put", "k", "--value", "v", "--username", "u"]) == exit_codes.ERROR
    assert "--fields" in caplog.text
    assert titles_in(temp_db) == []


def test_only_one_entry_password_source(temp_db: Path, tmp_path: Path, caplog: pytest.LogCaptureFixture):
    path = str(write(tmp_path / "f", "x\n"))
    rc = main(["--db", str(temp_db), "put", "k", "--entry-password", "a", "--entry-password-file", path])
    assert rc == exit_codes.ERROR
    assert "mutually exclusive" in caplog.text


def test_two_options_cannot_both_read_stdin(temp_db: Path, monkeypatch: pytest.MonkeyPatch, caplog):
    feed_stdin(monkeypatch, b"never-read\n")
    rc = main(["--db", str(temp_db), "put", "k", "--value", "-", "--entry-password-stdin"])
    assert rc == exit_codes.ERROR
    assert "both read from stdin" in caplog.text
    assert titles_in(temp_db) == []


def test_mode_error_message_mentions_the_real_options(temp_db: Path, caplog: pytest.LogCaptureFixture):
    assert main(["--db", str(temp_db), "put", "k", "--notes", "only notes"]) == exit_codes.ERROR
    assert "--value" in caplog.text and "--entry-password*" in caplog.text
    assert "--password" not in caplog.text.replace("--entry-password", "").replace("--db-password", "")


def test_empty_entry_password_literal_rejected(temp_db: Path, caplog: pytest.LogCaptureFixture):
    assert main(["--db", str(temp_db), "put", "k", "--entry-password", ""]) == exit_codes.ERROR
    assert "must not be empty" in caplog.text


# ---------------------------------------------------------------------------
# put --fields --password : deprecated alias for the entry password
# ---------------------------------------------------------------------------


def test_fields_password_is_a_deprecated_alias_for_the_entry_password(temp_db: Path, caplog: pytest.LogCaptureFixture):
    with caplog.at_level(logging.WARNING):
        rc = main(["--db", str(temp_db), "put", "svc", "--fields", "--username", "u", "--password", "legacy-pw"])
    assert rc == 0
    assert secret_of(temp_db, "svc") == "legacy-pw"
    assert "DEPRECATED" in caplog.text
    assert "--entry-password-file" in caplog.text
    assert "ps" in caplog.text and "shell history" in caplog.text
    assert "legacy-pw" not in caplog.text


def test_fields_password_alias_does_not_become_the_db_password(pw_db: Path):
    """The entry password must not be used to open the database (the DB here has no sidecar)."""
    rc = main(["--db", str(pw_db), "--db-password", "master-pw-1", "put", "svc", "--fields", "--entry-password", "e"])
    assert rc == 0
    assert secret_of(pw_db, "svc", "master-pw-1") == "e"
    # a bare --password in fields mode is NOT the DB password -> the DB cannot be opened (exit 7), no write happens
    rc = main(["--db", str(pw_db), "put", "other", "--fields", "--username", "u", "--password", "master-pw-1"])
    assert rc == exit_codes.DB_ACCESS


def test_password_with_value_is_still_the_db_password(pw_db: Path):
    assert main(["--db", str(pw_db), "--password", "wrong", "put", "k", "--value", "v"]) == exit_codes.DB_ACCESS
    assert main(["--db", str(pw_db), "--password", "master-pw-1", "put", "k", "--value", "v"]) == 0
    assert secret_of(pw_db, "k", "master-pw-1") == "v"


def test_password_is_ambiguous_with_entry_password_options(pw_db: Path, caplog: pytest.LogCaptureFixture):
    rc = main(["--db", str(pw_db), "put", "k", "--fields", "--password", "x", "--entry-password", "y"])
    assert rc == exit_codes.ERROR
    assert "ambiguous" in caplog.text and "--db-password" in caplog.text


# ---------------------------------------------------------------------------
# --db-password / --db-password-file
# ---------------------------------------------------------------------------


def test_db_password_is_an_alias_of_password(pw_db: Path):
    assert main(["--db", str(pw_db), "--db-password", "wrong", "get", "x"]) == exit_codes.DB_ACCESS
    assert main(["--db", str(pw_db), "--db-password", "master-pw-1", "get", "x"]) == exit_codes.NOT_FOUND
    # accepted after the subcommand too
    assert main(["--db", str(pw_db), "get", "x", "--db-password", "master-pw-1"]) == exit_codes.NOT_FOUND


def test_db_password_in_fields_mode_is_the_db_password(pw_db: Path, tmp_path: Path):
    entry_pw = write(tmp_path / "entry", "entry-secret\n")
    rc = main(
        [
            "--db",
            str(pw_db),
            "put",
            "svc",
            "--db-password",
            "master-pw-1",
            "--username",
            "u",
            "--entry-password-file",
            str(entry_pw),
        ]
    )
    assert rc == 0
    assert secret_of(pw_db, "svc", "master-pw-1") == "entry-secret"


def test_db_password_file(pw_db: Path, tmp_path: Path):
    good = write(tmp_path / "good", "  master-pw-1\n\n")
    bad = write(tmp_path / "bad", "not-the-password\n")
    assert main(["--db", str(pw_db), "--db-password-file", str(bad), "get", "x"]) == exit_codes.DB_ACCESS
    assert main(["--db", str(pw_db), "--db-password-file", str(good), "get", "x"]) == exit_codes.NOT_FOUND
    assert main(["--db", str(pw_db), "put", "k", "--value", "v", "--db-password-file", str(good)]) == 0
    assert secret_of(pw_db, "k", "master-pw-1") == "v"


def test_db_password_file_beats_environment(pw_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("KDBX_PASSWORD", "wrong-env-password")
    good = write(tmp_path / "good", "master-pw-1\n")
    assert main(["--db", str(pw_db), "get", "x"]) == exit_codes.DB_ACCESS  # env alone is wrong
    assert main(["--db", str(pw_db), "--db-password-file", str(good), "get", "x"]) == exit_codes.NOT_FOUND


def test_db_password_file_errors(pw_db: Path, tmp_path: Path, caplog: pytest.LogCaptureFixture, capsys):
    assert main(["--db", str(pw_db), "--db-password-file", str(tmp_path / "nope"), "get", "x"]) == exit_codes.ERROR
    assert main(["--db", str(pw_db), "--db-password-file", str(write(tmp_path / "e", "")), "get", "x"]) == 1
    good = write(tmp_path / "good", "master-pw-1\n")
    assert main(["--db", str(pw_db), "--password", "a", "--db-password-file", str(good), "get", "x"]) == 1
    err = capsys.readouterr().err
    assert "cannot read" in err and "is empty" in err and "mutually exclusive" in err
    assert "master-pw-1" not in err


def test_setup_accepts_db_password_file_without_the_argv_warning(tmp_path: Path, caplog: pytest.LogCaptureFixture):
    db = tmp_path / "new.kdbx"
    pw = write(tmp_path / "pw", "setup-pw\n")
    assert main(["--db", str(db), "setup", "--db-password-file", str(pw)]) == 0
    assert "visible to other users" not in caplog.text
    assert MattStash(path=str(db), password="setup-pw").list() == []


def test_help_texts_steer_away_from_argv(capsys: pytest.CaptureFixture[str]):
    with pytest.raises(SystemExit):
        main(["put", "--help"])
    text = " ".join(capsys.readouterr().out.split())
    for expected in (
        "--value-file",
        "'-' to read it from stdin",
        "--entry-password-file",
        "--entry-password-stdin",
        "--db-password-file",
        "visible via ps and shell history",
    ):
        assert expected in text, expected
    assert "--fields is inferred" not in text  # the old misleading wording is gone
    assert "inferred when any of --username, --url or --entry-password*" in text


# ---------------------------------------------------------------------------
# server mode
# ---------------------------------------------------------------------------


@pytest.fixture()
def server(monkeypatch: pytest.MonkeyPatch) -> FakeServer:
    return FakeServer(api_key=KEY).install(monkeypatch)


def test_server_put_value_from_stdin_and_file(server: FakeServer, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    base = ["--server-url", SERVER, "--api-key", KEY]
    feed_stdin(monkeypatch, b"stdin-value\n")
    assert main([*base, "put", "a", "--value", "-"]) == 0
    assert main([*base, "put", "b", "--value-file", str(write(tmp_path / "v", "file-value\n"))]) == 0
    assert server.store["a"][1]["password"] == "stdin-value"
    assert server.store["b"][1]["password"] == "file-value"


def test_server_put_entry_password_options(server: FakeServer, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    base = ["--server-url", SERVER, "--api-key", KEY]
    assert (
        main([*base, "put", "f", "--username", "u", "--entry-password-file", str(write(tmp_path / "p", "pw1\n"))]) == 0
    )
    feed_stdin(monkeypatch, b"pw2\n")
    assert main([*base, "put", "s", "--entry-password-stdin"]) == 0
    assert server.store["f"][1]["password"] == "pw1" and server.store["f"][1]["username"] == "u"
    assert server.store["s"][1]["password"] == "pw2"


def test_server_put_deprecated_password_warns(server: FakeServer, caplog: pytest.LogCaptureFixture):
    base = ["--server-url", SERVER, "--api-key", KEY]
    assert main([*base, "put", "d", "--fields", "--password", "legacy"]) == 0
    assert server.store["d"][1]["password"] == "legacy"
    assert "DEPRECATED" in caplog.text


# ---------------------------------------------------------------------------
# a real process with a real stdin pipe
# ---------------------------------------------------------------------------


def test_subprocess_reads_value_from_a_pipe(temp_db: Path):
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    proc = subprocess.run(
        [sys.executable, "-m", "mattstash.cli.main", "--db", str(temp_db), "put", "piped", "--value", "-"],
        input="päss\n".encode(),
        capture_output=True,
        env=env,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    assert secret_of(temp_db, "piped") == "päss"
    assert b"p\xc3\xa4ss" not in proc.stdout
