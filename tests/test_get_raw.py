"""``mattstash get --raw`` / ``--field`` (docs/security-review.md L-3): script-friendly output."""

import os
import subprocess
import sys
from pathlib import Path

import httpx
import pytest
from fake_server import FakeServer

from mattstash import MattStash
from mattstash.cli import exit_codes
from mattstash.cli.main import main

SERVER = "http://localhost:8000"
KEY = "api-key-value"


@pytest.fixture(scope="module")
def populated(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A database with a simple secret (2 versions), a full credential and a credential with empty fields."""
    directory = tmp_path_factory.mktemp("raw")
    db = directory / "raw.kdbx"
    ms = MattStash.create(str(db), sidecar=True)
    ms.put("simple", value="sk-old")
    ms.put("simple", value="sk-live", notes="ignored here")
    ms.put("db", username="alice", password="p@ss w0rd", url="db.local:5432", notes="line1\nline2")
    ms.put("bare", username="bob", password="only-pw")
    return db


def run(db: Path, *argv: str) -> int:
    return main(["--db", str(db), *argv])


def test_raw_prints_only_the_secret(populated: Path, capsys: pytest.CaptureFixture[str]):
    assert run(populated, "get", "simple", "--raw") == 0
    captured = capsys.readouterr()
    assert captured.out == "sk-live\n"
    assert captured.err == ""


def test_raw_implies_unmasked_and_show_password_is_redundant(populated: Path, capsys: pytest.CaptureFixture[str]):
    assert run(populated, "get", "db", "--raw", "--show-password") == 0
    assert capsys.readouterr().out == "p@ss w0rd\n"


@pytest.mark.parametrize(
    "field,expected",
    [
        ("password", "p@ss w0rd\n"),
        ("username", "alice\n"),
        ("url", "db.local:5432\n"),
        ("notes", "line1\nline2\n"),
    ],
)
def test_raw_field_of_a_full_credential(populated: Path, capsys: pytest.CaptureFixture[str], field: str, expected: str):
    assert run(populated, "get", "db", "--raw", "--field", field) == 0
    assert capsys.readouterr().out == expected


def test_raw_default_field_is_password(populated: Path, capsys: pytest.CaptureFixture[str]):
    assert run(populated, "get", "db", "--raw") == 0
    assert capsys.readouterr().out == "p@ss w0rd\n"


def test_raw_specific_version(populated: Path, capsys: pytest.CaptureFixture[str]):
    assert run(populated, "get", "simple", "--raw", "--version", "1") == 0
    assert capsys.readouterr().out == "sk-old\n"


def test_raw_simple_secret_accepts_password_field_only(populated: Path, capsys: pytest.CaptureFixture[str], caplog):
    assert run(populated, "get", "simple", "--raw", "--field", "password") == 0
    assert capsys.readouterr().out == "sk-live\n"
    for field in ("username", "url", "notes"):
        assert run(populated, "get", "simple", "--raw", "--field", field) == exit_codes.ERROR
        assert capsys.readouterr().out == ""
    assert "simple secret" in caplog.text


def test_raw_not_found_is_exit_2_with_empty_stdout(populated: Path, capsys: pytest.CaptureFixture[str], caplog):
    assert run(populated, "get", "nope", "--raw") == exit_codes.NOT_FOUND
    assert capsys.readouterr().out == ""
    assert "not found" in caplog.text
    assert run(populated, "get", "simple", "--raw", "--version", "99") == exit_codes.NOT_FOUND
    assert capsys.readouterr().out == ""


def test_raw_empty_field_is_exit_2_and_prints_nothing(populated: Path, capsys: pytest.CaptureFixture[str], caplog):
    """A script must not continue with an empty value that merely looks like success."""
    assert run(populated, "get", "bare", "--raw", "--field", "url") == exit_codes.NOT_FOUND
    assert capsys.readouterr().out == ""
    assert "'url' is empty" in caplog.text


def test_raw_and_json_are_mutually_exclusive(populated: Path):
    with pytest.raises(SystemExit):
        run(populated, "get", "simple", "--raw", "--json")


def test_field_requires_raw(populated: Path, capsys: pytest.CaptureFixture[str], caplog):
    assert run(populated, "get", "db", "--field", "username") == exit_codes.ERROR
    assert capsys.readouterr().out == ""
    assert "--field requires --raw" in caplog.text


def test_field_rejects_unknown_names(populated: Path):
    with pytest.raises(SystemExit):
        run(populated, "get", "db", "--raw", "--field", "tags")


def test_default_get_is_still_masked(populated: Path, capsys: pytest.CaptureFixture[str]):
    assert run(populated, "get", "simple") == 0
    out = capsys.readouterr().out
    assert "*****" in out and "sk-live" not in out


def test_raw_db_errors_print_nothing_on_stdout(populated: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    assert main(["--db", str(populated), "--password", "wrong", "get", "simple", "--raw"]) == exit_codes.DB_ACCESS
    assert main(["--db", str(tmp_path / "missing.kdbx"), "--password", "x", "get", "s", "--raw"]) == (
        exit_codes.DB_NOT_FOUND
    )
    assert capsys.readouterr().out == ""


def test_raw_stdout_is_exactly_the_secret_in_a_real_process(populated: Path):
    """Even with --verbose and log noise enabled, stdout carries nothing but the value."""
    env = {**os.environ, "MATTSTASH_LOG_LEVEL": "DEBUG"}
    proc = subprocess.run(
        [sys.executable, "-m", "mattstash.cli.main", "--db", str(populated), "--verbose", "get", "db", "--raw"],
        capture_output=True,
        env=env,
        timeout=120,
    )
    assert proc.returncode == 0
    assert proc.stdout == b"p@ss w0rd\n"
    assert b"p@ss w0rd" not in proc.stderr, "the secret must not be logged either"


def test_raw_missing_secret_in_a_real_process(populated: Path):
    proc = subprocess.run(
        [sys.executable, "-m", "mattstash.cli.main", "--db", str(populated), "get", "nope", "--raw"],
        capture_output=True,
        timeout=120,
    )
    assert proc.returncode == 2
    assert proc.stdout == b""
    assert b"not found" in proc.stderr


# ---------------------------------------------------------------------------
# server mode
# ---------------------------------------------------------------------------


@pytest.fixture()
def server(monkeypatch: pytest.MonkeyPatch) -> FakeServer:
    fake = FakeServer(api_key=KEY).install(monkeypatch)
    fake.add("tok", "old-token")
    fake.add("tok", "new-token", username="svc", notes="n")
    fake.add("empty", "pw")
    return fake


def server_run(*argv: str) -> int:
    return main(["--server-url", SERVER, "--api-key", KEY, *argv])


def test_server_raw_password_and_fields(server: FakeServer, capsys: pytest.CaptureFixture[str]):
    assert server_run("get", "tok", "--raw") == 0
    assert capsys.readouterr().out == "new-token\n"
    assert dict(server.requests[-1].url.params)["show_password"] == "true"
    assert server_run("get", "tok", "--raw", "--field", "username") == 0
    assert capsys.readouterr().out == "svc\n"
    assert server_run("get", "tok", "--raw", "--field", "notes") == 0
    assert capsys.readouterr().out == "n\n"
    assert server_run("get", "tok", "--raw", "--version", "1") == 0
    assert capsys.readouterr().out == "old-token\n"


def test_server_raw_not_found_and_empty_field(server: FakeServer, capsys: pytest.CaptureFixture[str]):
    assert server_run("get", "missing", "--raw") == exit_codes.NOT_FOUND
    assert server_run("get", "empty", "--raw", "--field", "url") == exit_codes.NOT_FOUND
    assert capsys.readouterr().out == ""


def test_server_raw_errors_print_nothing_on_stdout(server: FakeServer, capsys: pytest.CaptureFixture[str]):
    server.override = lambda r: httpx.Response(500, text="boom")
    assert server_run("get", "tok", "--raw") == exit_codes.ERROR
    assert capsys.readouterr().out == ""
    bad_key = main(["--server-url", SERVER, "--api-key", "wrong", "get", "tok", "--raw"])
    assert bad_key == exit_codes.ERROR
    assert capsys.readouterr().out == ""
