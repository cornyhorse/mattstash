"""``MattStash.resolve_env`` and the ``env`` / ``exec`` commands (docs/security-review.md G-1)."""

import json
import logging
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Dict, Optional
from unittest.mock import patch

import httpx
import pytest
from dbhelpers import create_db
from fake_server import FakeServer

from mattstash import MattStash
from mattstash.cli import exit_codes
from mattstash.cli.main import main
from mattstash.utils.exceptions import CredentialNotFoundError, DatabaseAccessError, DatabaseNotFoundError

SERVER = "http://localhost:8000"
KEY = "api-key-value"
HOSTILE = 'it\'s "q" $(echo PWNED) `echo PWNED2` ${HOME} \\n ; & | > < * ? !\n#tab\tend é😀 '

ENTRIES = [
    {"title": "app/db-password@0000000001", "password": "pw-db-old"},
    {"title": "app/db-password@0000000002", "password": "pw-db-new"},
    {"title": "app/api.key", "password": "key-123"},
    {
        "title": "app/user",
        "username": "svc",
        "password": "svc-pw",
        "url": "svc.local:9",
        "notes": "n1\nn2",
        "props": {"region": "eu-1", "token": "tok-9"},
    },
    {"title": "app/hostile", "password": HOSTILE},
    {"title": "app/empty-pw", "username": "only-user"},
    {"title": "other/thing", "password": "not-selected"},
    {"title": "bad/1st", "password": "x"},
    {"title": "dup/a-b", "password": "1"},
    {"title": "dup/a_b", "password": "2"},
    {"title": "Mixed/Foo", "password": "m"},
    {"title": "svc:prod@0000000001", "password": "colon-pw"},
]


@pytest.fixture(scope="module")
def db(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return create_db(tmp_path_factory.mktemp("env") / "env.kdbx", ENTRIES)


def run(db: Path, *argv: str) -> int:
    return main(["--db", str(db), *argv])


# ---------------------------------------------------------------------------
# the Python API
# ---------------------------------------------------------------------------


def test_resolve_env_prefix_uses_latest_versions(db: Path):
    env = MattStash(path=str(db)).resolve_env("app/")
    assert env == {
        "api_key": "key-123",
        "db_password": "pw-db-new",
        "hostile": HOSTILE,
        "user": "svc-pw",
    }


def test_resolve_env_options(db: Path):
    ms = MattStash(path=str(db))
    assert set(ms.resolve_env("app/", upper=True)) == {"API_KEY", "DB_PASSWORD", "HOSTILE", "USER"}
    assert set(ms.resolve_env("app/", strip_prefix=False, upper=True)) == {
        "APP_API_KEY",
        "APP_DB_PASSWORD",
        "APP_HOSTILE",
        "APP_USER",
    }


def test_resolve_env_mappings_and_fields(db: Path):
    env = MattStash(path=str(db)).resolve_env(
        mappings={
            "DB": "app/db-password",
            "U": "app/user:username",
            "P": "app/user",
            "H": "app/user:url",
            "N": "app/user:notes",
            "R": "app/user:region",
            "T": "app/user:token",
            "COLON": "svc:prod:password",
        }
    )
    assert env == {
        "DB": "pw-db-new",
        "U": "svc",
        "P": "svc-pw",
        "H": "svc.local:9",
        "N": "n1\nn2",
        "R": "eu-1",
        "T": "tok-9",
        "COLON": "colon-pw",
    }


def test_resolve_env_accepts_cli_style_mapping_strings(db: Path):
    assert MattStash(path=str(db)).resolve_env(mappings=["A=app/api.key", "B=app/user:username"]) == {
        "A": "key-123",
        "B": "svc",
    }


def test_resolve_env_errors(db: Path):
    ms = MattStash(path=str(db))
    with pytest.raises(ValueError, match="nothing selected"):
        ms.resolve_env()
    with pytest.raises(CredentialNotFoundError):
        ms.resolve_env("zzz/")
    with pytest.raises(CredentialNotFoundError, match="not found"):
        ms.resolve_env(mappings={"A": "nope"})
    with pytest.raises(CredentialNotFoundError, match="no value for field"):
        ms.resolve_env(mappings={"A": "app/user:missing"})
    with pytest.raises(CredentialNotFoundError, match="no value for field 'username'"):
        ms.resolve_env(mappings={"A": "app/api.key:username"})
    with pytest.raises(ValueError, match="would be set by both"):
        ms.resolve_env("dup/")
    with pytest.raises(ValueError, match="valid environment variable name"):
        ms.resolve_env("bad/")
    with pytest.raises(ValueError, match="invalid environment variable name"):
        ms.resolve_env(mappings={"bad-name": "app/api.key"})


def test_resolve_env_skips_empty_passwords_with_a_warning(db: Path, caplog: pytest.LogCaptureFixture):
    with caplog.at_level(logging.WARNING):
        env = MattStash(path=str(db)).resolve_env("app/")
    assert "empty_pw" not in env
    assert "skipping 'app/empty-pw'" in caplog.text
    assert "svc-pw" not in caplog.text and "key-123" not in caplog.text


def test_resolve_env_validates_titles(db: Path):
    with pytest.raises(Exception, match="title"):
        MattStash(path=str(db)).resolve_env(mappings={"A": "x\0y"})


def test_resolve_env_database_errors_are_typed(db: Path, tmp_path: Path):
    with pytest.raises(DatabaseAccessError):
        MattStash(path=str(db), password="wrong").resolve_env("app/")
    with pytest.raises(DatabaseNotFoundError):
        MattStash(path=str(tmp_path / "none.kdbx"), password="x").resolve_env("app/")


def test_resolve_env_sees_one_consistent_snapshot(db: Path):
    ms = MattStash(path=str(db))
    first = ms.resolve_env("app/")
    assert ms.resolve_env("app/") == first


# ---------------------------------------------------------------------------
# mattstash env
# ---------------------------------------------------------------------------


def test_env_shell_exact_output(db: Path, capsys: pytest.CaptureFixture[str]):
    assert run(db, "env", "--map", "B_VAR=app/user:username", "--map", "A_VAR=app/api.key") == 0
    assert capsys.readouterr().out == "export A_VAR=key-123\nexport B_VAR=svc\n"


def test_env_prefix_names_and_flags(db: Path, capsys: pytest.CaptureFixture[str]):
    assert run(db, "env", "--prefix", "app/") == 0
    names = [line.split("=", 1)[0] for line in capsys.readouterr().out.splitlines() if line.startswith("export ")]
    assert names == ["export api_key", "export db_password", "export hostile", "export user"]

    assert run(db, "env", "--prefix", "app/", "--upper", "--format", "json") == 0
    assert set(json.loads(capsys.readouterr().out)) == {"API_KEY", "DB_PASSWORD", "HOSTILE", "USER"}

    assert run(db, "env", "--prefix", "app/", "--no-strip-prefix", "--upper", "--format", "json") == 0
    assert set(json.loads(capsys.readouterr().out)) == {"APP_API_KEY", "APP_DB_PASSWORD", "APP_HOSTILE", "APP_USER"}


def test_env_json_and_dotenv_formats(db: Path, capsys: pytest.CaptureFixture[str]):
    args = ["env", "--prefix", "app/", "--upper"]
    assert run(db, *args, "--format", "json") == 0
    data = json.loads(capsys.readouterr().out)
    assert data == {"API_KEY": "key-123", "DB_PASSWORD": "pw-db-new", "HOSTILE": HOSTILE, "USER": "svc-pw"}

    assert run(db, "env", "--map", "A=app/api.key", "--map", "B=app/user:notes", "--format", "dotenv") == 0
    assert capsys.readouterr().out == 'A=key-123\nB="n1\\nn2"\n'


def test_env_shell_output_survives_eval_in_a_real_shell(db: Path, tmp_path: Path):
    """The hostile value (quotes, $(), backticks, newline, ...) must come back byte-for-byte and run nothing."""
    proc = subprocess.run(
        [sys.executable, "-m", "mattstash.cli.main", "--db", str(db), "env", "--map", "HOSTILE=app/hostile"],
        capture_output=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    script = 'eval "$1"; printf %s "$HOSTILE"'
    shell = subprocess.run(["sh", "-c", script, "sh", proc.stdout.decode()], capture_output=True, timeout=30)
    assert shell.stdout.decode() == HOSTILE
    assert shell.stderr == b"", "nothing in the value may have been executed"


def test_env_latest_version_wins(db: Path, capsys: pytest.CaptureFixture[str]):
    assert run(db, "env", "--map", "X=app/db-password") == 0
    assert capsys.readouterr().out == "export X=pw-db-new\n"


@pytest.mark.parametrize(
    "argv,code,fragment",
    [
        (["env"], 1, "nothing selected"),
        (["env", "--prefix", "zzz/"], 2, "no secrets found with prefix"),
        (["env", "--map", "A=nope"], 2, "secret not found: nope"),
        (["env", "--map", "A=app/user:missing"], 2, "no value for field 'missing'"),
        (["env", "--map", "A=app/api.key:username"], 2, "no value for field 'username'"),
        (["env", "--map", "1A=app/api.key"], 1, "invalid environment variable name"),
        (["env", "--map", "A-B=app/api.key"], 1, "invalid environment variable name"),
        (["env", "--map", "NOEQUALS"], 1, "invalid mapping"),
        (["env", "--map", "A=app/api.key", "--map", "A=app/user"], 1, "mapped more than once"),
        (["env", "--prefix", "dup/"], 1, "would be set by both"),
        (["env", "--prefix", "bad/"], 1, "valid environment variable name"),
        (["env", "--prefix", "app/api.", "--map", "key=app/user"], 1, "would be set by both"),
    ],
)
def test_env_errors_print_nothing_on_stdout(
    db: Path,
    argv: list,
    code: int,
    fragment: str,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
):
    assert run(db, *argv) == code
    assert capsys.readouterr().out == ""
    assert fragment in caplog.text
    for secret in ("key-123", "svc-pw", "pw-db-new", "pw-db-old", "tok-9"):
        assert secret not in caplog.text, "secret values never appear in error messages"


def test_env_database_errors(db: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    assert main(["--db", str(db), "--password", "wrong", "env", "--prefix", "app/"]) == exit_codes.DB_ACCESS
    assert (
        main(["--db", str(tmp_path / "x.kdbx"), "--password", "p", "env", "--prefix", "a"]) == exit_codes.DB_NOT_FOUND
    )
    assert capsys.readouterr().out == ""


def test_env_invalid_format_is_rejected_by_argparse(db: Path):
    with pytest.raises(SystemExit):
        run(db, "env", "--prefix", "app/", "--format", "yaml")


def test_env_help_documents_the_options(capsys: pytest.CaptureFixture[str]):
    with pytest.raises(SystemExit):
        main(["env", "--help"])
    text = " ".join(capsys.readouterr().out.split())
    for expected in (
        "--prefix",
        "--map ENVVAR=TITLE[:FIELD]",
        "--strip-prefix",
        "--no-strip-prefix",
        "--upper",
        "shell,dotenv,json",
    ):
        assert expected in text, expected


# ---------------------------------------------------------------------------
# mattstash exec (execve patched: we look at what would be executed)
# ---------------------------------------------------------------------------


@pytest.fixture()
def fake_exec():
    with patch("mattstash.cli.handlers.env.os.execve") as mocked:
        yield mocked


def test_exec_passes_secrets_to_the_command(db: Path, fake_exec, capsys: pytest.CaptureFixture[str]):
    rc = run(db, "exec", "--prefix", "app/api.", "--upper", "--", "sh", "-c", "echo hi")
    assert rc == 0
    program, argv, env = fake_exec.call_args.args
    assert os.path.basename(program) == "sh" and os.path.isabs(program)
    assert argv == ["sh", "-c", "echo hi"]
    assert env["KEY"] == "key-123"
    assert env["PATH"] == os.environ["PATH"]
    captured = capsys.readouterr()
    assert captured.out == "" and "key-123" not in captured.err, "nothing is printed before exec"


def test_exec_dash_dash_is_optional_but_options_must_come_first(db: Path, fake_exec):
    assert run(db, "exec", "--map", "X=app/api.key", "sh", "-c", "true") == 0
    assert fake_exec.call_args.args[1] == ["sh", "-c", "true"]
    assert run(db, "exec", "--map", "X=app/api.key", "--", "sh", "--map", "ignored") == 0
    assert fake_exec.call_args.args[1] == ["sh", "--map", "ignored"], "after the command everything is its own"


def test_exec_existing_variables_win_unless_override(db: Path, fake_exec, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("KEEP", "from-the-environment")
    argv = ["exec", "--map", "KEEP=app/api.key", "--map", "NEW=app/user:username", "--", "sh"]
    assert run(db, *argv) == 0
    env = fake_exec.call_args.args[2]
    assert env["KEEP"] == "from-the-environment" and env["NEW"] == "svc"

    assert run(db, "exec", "--override", *argv[1:]) == 0
    env = fake_exec.call_args.args[2]
    assert env["KEEP"] == "key-123" and env["NEW"] == "svc"
    assert os.environ["KEEP"] == "from-the-environment", "the parent environment is never modified"


def test_exec_secret_named_path_cannot_redirect_the_command_lookup(db: Path, fake_exec):
    rc = run(db, "exec", "--override", "--map", "PATH=app/user:region", "--", "sh", "-c", "true")
    assert rc == 0
    program, _argv, env = fake_exec.call_args.args
    assert os.path.isabs(program)  # found through the caller's PATH
    assert env["PATH"] == "eu-1"


def test_exec_requires_a_command(db: Path, fake_exec, caplog: pytest.LogCaptureFixture):
    for argv in (["exec", "--prefix", "app/"], ["exec", "--prefix", "app/", "--"]):
        assert run(db, *argv) == exit_codes.ERROR
    assert "no command given" in caplog.text
    fake_exec.assert_not_called()


def test_exec_command_not_found_and_not_executable(db: Path, tmp_path: Path, fake_exec, caplog):
    assert run(db, "exec", "--prefix", "app/api", "--", "definitely-not-a-command-xyz") == 127
    assert "command not found" in caplog.text
    plain = tmp_path / "plain.txt"
    plain.write_text("x")
    assert run(db, "exec", "--prefix", "app/api", "--", str(plain)) == 126
    assert "permission denied" in caplog.text
    fake_exec.assert_not_called()


def test_exec_selection_errors_do_not_run_anything(db: Path, fake_exec, caplog: pytest.LogCaptureFixture):
    assert run(db, "exec", "--prefix", "zzz/", "--", "sh") == exit_codes.NOT_FOUND
    assert run(db, "exec", "--", "sh") == exit_codes.ERROR
    assert run(db, "exec", "--map", "A=nope", "--", "sh") == exit_codes.NOT_FOUND
    assert (
        main(["--db", str(db), "--password", "wrong", "exec", "--prefix", "app/", "--", "sh"]) == exit_codes.DB_ACCESS
    )
    fake_exec.assert_not_called()


def test_exec_reports_an_execve_failure(db: Path, fake_exec, caplog: pytest.LogCaptureFixture):
    fake_exec.side_effect = OSError(8, "Exec format error")
    assert run(db, "exec", "--prefix", "app/api", "--", "sh") == 126
    assert "Exec format error" in caplog.text


# ---------------------------------------------------------------------------
# mattstash exec in a real process
# ---------------------------------------------------------------------------


def cli(db: Path, *argv: str, env: Optional[Dict[str, str]] = None) -> "subprocess.CompletedProcess[bytes]":
    return subprocess.run(
        [sys.executable, "-m", "mattstash.cli.main", "--db", str(db), *argv],
        capture_output=True,
        env={**os.environ, **(env or {})},
        timeout=120,
    )


def test_exec_real_process_sees_the_secrets_and_keeps_the_exit_status(db: Path):
    proc = cli(
        db,
        "exec",
        "--prefix",
        "app/",
        "--upper",
        "--",
        "sh",
        "-c",
        'printf "%s|%s|%s" "$API_KEY" "$USER" "$DB_PASSWORD"; exit 42',
    )
    assert proc.returncode == 42
    assert proc.stdout == b"key-123|svc-pw|pw-db-new"
    assert b"key-123" not in proc.stderr and b"svc-pw" not in proc.stderr


def test_exec_real_process_hostile_value_round_trips(db: Path):
    proc = cli(db, "exec", "--map", "H=app/hostile", "--", "sh", "-c", 'printf %s "$H"')
    assert proc.returncode == 0
    assert proc.stdout.decode() == HOSTILE


def test_exec_real_process_existing_env_wins_unless_override(db: Path):
    command = ["sh", "-c", 'printf %s "$K"']
    keep = cli(db, "exec", "--map", "K=app/api.key", "--", *command, env={"K": "preset"})
    assert keep.stdout == b"preset"
    over = cli(db, "exec", "--override", "--map", "K=app/api.key", "--", *command, env={"K": "preset"})
    assert over.stdout == b"key-123"


def test_exec_real_process_exit_codes_for_missing_commands(db: Path, tmp_path: Path):
    assert cli(db, "exec", "--prefix", "app/api", "--", "no-such-command-xyz").returncode == 127
    script = tmp_path / "noexec.sh"
    script.write_text("#!/bin/sh\necho hi\n")
    script.chmod(stat.S_IRUSR | stat.S_IWUSR)
    assert cli(db, "exec", "--prefix", "app/api", "--", str(script)).returncode == 126
    assert cli(db, "exec", "--prefix", "app/api").returncode == 1


def test_exec_failure_never_leaks_secrets_to_the_output(db: Path):
    proc = cli(db, "exec", "--map", "S=app/api.key", "--", "sh", "-c", "exit 3")
    assert proc.returncode == 3
    assert b"key-123" not in proc.stdout + proc.stderr


# ---------------------------------------------------------------------------
# server mode
# ---------------------------------------------------------------------------


@pytest.fixture()
def server(monkeypatch: pytest.MonkeyPatch) -> FakeServer:
    fake = FakeServer(api_key=KEY).install(monkeypatch)
    fake.add("app-db", "db-pw-old", username="dbuser")
    fake.add("app-db", "db-pw", username="dbuser", url="db:5432", notes="note")
    fake.add("app-key", "key-pw")
    fake.add("other", "other-pw")
    return fake


def server_run(*argv: str) -> int:
    return main(["--server-url", SERVER, "--api-key", KEY, *argv])


def test_server_env_prefix_lists_names_then_fetches_each(server: FakeServer, capsys: pytest.CaptureFixture[str]):
    assert server_run("env", "--prefix", "app-", "--upper", "--format", "json") == 0
    assert json.loads(capsys.readouterr().out) == {"DB": "db-pw", "KEY": "key-pw"}
    listing = server.requests[0]
    assert listing.url.raw_path.decode().startswith("/api/v1/credentials?")
    assert dict(listing.url.params) == {"show_password": "false", "prefix": "app-"}
    fetches = [r for r in server.requests[1:]]
    assert sorted(r.url.raw_path.decode().split("?")[0] for r in fetches) == [
        "/api/v1/credentials/app-db",
        "/api/v1/credentials/app-key",
    ]
    assert all(dict(r.url.params)["show_password"] == "true" for r in fetches)


def test_server_env_map_fields(server: FakeServer, capsys: pytest.CaptureFixture[str]):
    assert server_run("env", "--map", "U=app-db:username", "--map", "P=app-db", "--map", "N=app-db:notes") == 0
    assert capsys.readouterr().out == "export N=note\nexport P=db-pw\nexport U=dbuser\n"
    assert not any(r.url.raw_path.decode().startswith("/api/v1/credentials?") for r in server.requests)


def test_server_env_errors(server: FakeServer, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture):
    assert server_run("env", "--map", "A=nope") == exit_codes.NOT_FOUND
    assert server_run("env", "--prefix", "zzz") == exit_codes.NOT_FOUND
    assert server_run("env", "--map", "A=app-db:region") == exit_codes.ERROR
    assert "not available in server mode" in caplog.text
    assert server_run("env", "--map", "A=other:url") == exit_codes.NOT_FOUND  # no url on that secret
    assert capsys.readouterr().out == ""


def test_server_env_http_errors_do_not_leak(server: FakeServer, capsys: pytest.CaptureFixture[str], caplog):
    server.override = lambda r: httpx.Response(500, text="boom db-pw")
    assert server_run("env", "--prefix", "app-") == exit_codes.ERROR
    assert capsys.readouterr().out == ""
    assert "HTTP 500" in caplog.text and "db-pw" not in caplog.text and KEY not in caplog.text


def test_server_env_requires_a_key(server: FakeServer, caplog: pytest.LogCaptureFixture):
    assert main(["--server-url", SERVER, "env", "--prefix", "app-"]) == exit_codes.ERROR
    assert "API key required" in caplog.text
    assert server.requests == []


def test_server_exec(server: FakeServer, fake_exec, capsys: pytest.CaptureFixture[str]):
    assert server_run("exec", "--prefix", "app-", "--upper", "--", "sh", "-c", "true") == 0
    _program, argv, env = fake_exec.call_args.args
    assert argv == ["sh", "-c", "true"]
    assert env["DB"] == "db-pw" and env["KEY"] == "key-pw" and "OTHER" not in env
    assert capsys.readouterr().out == ""
