"""Regression tests for the second independent review: secret input, ``env``, ``exec`` and ``get --raw``.

Finding ids (M-1.., L-1..) are the reviewer's.
"""

import io
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Dict, Optional
from unittest.mock import patch

import pytest
from dbhelpers import create_db

from mattstash import MattStash
from mattstash.cli import exit_codes
from mattstash.cli.main import main
from mattstash.core.env_vars import format_env, is_reserved_env_name

ENTRIES = [
    {"title": "app_DB_PASSWORD", "password": "db-pw"},
    {"title": "app_LD_PRELOAD", "password": "/tmp/evil.so"},
    {"title": "app_PATH", "password": "/tmp/evilbin:/usr/bin"},
    {"title": "app_PYTHONPATH", "password": "/tmp/evil"},
    {"title": "app_BASH_ENV", "password": "/tmp/evil.sh"},
    {"title": "app_KDBX_PASSWORD", "password": "swap-the-vault-password"},
    {"title": "plain", "password": "p", "notes": "some notes"},
    {"title": "myapp.db-password", "password": "dotted"},
]


@pytest.fixture(scope="module")
def db(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return create_db(tmp_path_factory.mktemp("round2") / "r2.kdbx", ENTRIES)


def run(db: Path, *argv: str) -> int:
    return main(["--db", str(db), *argv])


# ---------------------------------------------------------------------------
# M-1: a secret's title must not be able to choose loader/shell control variables
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        *("LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "PATH", "IFS", "BASH_ENV", "PS4"),
        *("PROMPT_COMMAND", "PYTHONPATH", "NODE_OPTIONS", "PERL5OPT", "RUBYOPT", "JAVA_TOOL_OPTIONS"),
        *("KDBX_PASSWORD", "HOME"),
    ],
)
def test_m1_reserved_names_are_recognised(name: str):
    assert is_reserved_env_name(name)


@pytest.mark.parametrize("name", ["DB_PASSWORD", "API_KEY", "NODE_ENV", "PATHS", "MY_PATH", "LDAP_HOST", "PS5"])
def test_m1_ordinary_names_are_not_reserved(name: str):
    assert not is_reserved_env_name(name)


def test_m1_prefix_selecting_reserved_names_is_refused_and_prints_nothing(
    db: Path, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
):
    assert run(db, "env", "--prefix", "app_") == exit_codes.ERROR
    captured = capsys.readouterr()
    assert captured.out == "", "nothing is exported when any selected name is refused"
    assert "reserved variable" in caplog.text and "--allow-reserved" in caplog.text and "evil" not in caplog.text


def test_m1_allow_reserved_and_explicit_map_are_the_operators_choice(db: Path, capsys: pytest.CaptureFixture[str]):
    assert run(db, "env", "--prefix", "app_", "--allow-reserved") == exit_codes.OK
    out = capsys.readouterr().out
    assert "export LD_PRELOAD=/tmp/evil.so" in out and "export DB_PASSWORD=db-pw" in out
    assert run(db, "env", "--map", "LD_PRELOAD=app_LD_PRELOAD") == exit_codes.OK
    assert capsys.readouterr().out == "export LD_PRELOAD=/tmp/evil.so\n"


def test_m1_exec_refuses_too_and_nothing_is_executed(db: Path):
    with patch("mattstash.cli.handlers.env.os.execve") as execve:
        assert run(db, "exec", "--prefix", "app_", "--", "sh") == exit_codes.ERROR
    execve.assert_not_called()


def test_m1_the_python_api_has_the_same_default(db: Path):
    stash = MattStash(path=str(db))
    with pytest.raises(ValueError, match="reserved variable"):
        stash.resolve_env(prefix="app_")
    assert stash.resolve_env(prefix="app_", allow_reserved=True)["LD_PRELOAD"] == "/tmp/evil.so"


# ---------------------------------------------------------------------------
# M-2: docker run --env-file has no quoting; never write a value it would corrupt
# ---------------------------------------------------------------------------


def test_m2_docker_env_format_is_literal_and_refuses_what_it_cannot_carry():
    assert format_env({"A": "has space inside", "B": "q'uote$x#y\\z"}, "docker-env") == (
        "A=has space inside\nB=q'uote$x#y\\z\n"
    )
    for bad in ("line1\nline2", "cr\rx", " leading", "trailing ", "nul\0x"):
        with pytest.raises(ValueError, match="docker --env-file"):
            format_env({"X": bad}, "docker-env")


def test_m2_cli_docker_env(db: Path, capsys: pytest.CaptureFixture[str]):
    assert run(db, "env", "--map", "A=plain", "--format", "docker-env") == exit_codes.OK
    assert capsys.readouterr().out == "A=p\n"


# ---------------------------------------------------------------------------
# M-3: the documented prefix convention must be creatable with `put`
# ---------------------------------------------------------------------------


def test_m3_dotted_prefix_works_end_to_end_through_put(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    path = tmp_path / "m3.kdbx"
    MattStash.create(str(path), password="pw", sidecar=False)
    stdin = io.TextIOWrapper(io.BytesIO(b"s3cret\n"))
    with patch.object(sys, "stdin", stdin):
        assert main(["--db", str(path), "--password", "pw", "put", "myapp.db-password", "--value", "-"]) == 0
    capsys.readouterr()
    assert main(["--db", str(path), "--password", "pw", "env", "--prefix", "myapp.", "--upper"]) == 0
    assert capsys.readouterr().out == "export DB_PASSWORD=s3cret\n"
    # a '/' separator is not accepted by put (and not routable on the server): the docs use '.'
    assert main(["--db", str(path), "--password", "pw", "put", "myapp/db-password", "--value", "x"]) != 0


# ---------------------------------------------------------------------------
# exec details: L-1 signals, L-2 mapped vault names, L-4 exit 126
# ---------------------------------------------------------------------------


def exec_cli(db: Path, *argv: str, env: Optional[Dict[str, str]] = None) -> "subprocess.CompletedProcess[bytes]":
    return subprocess.run(
        [sys.executable, "-m", "mattstash.cli.main", "--db", str(db), *argv],
        capture_output=True,
        stdin=subprocess.DEVNULL,
        env={**os.environ, "KDBX_PASSWORD": "test-master-pw", **(env or {})},
        timeout=120,
    )


@pytest.mark.skipif(not os.path.exists("/proc/self/status"), reason="needs /proc")
def test_l1_exec_does_not_leave_sigpipe_and_sigxfsz_ignored(db: Path):
    proc = exec_cli(db, "exec", "--map", "X=plain", "--", "sh", "-c", "grep SigIgn /proc/self/status")
    assert proc.returncode == 0, proc.stderr
    ignored = int(proc.stdout.split()[1], 16)
    assert not ignored & (1 << 12), "SIGPIPE (13) must not be ignored in the command"
    assert not ignored & (1 << 24), "SIGXFSZ (25) must not be ignored in the command"


def test_l2_a_secret_mapped_to_a_vault_variable_is_injected_without_override(db: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("KDBX_PASSWORD", "test-master-pw")
    with patch("mattstash.cli.handlers.env.os.execve") as execve:
        assert run(db, "exec", "--map", "KDBX_PASSWORD=plain", "--", "sh") == 0
    assert execve.call_args.args[2]["KDBX_PASSWORD"] == "p"


def test_l4_a_command_that_exists_on_path_but_is_not_executable_is_126(db: Path, tmp_path: Path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    script = bindir / "noexec"
    script.write_text("#!/bin/sh\necho hi\n")
    script.chmod(stat.S_IRUSR | stat.S_IWUSR)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    with patch("mattstash.cli.handlers.env.os.execve") as execve:
        assert run(db, "exec", "--map", "X=plain", "--", "noexec") == exit_codes.COMMAND_NOT_EXECUTABLE
        assert run(db, "exec", "--map", "X=plain", "--", "no-such-command-xyz") == exit_codes.COMMAND_NOT_FOUND
    execve.assert_not_called()


# ---------------------------------------------------------------------------
# L-7 / put
# ---------------------------------------------------------------------------


def test_l7_get_raw_notes_of_a_simple_secret(db: Path, capsys: pytest.CaptureFixture[str]):
    assert run(db, "get", "plain", "--raw", "--field", "notes") == exit_codes.OK
    assert capsys.readouterr().out == "some notes\n"


def test_put_entry_password_dash_is_not_silently_a_literal_dash(tmp_path: Path, caplog):
    path = tmp_path / "p.kdbx"
    MattStash.create(str(path), password="pw", sidecar=False)
    assert main(["--db", str(path), "--db-password", "pw", "put", "x", "--fields", "--entry-password", "-"]) != 0
    assert "--entry-password-stdin" in caplog.text
    assert MattStash(str(path), password="pw").get("x") is None
