"""
``put -i`` / ``mattstash -i``: prompt for the title (when omitted) and the secret on the terminal.

Default: a full credential (username + password). ``--value`` without an argument: only the value.
"""

import io
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Optional

import pytest
from fake_server import FakeServer

from mattstash import MattStash
from mattstash.cli import exit_codes
from mattstash.cli.inputs import InputError, prompt_line, prompt_new_secret, require_terminal
from mattstash.cli.main import _expand_interactive_shortcut, main

if TYPE_CHECKING:
    from collections.abc import Iterator

SERVER = "http://localhost:8000"
KEY = "api-key-value"


def terminal(monkeypatch: pytest.MonkeyPatch, lines: str = "", secrets: Optional[list[str]] = None) -> list[str]:
    """A terminal on stdin that answers visible prompts with ``lines`` and hidden ones with ``secrets``.

    Returns the list of hidden prompts shown."""

    class Tty(io.StringIO):
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr(sys, "stdin", Tty(lines))
    answers: Iterator[str] = iter(secrets or [])
    shown: list[str] = []

    def getpass(prompt: str = "") -> str:
        shown.append(prompt)
        return next(answers)

    monkeypatch.setattr("getpass.getpass", getpass)
    return shown


def stored(db: Path, title: str) -> object:
    return MattStash(path=str(db)).get(title, show_password=True)


# ---------------------------------------------------------------------------
# full credential (default)
# ---------------------------------------------------------------------------


def test_interactive_prompts_for_username_and_password(
    temp_db: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    hidden = terminal(monkeypatch, "dbuser\n", ["s3cret", "s3cret"])
    assert main(["--db", str(temp_db), "put", "prod-db", "-i", "--url", "db:5432"]) == exit_codes.OK
    cred = stored(temp_db, "prod-db")
    assert (cred.username, cred.password, cred.url) == ("dbuser", "s3cret", "db:5432")  # type: ignore[attr-defined]
    out = capsys.readouterr()
    assert out.out == "prod-db: OK\n"
    assert "Username: " in out.err  # prompts go to stderr, not into the command's output
    assert "s3cret" not in out.out + out.err
    assert len(hidden) == 2


def test_interactive_prompts_for_missing_title(temp_db: Path, monkeypatch: pytest.MonkeyPatch):
    terminal(monkeypatch, "  myapp.db  \ndbuser\n", ["pw", "pw"])
    assert main(["--db", str(temp_db), "put", "-i"]) == exit_codes.OK
    assert stored(temp_db, "myapp.db").username == "dbuser"  # type: ignore[attr-defined]


def test_interactive_username_option_skips_prompt(temp_db: Path, monkeypatch: pytest.MonkeyPatch):
    terminal(monkeypatch, "", ["pw", "pw"])  # no visible input at all
    assert main(["--db", str(temp_db), "put", "x", "-i", "--username", "u"]) == exit_codes.OK
    assert stored(temp_db, "x").username == "u"  # type: ignore[attr-defined]


def test_interactive_empty_username_is_allowed(temp_db: Path, monkeypatch: pytest.MonkeyPatch):
    terminal(monkeypatch, "\n", ["pw", "pw"])
    assert main(["--db", str(temp_db), "put", "x", "--interactive"]) == exit_codes.OK
    # without a username or URL the entry reads back as a simple secret
    assert stored(temp_db, "x")["value"] == "pw"  # type: ignore[index]


def test_top_level_shortcut(temp_db: Path, monkeypatch: pytest.MonkeyPatch):
    terminal(monkeypatch, "u\n", ["pw", "pw"])
    assert main(["--db", str(temp_db), "-i", "short"]) == exit_codes.OK
    assert stored(temp_db, "short").password == "pw"  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# value (password-only) mode
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        ["put", "tok", "-i", "--value"],
        ["put", "tok", "--value"],  # a bare --value prompts as well
        ["-i", "tok", "--value"],
    ],
)
def test_interactive_value_mode(temp_db: Path, monkeypatch: pytest.MonkeyPatch, argv: list[str]):
    hidden = terminal(monkeypatch, "", ["v4lue", "v4lue"])
    assert main(["--db", str(temp_db), *argv]) == exit_codes.OK
    assert stored(temp_db, "tok")["value"] == "v4lue"  # type: ignore[index]
    assert hidden[0].startswith("Password")


def test_interactive_value_mode_prompts_for_title(temp_db: Path, monkeypatch: pytest.MonkeyPatch):
    terminal(monkeypatch, "tok\n", ["v", "v"])
    assert main(["--db", str(temp_db), "-i", "--value"]) == exit_codes.OK
    assert stored(temp_db, "tok")["value"] == "v"  # type: ignore[index]


def test_interactive_value_mode_keeps_db_password(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db = tmp_path / "pw.kdbx"
    MattStash.create(str(db), password="master")
    terminal(monkeypatch, "", ["v", "v"])
    assert main(["--db", str(db), "--password", "master", "put", "tok", "-i", "--value"]) == exit_codes.OK
    assert MattStash(path=str(db), password="master").get("tok", show_password=True)["value"] == "v"  # type: ignore[index]


def test_interactive_fields_with_db_password(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db = tmp_path / "pw.kdbx"
    MattStash.create(str(db), password="master")
    terminal(monkeypatch, "u\n", ["entry", "entry"])
    assert main(["--db", str(db), "--db-password", "master", "put", "c", "-i"]) == exit_codes.OK
    assert MattStash(path=str(db), password="master").get("c", show_password=True).password == "entry"  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "extra,message",
    [
        (["--value", "literal"], "--value takes no argument"),
        (["--value-file", "f"], "--value-file"),
        (["--entry-password", "p"], "--entry-password"),
        (["--entry-password-file", "f"], "--entry-password-file"),
        (["--entry-password-stdin"], "--entry-password-stdin"),
        (["--value", "--username", "u"], "simple secret"),
        (["--password", "p"], "--db-password"),
    ],
)
def test_interactive_rejects_conflicting_options(
    temp_db: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, extra: list[str], message: str
):
    terminal(monkeypatch)
    assert main(["--db", str(temp_db), "put", "x", "-i", *extra]) == exit_codes.ERROR
    assert message in caplog.text
    assert stored(temp_db, "x") is None


def test_interactive_needs_a_terminal(temp_db: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture):
    monkeypatch.setattr(sys, "stdin", io.StringIO("u\n"))
    assert main(["--db", str(temp_db), "put", "x", "-i"]) == exit_codes.ERROR
    assert "needs a terminal" in caplog.text


@pytest.mark.parametrize(
    "lines,secrets,message",
    [
        ("\n", [], "a title is required"),
        ("", [], "end of input"),
        ("k\nu\n", ["", ""], "empty value"),
        ("k\nu\n", ["one", "two"], "do not match"),
    ],
)
def test_interactive_bad_answers(
    temp_db: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    lines: str,
    secrets: list[str],
    message: str,
):
    terminal(monkeypatch, lines, secrets)
    assert main(["--db", str(temp_db), "put", "-i"]) == exit_codes.ERROR
    assert message in caplog.text
    assert MattStash(path=str(temp_db)).list() == []


def test_title_still_required_without_interactive(temp_db: Path, caplog: pytest.LogCaptureFixture):
    assert main(["--db", str(temp_db), "put", "--value-file", "f"]) == exit_codes.ERROR
    assert "a title is required" in caplog.text


# ---------------------------------------------------------------------------
# server mode, helpers, argv shortcut
# ---------------------------------------------------------------------------


def test_interactive_server_mode(monkeypatch: pytest.MonkeyPatch):
    server = FakeServer(api_key=KEY).install(monkeypatch)
    base = ["--server-url", SERVER, "--api-key", KEY]
    terminal(monkeypatch, "u\n", ["pw", "pw", "val", "val"])
    assert main([*base, "-i", "cred"]) == exit_codes.OK
    assert main([*base, "-i", "simple", "--value"]) == exit_codes.OK
    assert server.store["cred"][1]["username"] == "u"
    assert server.store["cred"][1]["password"] == "pw"
    assert server.store["simple"][1]["password"] == "val"


def test_helpers(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    with pytest.raises(InputError, match="needs a terminal"):
        require_terminal("-i")
    with pytest.raises(InputError, match="Key: no data"):
        prompt_line("Key: ")
    terminal(monkeypatch, "", ["a", "a"])
    assert prompt_new_secret("Password") == "a"


@pytest.mark.parametrize(
    "argv,expected",
    [
        (["-i"], ["put", "-i"]),
        (["--interactive", "k"], ["put", "--interactive", "k"]),
        (["--db", "x", "--verbose", "-i", "k"], ["--db", "x", "--verbose", "put", "-i", "k"]),
        (["--db=x", "-i"], ["--db=x", "put", "-i"]),
        (["get", "-i"], ["get", "-i"]),  # not ours: argparse reports it
        (["put", "k", "-i"], ["put", "k", "-i"]),
        (["--", "-i"], ["--", "-i"]),
        ([], []),
    ],
)
def test_expand_interactive_shortcut(argv: list[str], expected: list[str]):
    assert _expand_interactive_shortcut(argv) == expected
