"""Line-coverage tests for the command-line layer: ``cli.main``, ``cli.inputs`` and the command handlers.

Everything runs in-process through ``main(argv)``: databases are real (tiny, cheap-KDF) ones and server mode talks to
``FakeServer``. A few branches cannot be reached from the command line (argparse already forbids the combination, or
the code only exists for hand-built namespaces and fault injection); those call the handler or helper directly.
"""

import errno
import getpass
import io
import json
import runpy
import signal
import sys
import threading
import warnings
from argparse import Namespace
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import patch

import httpx
import pytest
from dbhelpers import create_db
from fake_server import FakeServer
from pykeepass import PyKeePass

from mattstash import MattStash
from mattstash.cli import exit_codes
from mattstash.cli.handlers.base import BaseHandler
from mattstash.cli.handlers.env import ServerSecretSource
from mattstash.cli.handlers.get import GetHandler
from mattstash.cli.handlers.put import PutHandler
from mattstash.cli.handlers.rotate import _sibling_databases
from mattstash.cli.inputs import InputError, _interactive, read_stdin_line, read_stdin_secret
from mattstash.cli.main import _signals_as_interrupt, main
from mattstash.core.bootstrap import DatabaseBootstrapper
from mattstash.utils.exceptions import DatabaseExistsError, MattStashError

KEY = "k3y-s3cret-AAAA"
URL = "http://localhost:8000"
MASTER = "test-master-pw"


class _Concrete(BaseHandler):
    """The smallest concrete handler, to reach the shared ``BaseHandler`` code."""

    def handle(self, args: Namespace) -> int:
        return super().handle(args)


class _Tty:
    """A stand-in for an interactive stdin."""

    def isatty(self) -> bool:
        return True


class _BrokenStdout:
    """A stdout whose ``write`` fails the way a full disk, a closed pipe or a narrow terminal encoding does."""

    def __init__(self, error: BaseException) -> None:
        self.error = error

    def write(self, text: str) -> int:
        raise self.error

    def flush(self) -> None:
        pass


@pytest.fixture()
def db(tmp_path: Path) -> Path:
    """A local database (with its sidecar) holding one simple secret."""
    return create_db(tmp_path / "cli.kdbx", [{"title": "alpha", "password": "alpha-pw"}])


@pytest.fixture()
def server(monkeypatch: pytest.MonkeyPatch) -> FakeServer:
    """A fake MattStash server, selected through the environment (server mode, API key from MATTSTASH_API_KEY)."""
    fake = FakeServer(api_key=KEY).install(monkeypatch)
    monkeypatch.setenv("MATTSTASH_SERVER_URL", URL)
    monkeypatch.setenv("MATTSTASH_API_KEY", KEY)
    return fake


@pytest.fixture()
def server_without_key(server: FakeServer, monkeypatch: pytest.MonkeyPatch) -> FakeServer:
    """Server mode selected, but no API key anywhere: every command must refuse before sending anything."""
    monkeypatch.delenv("MATTSTASH_API_KEY")
    return server


def fail_with_500(server: FakeServer) -> None:
    server.override = lambda request: httpx.Response(500, json={"detail": "internal secret detail"})


# ---------------------------------------------------------------------------
# handlers/base.py
# ---------------------------------------------------------------------------


def test_base_handle_is_abstract_and_its_default_body_does_nothing():
    with pytest.raises(TypeError):
        BaseHandler()
    assert _Concrete().handle(Namespace()) is None


def test_opt_does_not_mistake_a_boolean_for_a_number():
    args = Namespace(flagged=True, count=3, text="x")
    assert BaseHandler.opt(args, "flagged", int) is None  # bool is an int in Python, but never a "number" option
    assert BaseHandler.opt(args, "flagged", bool) is True
    assert BaseHandler.opt(args, "count", int) == 3
    assert BaseHandler.opt(args, "count", str) is None
    assert BaseHandler.opt(args, "absent", str) is None


def test_get_server_client_is_none_outside_server_mode():
    handler = _Concrete()
    assert handler.is_server_mode(Namespace()) is False
    assert handler.get_server_client(Namespace()) is None
    assert handler.get_server_client(Namespace(server_url=None)) is None


def test_an_unusable_server_url_is_reported_and_nothing_is_sent(
    server: FakeServer, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("MATTSTASH_SERVER_URL", "ftp://localhost:8000")
    assert main(["list"]) == exit_codes.ERROR
    assert "the server URL must look like http(s)://host[:port][/prefix]" in caplog.text
    assert KEY not in caplog.text
    assert server.requests == []


# ---------------------------------------------------------------------------
# handlers/config.py
# ---------------------------------------------------------------------------


def test_config_writes_an_example_file_to_the_requested_path(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    target = tmp_path / "out" / "mattstash.yml"
    assert main(["config", "--output", str(target)]) == exit_codes.OK
    assert "MattStash Configuration File" in target.read_text()
    out = capsys.readouterr().out
    assert f"Created example configuration at: {target}" in out
    assert "Configuration priority" in out


def test_config_defaults_to_the_users_config_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    assert main(["config"]) == exit_codes.OK
    assert (tmp_path / ".config" / "mattstash" / "config.yml").is_file()


def test_config_expands_a_tilde_in_the_output_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    assert main(["config", "--output", "~/home-relative.yml"]) == exit_codes.OK
    assert (tmp_path / "home-relative.yml").is_file()


@pytest.mark.parametrize("answer", ["", "n", "no", "maybe"])
def test_config_keeps_an_existing_file_unless_the_answer_is_yes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], answer: str
):
    target = tmp_path / "existing.yml"
    target.write_text("mine: true\n")
    monkeypatch.setattr("builtins.input", lambda prompt="": answer)
    assert main(["config", "--output", str(target)]) == exit_codes.OK
    assert target.read_text() == "mine: true\n"
    assert "Cancelled." in capsys.readouterr().out


@pytest.mark.parametrize("answer", ["y", "YES", "Yes"])
def test_config_overwrites_an_existing_file_when_confirmed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: str
):
    target = tmp_path / "existing.yml"
    target.write_text("mine: true\n")
    prompts: List[str] = []

    def reply(prompt: str = "") -> str:
        prompts.append(prompt)
        return answer

    monkeypatch.setattr("builtins.input", reply)
    assert main(["config", "--output", str(target)]) == exit_codes.OK
    assert "MattStash Configuration File" in target.read_text()
    assert prompts == [f"File {target} already exists. Overwrite? [y/N]: "]


def test_config_explains_how_to_get_yaml_support_when_it_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    monkeypatch.setitem(sys.modules, "mattstash.utils.config_loader", None)  # makes the import raise ImportError
    target = tmp_path / "never.yml"
    assert main(["config", "--output", str(target)]) == exit_codes.ERROR
    assert "requires PyYAML" in capsys.readouterr().out
    assert not target.exists()


# ---------------------------------------------------------------------------
# handlers/db_url.py, delete.py, s3_test.py
# ---------------------------------------------------------------------------


def test_db_url_reports_a_missing_database_with_its_own_exit_code(missing_db: Path, caplog: pytest.LogCaptureFixture):
    assert main(["--db", str(missing_db), "--password", MASTER, "db-url", "pg"]) == exit_codes.DB_NOT_FOUND
    assert f"Database file not found: {missing_db}" in caplog.text


def test_db_url_with_a_wrong_database_password_is_an_access_error(db: Path):
    assert main(["--db", str(db), "--password", "wrong-password", "db-url", "pg"]) == exit_codes.DB_ACCESS


def test_db_url_server_mode_needs_an_api_key(server_without_key: FakeServer, caplog: pytest.LogCaptureFixture):
    assert main(["db-url", "pg"]) == exit_codes.ERROR
    assert "API key required for server mode" in caplog.text
    assert server_without_key.requests == []


def test_db_url_server_failure_is_reported_without_the_response_detail(
    server: FakeServer, caplog: pytest.LogCaptureFixture
):
    fail_with_500(server)
    assert main(["db-url", "pg"]) == exit_codes.DB_URL_FAILED
    assert "Server error" in caplog.text
    assert "internal secret detail" not in caplog.text


def test_delete_server_mode_needs_an_api_key(server_without_key: FakeServer):
    assert main(["delete", "anything"]) == exit_codes.ERROR
    assert server_without_key.requests == []


def test_s3_test_reports_a_missing_database_with_its_own_exit_code(missing_db: Path):
    assert main(["--db", str(missing_db), "--password", MASTER, "s3-test", "bucket-creds"]) == exit_codes.DB_NOT_FOUND


# ---------------------------------------------------------------------------
# handlers/env.py
# ---------------------------------------------------------------------------


class _ListingClient:
    def __init__(self, names: List[Any]) -> None:
        self.names = names

    def list(self, show_password: bool = False, prefix: Optional[str] = None) -> List[Dict[str, Any]]:
        return [{"name": name} for name in self.names] + [{"no-name-at-all": 1}]


def test_server_listing_entries_without_a_text_name_are_ignored():
    source = ServerSecretSource(_ListingClient([5, None, ["a"], "app.key", "app.key@0000000002", "other"]))
    assert source.titles("app.") == ["app.key", "app.key"]


def test_env_refuses_a_value_the_docker_env_format_cannot_carry(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
):
    db = create_db(tmp_path / "multi.kdbx", [{"title": "app.cert", "password": "line-one\nline-two"}])
    rc = main(["--db", str(db), "env", "--map", "CERT=app.cert", "--format", "docker-env"])
    assert rc == exit_codes.ERROR
    assert "cannot be written in docker --env-file format" in caplog.text
    captured = capsys.readouterr()
    assert "line-one" not in captured.out + captured.err + caplog.text, "a secret value is never part of the message"


@pytest.mark.parametrize(
    "failure",
    [
        OSError(errno.ENOSPC, "No space left on device"),
        BrokenPipeError(errno.EPIPE, "Broken pipe"),
        UnicodeEncodeError("ascii", "café", 3, 4, "ordinal not in range(128)"),
    ],
    ids=["disk-full", "closed-pipe", "unencodable"],
)
def test_env_unwritable_stdout_is_an_error_not_a_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, failure: BaseException
):
    db = create_db(tmp_path / "e.kdbx", [{"title": "app.token", "password": "s3cret-value"}])
    monkeypatch.setattr(sys, "stdout", _BrokenStdout(failure))
    assert main(["--db", str(db), "env", "--map", "T=app.token"]) == exit_codes.ERROR
    assert f"cannot write the environment to stdout: {type(failure).__name__}" in caplog.text
    assert "s3cret-value" not in caplog.text


# ---------------------------------------------------------------------------
# handlers/get.py
# ---------------------------------------------------------------------------


def test_get_handler_refuses_raw_together_with_json_when_called_directly(caplog: pytest.LogCaptureFixture):
    # argparse's mutually exclusive group stops this on the command line; the handler guards embedders as well
    args = Namespace(title="alpha", raw=True, json=True, field=None)
    assert GetHandler().handle(args) == exit_codes.ERROR
    assert "--raw and --json are mutually exclusive" in caplog.text


def test_get_raw_server_mode_needs_an_api_key(server_without_key: FakeServer):
    assert main(["get", "alpha", "--raw"]) == exit_codes.ERROR
    assert server_without_key.requests == []


def test_get_server_mode_needs_an_api_key(server_without_key: FakeServer):
    assert main(["get", "alpha"]) == exit_codes.ERROR
    assert server_without_key.requests == []


def test_get_server_mode_reports_an_unknown_secret_with_exit_status_2(
    server: FakeServer, caplog: pytest.LogCaptureFixture
):
    assert main(["get", "nobody"]) == exit_codes.NOT_FOUND
    assert "not found: nobody" in caplog.text


def test_get_server_mode_json_is_the_servers_answer(server: FakeServer, capsys: pytest.CaptureFixture[str]):
    server.add("svc", "pw-1", username="alice")
    assert main(["get", "svc", "--json", "--show-password"]) == exit_codes.OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["name"] == "svc" and payload["password"] == "pw-1" and payload["username"] == "alice"


def test_get_server_mode_text_shows_every_populated_field(server: FakeServer, capsys: pytest.CaptureFixture[str]):
    server.add("svc", "pw-1", username="alice", url="db.example:5432", notes="first line\nsecond line")
    assert main(["get", "svc"]) == exit_codes.OK
    assert capsys.readouterr().out.splitlines() == [
        "svc",
        "  username: alice",
        "  password: *****",
        "  url:      db.example:5432",
        "  notes/comments:",
        "    first line",
        "    second line",
    ]
    assert main(["get", "svc", "--show-password"]) == exit_codes.OK
    assert "  password: pw-1" in capsys.readouterr().out


def test_get_server_mode_omits_the_fields_the_credential_does_not_have(
    server: FakeServer, capsys: pytest.CaptureFixture[str]
):
    server.add("bare", None)
    assert main(["get", "bare", "--show-password"]) == exit_codes.OK
    assert capsys.readouterr().out == "bare\n"


# ---------------------------------------------------------------------------
# handlers/list.py (list and keys)
# ---------------------------------------------------------------------------


def test_list_server_mode_prints_one_line_per_credential(server: FakeServer, capsys: pytest.CaptureFixture[str]):
    server.add("alpha", "alpha-pw", username="u1", url="http://a", notes="  first note\nsecond line")
    server.add("beta", "beta-pw", username="u2", url="http://b", notes=" \n ")  # whitespace only: no snippet
    server.add("gamma", "gamma-pw", username="u3", url="http://c")
    assert main(["list"]) == exit_codes.OK
    assert capsys.readouterr().out.splitlines() == [
        "- alpha user='u1' url='http://a' pwd='*****' notes='first note'",
        "- beta user='u2' url='http://b' pwd='*****'",
        "- gamma user='u3' url='http://c' pwd='*****'",
    ]
    assert main(["list", "--show-password"]) == exit_codes.OK
    assert "pwd='alpha-pw'" in capsys.readouterr().out


def test_list_server_mode_json_is_the_servers_listing(server: FakeServer, capsys: pytest.CaptureFixture[str]):
    server.add("alpha", "alpha-pw")
    server.add("beta", "beta-pw")
    assert main(["list", "--json"]) == exit_codes.OK
    assert [c["name"] for c in json.loads(capsys.readouterr().out)] == ["alpha", "beta"]


def test_list_server_mode_fills_in_what_the_server_left_out(server: FakeServer, capsys: pytest.CaptureFixture[str]):
    server.override = lambda request: httpx.Response(200, json={"credentials": [{}], "count": 1})
    assert main(["list"]) == exit_codes.OK
    assert capsys.readouterr().out == "- unknown user='' url='' pwd='*****'\n"


def test_list_server_mode_failure_is_an_error(server: FakeServer, caplog: pytest.LogCaptureFixture):
    fail_with_500(server)
    assert main(["list"]) == exit_codes.ERROR
    assert "Server error" in caplog.text
    assert "internal secret detail" not in caplog.text


def test_list_server_mode_needs_an_api_key(server_without_key: FakeServer):
    assert main(["list"]) == exit_codes.ERROR
    assert server_without_key.requests == []


def test_keys_server_mode_prints_the_titles(server: FakeServer, capsys: pytest.CaptureFixture[str]):
    server.add("alpha", "alpha-pw")
    server.add("beta", "beta-pw")
    assert main(["keys"]) == exit_codes.OK
    assert capsys.readouterr().out == "alpha\nbeta\n"
    assert server.requests[-1].url.params["show_password"] == "false", "keys never asks the server for passwords"


def test_keys_server_mode_json(server: FakeServer, capsys: pytest.CaptureFixture[str]):
    server.add("alpha", "alpha-pw")
    assert main(["keys", "--json"]) == exit_codes.OK
    assert json.loads(capsys.readouterr().out) == ["alpha"]


def test_keys_server_mode_failure_is_an_error(server: FakeServer, caplog: pytest.LogCaptureFixture):
    fail_with_500(server)
    assert main(["keys"]) == exit_codes.ERROR
    assert "Server error" in caplog.text


def test_keys_server_mode_needs_an_api_key(server_without_key: FakeServer):
    assert main(["keys"]) == exit_codes.ERROR
    assert server_without_key.requests == []


# ---------------------------------------------------------------------------
# handlers/put.py
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode", [["--value", "v"], ["--fields"]], ids=["simple", "fields"])
def test_put_reports_a_store_that_returned_nothing(db: Path, caplog: pytest.LogCaptureFixture, mode: List[str]):
    with patch("mattstash.cli.handlers.put.put", return_value=None):
        assert main(["--db", str(db), "put", "x", *mode]) == exit_codes.ERROR
    assert "Failed to store credential" in caplog.text


def test_put_simple_value_prints_ok_when_the_store_returns_a_credential_object(
    db: Path, capsys: pytest.CaptureFixture[str]
):
    with patch("mattstash.cli.handlers.put.put", return_value=object()):
        assert main(["--db", str(db), "put", "x", "--value", "v"]) == exit_codes.OK
    assert capsys.readouterr().out == "x: OK\n"


def test_put_handler_refuses_value_together_with_fields_when_called_directly(caplog: pytest.LogCaptureFixture):
    # argparse's mutually exclusive group stops this on the command line; the handler guards embedders as well
    assert PutHandler().handle(Namespace(title="x", value="v", fields=True)) == exit_codes.ERROR
    assert "--value/--value-file and --fields are mutually exclusive" in caplog.text


def test_put_server_mode_needs_an_api_key(server_without_key: FakeServer):
    assert main(["put", "svc", "--value", "v"]) == exit_codes.ERROR
    assert server_without_key.requests == []


def test_put_server_mode_forwards_every_field_option(server: FakeServer, capsys: pytest.CaptureFixture[str]):
    argv = ["put", "svc", "--username", "alice", "--entry-password", "pw-1", "--url", "db.example:5432"]
    argv += ["--notes", "the notes", "--comment", "the comment", "--tag", "prod", "--tag", "db", "--json"]
    assert main(argv) == exit_codes.OK
    assert json.loads(capsys.readouterr().out)["created"] is True
    body = json.loads(server.requests[-1].content)
    assert body == {
        "username": "alice",
        "password": "pw-1",
        "url": "db.example:5432",
        "notes": "the notes",  # --notes wins over --comment, as it does for a local database
        "tags": ["prod", "db"],
    }
    assert server.store["svc"][1]["password"] == "pw-1"


def test_put_server_mode_comment_is_the_notes(server: FakeServer, capsys: pytest.CaptureFixture[str]):
    assert main(["put", "svc", "--value", "v", "--comment", "only a comment"]) == exit_codes.OK
    assert capsys.readouterr().out == "svc: OK\n"
    assert server.store["svc"][1]["notes"] == "only a comment"


def test_put_server_mode_failure_is_an_error(server: FakeServer, caplog: pytest.LogCaptureFixture):
    server.allow_writes = False
    assert main(["put", "svc", "--value", "v"]) == exit_codes.ERROR
    assert "Server error" in caplog.text
    assert "secret-looking detail" not in caplog.text


# ---------------------------------------------------------------------------
# handlers/rotate.py
# ---------------------------------------------------------------------------


def test_sibling_databases_of_a_directory_that_cannot_be_listed_is_empty(tmp_path: Path):
    assert _sibling_databases(str(tmp_path / "no-such-directory" / "main.kdbx")) == []


def test_sibling_databases_lists_other_kdbx_files_only(tmp_path: Path):
    for name in ("main.kdbx", "other.kdbx", "notes.txt"):
        (tmp_path / name).write_text("")
    assert _sibling_databases(str(tmp_path / "main.kdbx")) == ["other.kdbx"]


# ---------------------------------------------------------------------------
# handlers/setup.py
# ---------------------------------------------------------------------------


def test_setup_reports_a_database_that_appeared_while_it_was_being_created(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
):
    target = tmp_path / "raced.kdbx"
    with patch.object(DatabaseBootstrapper, "create", side_effect=DatabaseExistsError("someone else was faster")):
        assert main(["--db", str(target), "setup", "--generate"]) == exit_codes.WOULD_OVERWRITE
    assert "someone else was faster" in caplog.text


def test_setup_force_confirmation_that_hits_end_of_input_changes_nothing(db: Path, monkeypatch: pytest.MonkeyPatch):
    def end_of_input(prompt: str = "") -> str:
        raise EOFError

    monkeypatch.setattr(sys, "stdin", _Tty())
    monkeypatch.setattr("builtins.input", end_of_input)
    assert main(["--db", str(db), "setup", "--force", "--sidecar"]) == exit_codes.WOULD_OVERWRITE
    assert MattStash(str(db)).get("alpha") is not None, "the existing database was not replaced"


def test_setup_with_an_empty_password_file_creates_nothing(tmp_path: Path, caplog: pytest.LogCaptureFixture):
    empty = tmp_path / "pw.txt"
    empty.write_text("\n")
    target = tmp_path / "fresh.kdbx"
    assert main(["--db", str(target), "setup", "--password-file", str(empty)]) == exit_codes.ERROR
    assert f"password file {empty} is empty" in caplog.text
    assert not target.exists()


def test_setup_warns_about_a_password_given_on_the_command_line(tmp_path: Path, caplog: pytest.LogCaptureFixture):
    target = tmp_path / "cli-pw.kdbx"
    assert main(["--db", str(target), "--password", "pw-from-argv", "setup"]) == exit_codes.OK
    assert "visible to other users" in caplog.text
    assert "pw-from-argv" not in caplog.text
    PyKeePass(str(target), password="pw-from-argv")  # the database really uses it


def test_setup_does_not_warn_about_a_password_that_came_from_a_file(tmp_path: Path, caplog: pytest.LogCaptureFixture):
    pw_file = tmp_path / "pw.txt"
    pw_file.write_text("pw-from-file\n")
    target = tmp_path / "file-pw.kdbx"
    assert main(["--db", str(target), "--db-password-file", str(pw_file), "setup"]) == exit_codes.OK
    assert "visible to other users" not in caplog.text
    PyKeePass(str(target), password="pw-from-file")


def test_setup_prompt_rejects_an_empty_password(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
):
    monkeypatch.setattr(sys, "stdin", _Tty())
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": "")
    target = tmp_path / "prompted.kdbx"
    assert main(["--db", str(target), "setup"]) == exit_codes.ERROR
    assert "Password cannot be empty" in caplog.text
    assert "No master password source" in caplog.text
    assert not target.exists()


# ---------------------------------------------------------------------------
# handlers/versions.py
# ---------------------------------------------------------------------------


def test_versions_server_mode_lists_the_version_labels(server: FakeServer, capsys: pytest.CaptureFixture[str]):
    server.add("svc", "one")
    server.add("svc", "two")
    assert main(["versions", "svc"]) == exit_codes.OK
    assert capsys.readouterr().out == "0000000001\n0000000002\n"
    assert main(["versions", "svc", "--json"]) == exit_codes.OK
    assert json.loads(capsys.readouterr().out) == ["0000000001", "0000000002"]


def test_versions_server_mode_reports_an_unknown_secret(server: FakeServer, caplog: pytest.LogCaptureFixture):
    assert main(["versions", "nobody"]) == exit_codes.NOT_FOUND
    assert "not found: nobody" in caplog.text


def test_versions_server_mode_failure_is_an_error(server: FakeServer, caplog: pytest.LogCaptureFixture):
    fail_with_500(server)
    assert main(["versions", "svc"]) == exit_codes.ERROR
    assert "Server error" in caplog.text


def test_versions_server_mode_needs_an_api_key(server_without_key: FakeServer):
    assert main(["versions", "svc"]) == exit_codes.ERROR
    assert server_without_key.requests == []


# ---------------------------------------------------------------------------
# main.py
# ---------------------------------------------------------------------------


def test_server_subcommand_explains_how_to_run_the_server(capsys: pytest.CaptureFixture[str]):
    assert main(["server"]) == exit_codes.OK
    out = capsys.readouterr().out
    assert "separate Docker container" in out
    assert "MATTSTASH_SERVER_URL" in out and "KDBX_PASSWORD_FILE" in out


def test_a_library_error_from_a_handler_is_a_message_not_a_traceback(capsys: pytest.CaptureFixture[str]):
    with patch("mattstash.cli.handlers.list.KeysHandler.handle", side_effect=MattStashError("something specific")):
        assert main(["keys"]) == exit_codes.ERROR
    assert capsys.readouterr().err == "mattstash: something specific\n"


def test_a_secret_input_error_from_a_handler_is_a_message_not_a_traceback(capsys: pytest.CaptureFixture[str]):
    with patch("mattstash.cli.handlers.list.KeysHandler.handle", side_effect=InputError("bad input")):
        assert main(["keys"]) == exit_codes.ERROR
    assert capsys.readouterr().err == "mattstash: bad input\n"


def test_the_command_runs_unchanged_off_the_main_thread(db: Path):
    # signal handlers can only be installed from the main thread; elsewhere (an embedding application) they are skipped
    before = signal.getsignal(signal.SIGTERM)
    seen: List[Any] = []
    results: List[int] = []

    def keys(self: Any, args: Namespace) -> int:
        seen.append(signal.getsignal(signal.SIGTERM))
        return 0

    with patch("mattstash.cli.handlers.list.KeysHandler.handle", keys):
        worker = threading.Thread(target=lambda: results.append(main(["--db", str(db), "keys"])))
        worker.start()
        worker.join(30)
    assert results == [exit_codes.OK]
    assert seen == [before], "SIGTERM handling is left alone outside the main thread"
    assert signal.getsignal(signal.SIGTERM) == before


def test_signals_the_platform_does_not_have_are_skipped(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delattr(signal, "SIGHUP", raising=False)  # e.g. Windows
    before = signal.getsignal(signal.SIGTERM)
    with _signals_as_interrupt():
        installed = signal.getsignal(signal.SIGTERM)
        with pytest.raises(KeyboardInterrupt):
            installed(signal.SIGTERM, None)
    assert signal.getsignal(signal.SIGTERM) == before


def test_python_dash_m_runs_main_and_exits_with_its_status(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    monkeypatch.setattr(sys, "argv", ["mattstash", "server"])
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)  # "found in sys.modules": the test run imported it already
        with pytest.raises(SystemExit) as exit_info:
            runpy.run_module("mattstash.cli.main", run_name="__main__")
    assert exit_info.value.code == exit_codes.OK
    assert "separate Docker container" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# inputs.py
# ---------------------------------------------------------------------------


class _TextStdin:
    """Text-only stdin replacement: no ``buffer`` and whatever ``isatty`` does."""

    def __init__(self, text: str, isatty_error: Optional[BaseException] = None) -> None:
        self.text = text
        self.isatty_error = isatty_error

    def isatty(self) -> bool:
        if self.isatty_error is not None:
            raise self.isatty_error
        return False

    def read(self, size: int = -1) -> str:
        return self.text

    def readline(self, size: int = -1) -> str:
        return self.text.splitlines(keepends=True)[0]


class _NoIsattyStdin:
    def read(self, size: int = -1) -> str:
        return "from-a-pipe\n"


def test_a_stdin_that_cannot_tell_whether_it_is_a_terminal_counts_as_not_interactive(
    monkeypatch: pytest.MonkeyPatch,
):
    assert _interactive(object()) is False  # no isatty at all
    assert _interactive(_TextStdin("", isatty_error=ValueError("I/O operation on closed file"))) is False
    assert _interactive(_Tty()) is True
    monkeypatch.setattr(sys, "stdin", _NoIsattyStdin())
    assert read_stdin_secret("--value -") == "from-a-pipe"
    monkeypatch.setattr(sys, "stdin", _TextStdin("from-a-closed-tty\n", isatty_error=ValueError("closed")))
    assert read_stdin_secret("--value -") == "from-a-closed-tty"


def test_an_empty_hidden_prompt_is_not_a_secret(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(sys, "stdin", _Tty())
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": "")
    with pytest.raises(InputError, match=r"--value -: no data received on stdin \(empty value\)"):
        read_stdin_secret("--value -")
    with pytest.raises(InputError, match=r"--new-password-stdin: no password received on stdin \(empty line\)"):
        read_stdin_line("--new-password-stdin")


def test_a_hidden_prompt_answer_is_used_as_typed(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(sys, "stdin", _Tty())
    prompts: List[str] = []

    def typed(prompt: str = "") -> str:
        prompts.append(prompt)
        return "typed secret"

    monkeypatch.setattr(getpass, "getpass", typed)
    assert read_stdin_secret("--value -") == "typed secret"
    assert read_stdin_line("--new-password-stdin") == "typed secret"
    assert prompts == ["--value - (input is not shown): ", "--new-password-stdin (input is not shown): "]


def test_stdin_text_replacement_is_read_like_a_pipe(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(sys, "stdin", io.StringIO("first line\nsecond line\n"))
    assert read_stdin_line("--new-password-stdin") == "first line"
