"""Review round 1 for ``mattstash admin``: the same behaviour in local and server mode (real client, real handler,
a fake of the admin API over a real policy file)."""

import errno
import json
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, NamedTuple

import httpx
import pytest
from admin_helpers import TOKEN_RE, FakeAdminServer, Runner

from mattstash.authz import load_policy
from mattstash.cli.handlers import admin as admin_module
from mattstash.cli.handlers.admin import AdminHandler, _clean

URL = "http://localhost:8000"
ADMIN_KEY = "mst_" + "a2b3c4d5e6f7" + "_" + "Zk3-_rTQ9s7XyV1mN0pLwE5uHdJ8aB2cF4gIoKq6tYe"


class Mode(NamedTuple):
    name: str
    argv: list[str]
    policy: Path
    log: Path
    requests: Callable[[], int]
    server: "FakeAdminServer | None"


@pytest.fixture()
def run(capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture) -> Runner:
    return Runner(capsys, caplog)


@pytest.fixture(params=["local", "server"])
def mode(request: pytest.FixtureRequest, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Mode:
    """The admin command prefix for each mode, over one policy file and access log."""
    policy, log = tmp_path / "policy.json", tmp_path / "access.jsonl"
    if request.param == "local":
        monkeypatch.setenv("MATTSTASH_ACCESS_LOG_FILE", str(log))
        argv = ["admin", "--policy-file", str(policy)]
        return Mode("local", argv, policy, log, lambda: 0, None)
    fake = FakeAdminServer(policy, ADMIN_KEY, log_file=log)
    fake.install(monkeypatch)
    argv = ["--server-url", URL, "--api-key", ADMIN_KEY, "admin"]
    return Mode("server", argv, policy, log, lambda: len(fake.requests), fake)


def seed(run: Runner, mode: Mode) -> None:
    """A human-device admin (with a long-lived token already in the file) and an agent."""
    if mode.server is None:
        assert run(*mode.argv, "principal", "add", "matt", "--kind", "human-device", "--admin").code == 0
        assert run(*mode.argv, "token", "issue", "matt").code == 0
    assert run(*mode.argv, "principal", "add", "bot", "--kind", "agent").code == 0


def server_seed(run: Runner, mode: Mode) -> None:
    """The fake server needs principals to exist; its own admin check is the API key, so only the agent matters."""
    assert run(*mode.argv, "principal", "add", "matt", "--kind", "human-device", "--admin").code == 0
    assert run(*mode.argv, "principal", "add", "bot", "--kind", "agent").code == 0


def prepare(run: Runner, mode: Mode) -> None:
    if mode.server is None:
        seed(run, mode)
    else:
        server_seed(run, mode)
        # a long-lived admin token so that lockout rules never interfere with what the tests check
        assert run(*mode.argv, "token", "issue", "matt").code == 0


# ---- L1: out-of-range values are errors, not tracebacks ----


@pytest.mark.parametrize(
    "tail",
    [
        ["token", "issue", "bot", "--expires", "999999w"],
        ["token", "rotate", "bot", "TOKENID", "--expires", "999999w"],
        ["grant", "add", "bot", "--key", "a.*", "--expires", "999999w"],
        ["token", "issue", "bot", "--expires", "9999-12-31T23:59:59-05:00"],
        ["log", "--since", "999999w"],
        ["log", "--since", "0001-01-01T00:00:00+05:00"],
    ],
)
def test_out_of_range_dates_are_clean_errors(run: Runner, mode: Mode, tail: list[str]) -> None:
    prepare(run, mode)
    first = run(*mode.argv, "token", "issue", "bot").out.strip()
    tail = [first.split("_")[1] if part == "TOKENID" else part for part in tail]
    result = run(*mode.argv, *tail)
    assert result.code == 1, result
    assert "range of supported dates" in result.err
    assert "Traceback" not in result.err and "OverflowError" not in result.err


def test_an_expiry_in_the_past_is_refused(run: Runner, mode: Mode) -> None:
    prepare(run, mode)
    result = run(*mode.argv, "token", "issue", "bot", "--expires", "2020-01-01")
    assert result.code == 1 and "must be in the future" in result.err
    assert TOKEN_RE.search(result.out) is None
    assert load_policy(mode.policy).principal("bot").tokens == ()  # type: ignore[union-attr]


# ---- empty filters ----


@pytest.mark.parametrize(
    ("tail", "option"),
    [
        (["log", "--principal", ""], "principal"),
        (["log", "--principal", "  "], "principal"),
        (["log", "--since", ""], "since"),
        (["grant", "list", "--principal", ""], "principal"),
    ],
)
def test_empty_filters_are_rejected_in_both_modes(run: Runner, mode: Mode, tail: list[str], option: str) -> None:
    prepare(run, mode)
    before = mode.requests()
    result = run(*mode.argv, *tail)
    assert result.code == 1 and f"--{option} was given an empty value" in result.err
    assert mode.requests() == before  # nothing was sent


def test_the_client_sends_every_given_filter_even_if_falsy() -> None:
    from mattstash.cli.http_client import MattStashServerClient

    client = MattStashServerClient(URL, ADMIN_KEY)
    sent: list[dict[str, Any]] = []

    def capture(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        sent.append({"path": path, **kwargs})
        return {"records": [], "grants": [], "id": "aaaaaaaaaaaa"}

    client._make_request = capture  # type: ignore[method-assign]
    client.admin_access_log("", "", "", 5)
    client.admin_grants("")
    client.admin_token_issue("p", "", "")
    client.admin_token_rotate("p", "t", "", "", "")
    client.admin_grant_add("p", "k", None, ["read"], "", "")
    assert sent[0]["params"] == {"limit": 5, "principal": "", "decision": "", "since": ""}
    assert sent[1]["params"] == {"principal": ""}
    assert sent[2]["json_data"]["expires"] == ""
    assert sent[3]["json_data"] == {"description": "", "grace": "", "expires": ""}
    assert sent[4]["json_data"]["expires"] == ""


# ---- the token plaintext never reaches stderr ----


class BrokenStdout:
    encoding = "utf-8"

    def write(self, _text: str) -> int:
        raise OSError(errno.EPIPE, "Broken pipe")

    def flush(self) -> None:
        raise OSError(errno.EPIPE, "Broken pipe")  # pragma: no cover


@pytest.mark.parametrize("command", ["issue", "rotate"])
def test_a_failing_stdout_fails_the_command_and_names_the_id(
    run: Runner, mode: Mode, monkeypatch: pytest.MonkeyPatch, command: str
) -> None:
    prepare(run, mode)
    old = run(*mode.argv, "token", "issue", "bot").out.strip()
    known = {t.id for t in load_policy(mode.policy).principal("bot").tokens}  # type: ignore[union-attr]
    monkeypatch.setattr(sys, "stdout", BrokenStdout())
    tail = ["token", "issue", "bot"] if command == "issue" else ["token", "rotate", "bot", old.split("_")[1]]
    result = run(*mode.argv, *tail)
    created = {t.id for t in load_policy(mode.policy).principal("bot").tokens} - known  # type: ignore[union-attr]
    assert result.code == 1 and len(created) == 1
    (token_id,) = created
    assert token_id in result.err and "revoke it" in result.err and "stdout" in result.err
    assert TOKEN_RE.search(result.err) is None and TOKEN_RE.search(result.out) is None


def test_no_stdout_at_all_is_the_same_failure(run: Runner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    policy = tmp_path / "p.json"
    argv = ["admin", "--policy-file", str(policy)]
    assert run(*argv, "principal", "add", "bot", "--kind", "agent").code == 0
    monkeypatch.setattr(sys, "stdout", None)
    result = run(*argv, "token", "issue", "bot")
    assert result.code == 1 and "could not be written to stdout" in result.err
    assert TOKEN_RE.search(result.err) is None


# ---- malformed answers ----


@pytest.mark.parametrize(
    "answer",
    [
        {"id": "aaaaaaaaaaaa", "expires": None},
        {"id": "aaaaaaaaaaaa", "token": 5},
        {"id": "aaaaaaaaaaaa", "token": "not-a-token"},
        {"id": "aaaaaaaaaaaa", "token": "mst_aaaaaaaaaaaa_two words"},
    ],
)
@pytest.mark.parametrize("tail", [["token", "issue", "bot"], ["token", "rotate", "bot", "tid"]])
def test_a_token_without_a_usable_secret_reports_the_id(
    run: Runner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: dict[str, Any], tail: list[str]
) -> None:
    server = FakeAdminServer(tmp_path / "p.json", ADMIN_KEY)
    server.install(monkeypatch)
    server.forced = lambda _request: httpx.Response(201, json=answer)
    argv = ["--server-url", URL, "--api-key", ADMIN_KEY, "admin"]
    result = run(*argv, *tail)
    assert result.code == 1 and "aaaaaaaaaaaa" in result.err and "revoke it" in result.err
    assert result.out == ""
    output = tmp_path / "token-file"
    result = run(*argv, *tail, "--output-file", str(output))
    assert result.code == 1 and "aaaaaaaaaaaa" in result.err
    assert not output.exists()


def test_a_dubious_id_is_not_echoed(run: Runner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    server = FakeAdminServer(tmp_path / "p.json", ADMIN_KEY)
    server.install(monkeypatch)
    server.forced = lambda _request: httpx.Response(201, json={"id": "evil\nforged: line"})
    result = run("--server-url", URL, "--api-key", ADMIN_KEY, "admin", "token", "issue", "bot")
    assert result.code == 1 and "id unknown" in result.err and "forged" not in result.err


# ---- confirmation ----


class Tty:
    def __init__(self, answer: str) -> None:
        self.answer = answer

    def isatty(self) -> bool:
        return True

    def readline(self) -> str:
        return self.answer + "\n"


def test_the_confirmation_prompt_goes_to_stderr(run: Runner, mode: Mode, monkeypatch: pytest.MonkeyPatch) -> None:
    prepare(run, mode)
    monkeypatch.setattr(sys, "stdin", Tty("n"))
    result = run(*mode.argv, "principal", "remove", "bot")
    assert result.code == 1 and "[y/N]" in result.err and "[y/N]" not in result.out


def test_no_stdin_is_a_refusal_not_a_crash(run: Runner, mode: Mode, monkeypatch: pytest.MonkeyPatch) -> None:
    prepare(run, mode)
    monkeypatch.setattr(sys, "stdin", None)
    result = run(*mode.argv, "principal", "remove", "bot")
    assert result.code == 1 and "without --yes" in result.err
    assert load_policy(mode.policy).principal("bot") is not None


def test_confirm_survives_a_missing_or_failing_stdin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdin", None)
    assert AdminHandler._confirm("sure?") is False

    class Failing:
        def readline(self) -> str:
            raise OSError(errno.EIO, "I/O error")

    monkeypatch.setattr(sys, "stdin", Failing())
    assert AdminHandler._confirm("sure?") is False
    monkeypatch.setattr(sys, "stdin", Tty("Yes"))
    assert AdminHandler._confirm("sure?") is True


# ---- --grace ----


@pytest.mark.parametrize("grace", ["", "2027-01-01", "soon", "-5d", "1y", "2027-01-01T00:00:00Z", "7"])
def test_grace_takes_only_relative_durations(run: Runner, mode: Mode, grace: str) -> None:
    prepare(run, mode)
    token_id = run(*mode.argv, "token", "issue", "bot").out.strip().split("_")[1]
    before = mode.requests()
    result = run(*mode.argv, "token", "rotate", "bot", token_id, f"--grace={grace}")
    assert result.code == 1 and "as a duration (30m, 24h, 7d, 2w)" in result.err
    assert mode.requests() == before
    assert [t.id for t in load_policy(mode.policy).principal("bot").tokens] == [token_id]  # type: ignore[union-attr]


@pytest.mark.parametrize("grace", ["30m", "24h", "7d", "2w"])
def test_grace_durations_work(run: Runner, mode: Mode, grace: str) -> None:
    prepare(run, mode)
    token_id = run(*mode.argv, "token", "issue", "bot").out.strip().split("_")[1]
    result = run(*mode.argv, "token", "rotate", "bot", token_id, f"--grace={grace}")
    assert result.code == 0 and "stays valid until" in result.err
    assert len(load_policy(mode.policy).principal("bot").tokens) == 2  # type: ignore[union-attr]


# ---- log --json ----


def test_log_json_never_prints_a_hash(run: Runner, mode: Mode) -> None:
    prepare(run, mode)
    mode.log.write_text(
        json.dumps({"ts": "2026-10-18T12:00:00Z", "principal": "bot", "hash": "hmac-sha256:aa:bb", "n": {"hash": "x"}})
        + "\n"
    )
    result = run(*mode.argv, "log", "--json")
    assert result.code == 0 and "hmac-sha256" not in result.out and '"hash"' not in result.out
    assert json.loads(result.out) == {"ts": "2026-10-18T12:00:00Z", "principal": "bot", "n": {}}


# ---- the token file ----


def test_the_descriptor_is_closed_when_the_file_cannot_be_opened(
    run: Runner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    argv = ["admin", "--policy-file", str(tmp_path / "p.json")]
    assert run(*argv, "principal", "add", "bot", "--kind", "agent").code == 0
    seen: list[int] = []

    def refuse(descriptor: int) -> Any:
        seen.append(descriptor)
        raise OSError(errno.EMFILE, "Too many open files")

    monkeypatch.setattr(admin_module, "_open_token_file", refuse)
    target = tmp_path / "t"
    result = run(*argv, "token", "issue", "bot", "--output-file", str(target))
    stored = load_policy(tmp_path / "p.json").principal("bot").tokens[0]  # type: ignore[union-attr]
    assert result.code == 1 and stored.id in result.err and not target.exists()
    assert len(seen) == 1
    with pytest.raises(OSError):
        os.fstat(seen[0])  # closed: nothing leaked


def test_a_failing_write_reports_the_token_id_and_removes_the_file(
    run: Runner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    argv = ["admin", "--policy-file", str(tmp_path / "p.json")]
    assert run(*argv, "principal", "add", "bot", "--kind", "agent").code == 0

    class Full:
        def __enter__(self) -> "Full":
            return self

        def __exit__(self, *exc: object) -> None:
            os.close(self.descriptor)

        def __init__(self, descriptor: int) -> None:
            self.descriptor = descriptor

        def write(self, _text: str) -> int:
            raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(admin_module, "_open_token_file", Full)
    target = tmp_path / "t"
    result = run(*argv, "token", "issue", "bot", "--output-file", str(target))
    stored = load_policy(tmp_path / "p.json").principal("bot").tokens[0]  # type: ignore[union-attr]
    assert result.code == 1 and stored.id in result.err and "revoke it" in result.err
    assert "No space left" in result.err and not target.exists() and result.out == ""


# ---- output formatting ----


def test_clean_escapes_by_width() -> None:
    assert _clean("a\x00b") == "a\\x00b"
    assert _clean(chr(0x2028)) == "\\u2028"
    assert _clean("\U000e0001") == "\\U000e0001"
    assert _clean("é😀") == "é😀"  # printable text is kept
    assert _clean(None) == "-" and _clean(True) == "yes"


def test_show_indents_the_tables_under_their_headings(run: Runner, mode: Mode) -> None:
    prepare(run, mode)
    assert run(*mode.argv, "token", "issue", "bot").code == 0
    assert run(*mode.argv, "grant", "add", "bot", "--key", "a.*").code == 0
    lines = run(*mode.argv, "principal", "show", "bot").out.splitlines()
    for heading in ("tokens:", "grants:"):
        table = lines[lines.index(heading) + 1 :]
        assert table[0].startswith("  ID") and table[1].startswith("  ")
    assert run(*mode.argv, "principal", "show", "matt").out.count("(none)") == 1


def test_log_without_a_policy_file_reads_just_the_log(run: Runner, tmp_path: Path) -> None:
    log = tmp_path / "access.jsonl"
    log.write_text(json.dumps({"ts": "2026-10-18T12:00:00Z", "principal": "bot", "decision": "allowed"}) + "\n")
    result = run("admin", "log", "--log-file", str(log))
    assert result.code == 0 and "bot" in result.out
    assert run("admin", "log", "--log-file", str(log), "--since", "999999w").code == 1
    local = run("admin", "--policy-file", str(tmp_path / "none.json"), "log")
    assert local.code == 1 and "no access log file" in local.err


def test_rotating_the_sole_admin_token_into_a_short_lived_one_is_refused(run: Runner, mode: Mode) -> None:
    prepare(run, mode)
    (admin_token,) = load_policy(mode.policy).principal("matt").tokens  # type: ignore[union-attr]
    before = mode.policy.read_bytes()
    result = run(*mode.argv, "token", "rotate", "matt", admin_token.id, "--grace", "1h", "--expires", "1m")
    assert result.code == 1 and "within the hour" in result.err and TOKEN_RE.search(result.out) is None
    assert mode.policy.read_bytes() == before
    assert run(*mode.argv, "token", "rotate", "matt", admin_token.id, "--grace", "1h", "--expires", "2h").code == 0
