"""Final-review fixes in the CLI: malformed token ids and the server's 'saved but not active' warning."""

from pathlib import Path

import pytest
from admin_helpers import TOKEN_RE, FakeAdminServer, Runner

from mattstash.authz import load_policy
from mattstash.cli import exit_codes

URL = "http://localhost:8000"
ADMIN_KEY = "mst_" + "a2b3c4d5e6f7" + "_" + "Zk3-_rTQ9s7XyV1mN0pLwE5uHdJ8aB2cF4gIoKq6tYe"
ADMIN_ARGS = ["--server-url", URL, "--api-key", ADMIN_KEY, "admin"]
WARNING = "Saved to the policy file but NOT active: the previous policy is still in force."
MALFORMED = "malformed token id (expected the 12-character id, not the token itself)"
PASTED = "mst_abcdefghijkl_" + "Zk3rTQ9s7XyV1mN0pLwE5uHdJ8aB2cF4gIoKq6tYe0"


@pytest.fixture()
def run(capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture) -> Runner:
    return Runner(capsys, caplog)


@pytest.fixture()
def policy(tmp_path: Path) -> Path:
    return tmp_path / "policy.json"


@pytest.fixture()
def server(policy: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeAdminServer:
    fake = FakeAdminServer(policy, ADMIN_KEY, log_file=tmp_path / "access.jsonl")
    fake.install(monkeypatch)
    return fake


# ---- malformed token ids -----------------------------------------------------


@pytest.mark.parametrize("verb", ["revoke", "rotate"])
@pytest.mark.parametrize("bad", [PASTED, "short", "ABCDEFGHIJKL", "abcdefghijk1", ""])
def test_a_malformed_token_id_is_refused_in_server_mode_before_anything_is_sent(
    run: Runner, server: FakeAdminServer, verb: str, bad: str
):
    result = run(*ADMIN_ARGS, "token", verb, "bot", bad)
    assert result.code == exit_codes.ERROR
    assert MALFORMED in result.err
    assert bad not in result.err.replace(MALFORMED, "") or bad == ""
    assert PASTED.split("_")[2] not in result.out + result.err
    assert server.requests == []


@pytest.mark.parametrize("verb", ["revoke", "rotate"])
def test_a_malformed_token_id_is_refused_in_local_mode_and_nothing_is_changed(run: Runner, policy: Path, verb: str):
    run("admin", "--policy-file", str(policy), "principal", "add", "bot", "--kind", "agent")
    run("admin", "--policy-file", str(policy), "token", "issue", "bot")
    before = policy.read_text()
    result = run("admin", "--policy-file", str(policy), "token", verb, "bot", PASTED)
    assert result.code == exit_codes.ERROR and MALFORMED in result.err
    assert PASTED not in result.err and PASTED.split("_")[2] not in result.err + result.out
    assert policy.read_text() == before


# ---- warning: saved but not active ---------------------------------------------


MUTATIONS = [
    ("principal add bot --kind agent", "created principal bot"),
    ("principal disable ansible", "ansible: disabled"),
    ("principal update ansible --description x", "ansible: admin=no"),
    ("principal remove ansible --yes", "removed principal ansible"),
    ("grant add ansible --key x", "g_"),
    ("token issue ansible", "mst_"),
]


def prepare(run: Runner, server: FakeAdminServer) -> None:
    for argv in ("principal add ansible --kind runner", "principal add boss --kind human-device --admin"):
        assert run(*ADMIN_ARGS, *argv.split()).code == 0


@pytest.mark.parametrize(("argv", "expected"), MUTATIONS)
def test_every_mutation_with_a_warning_exits_non_zero_and_shows_the_warning(
    run: Runner, server: FakeAdminServer, argv: str, expected: str
):
    prepare(run, server)
    server.warning = WARNING
    result = run(*ADMIN_ARGS, *argv.split())
    assert result.code == exit_codes.ERROR
    assert f"warning: {WARNING}" in result.err
    assert expected in result.out  # the work is reported; the exit status says it is not active


def test_grant_remove_and_token_revoke_with_a_warning(run: Runner, server: FakeAdminServer, policy: Path):
    prepare(run, server)
    grant_id = run(*ADMIN_ARGS, "grant", "add", "ansible", "--key", "x").out.strip()
    token = run(*ADMIN_ARGS, "token", "issue", "ansible").out.strip()
    server.warning = WARNING
    revoked = run(*ADMIN_ARGS, "token", "revoke", "ansible", token.split("_")[1])
    removed = run(*ADMIN_ARGS, "grant", "remove", grant_id)
    for result in (revoked, removed):
        assert result.code == exit_codes.ERROR and f"warning: {WARNING}" in result.err


def test_without_a_warning_nothing_changes(run: Runner, server: FakeAdminServer):
    prepare(run, server)
    result = run(*ADMIN_ARGS, "token", "issue", "ansible")
    assert result.code == 0 and "warning" not in result.err


def test_a_warning_is_sanitised(run: Runner, server: FakeAdminServer):
    prepare(run, server)
    server.warning = "bad\x1b[31m text " + "x" * 1000
    result = run(*ADMIN_ARGS, "principal", "disable", "ansible")
    assert result.code == exit_codes.ERROR
    assert "\x1b" not in result.err and len(result.err) < 500


def test_a_token_with_a_warning_is_still_printed_on_stdout(run: Runner, server: FakeAdminServer, policy: Path):
    prepare(run, server)
    server.warning = WARNING
    result = run(*ADMIN_ARGS, "token", "issue", "ansible")
    assert result.code == exit_codes.ERROR
    assert TOKEN_RE.fullmatch(result.out.strip()) and WARNING in result.err
    assert result.out.strip().split("_")[1] in [t.id for t in load_policy(policy).principal("ansible").tokens]  # type: ignore[union-attr]


def test_rotate_with_a_warning_does_not_claim_the_old_token_is_revoked(run: Runner, server: FakeAdminServer):
    prepare(run, server)
    old_id = run(*ADMIN_ARGS, "token", "issue", "ansible").out.strip().split("_")[1]
    server.warning = WARNING
    result = run(*ADMIN_ARGS, "token", "rotate", "ansible", old_id)
    assert result.code == exit_codes.ERROR
    assert TOKEN_RE.fullmatch(result.out.strip())
    assert "is revoked" not in result.err and "NOT known to be revoked" in result.err
    assert f"warning: {WARNING}" in result.err


def test_a_non_text_warning_still_fails(run: Runner, server: FakeAdminServer):
    prepare(run, server)
    server.warning = 5  # type: ignore[assignment]
    result = run(*ADMIN_ARGS, "principal", "disable", "ansible")
    assert result.code == exit_codes.ERROR and "saved but is not active" in result.err
