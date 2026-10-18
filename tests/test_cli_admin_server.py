"""``mattstash admin ...`` in server mode, against a fake of the admin API contract (real client, real handler)."""

import json
import stat
from pathlib import Path
from typing import Optional

import httpx
import pytest
from admin_helpers import TOKEN_RE, FakeAdminServer, Runner
from fake_server import FakeServer

from mattstash.authz import load_policy, verify_token_hash
from mattstash.cli import exit_codes
from mattstash.cli.http_client import MattStashServerClient
from mattstash.utils.exceptions import ServerError
from mattstash.utils.validation import api_key_problem

URL = "http://localhost:8000"
# an ordinary admin's token has the shape of every principal token
ADMIN_KEY = "mst_" + "a2b3c4d5e6f7" + "_" + "Zk3-_rTQ9s7XyV1mN0pLwE5uHdJ8aB2cF4gIoKq6tYe"
ADMIN_ARGS = ["--server-url", URL, "--api-key", ADMIN_KEY, "admin"]


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


def last(server: FakeAdminServer) -> httpx.Request:
    return server.requests[-1]


def path_of(request: httpx.Request) -> str:
    return request.url.raw_path.decode().split("?")[0]


# ---- the whole contract, endpoint by endpoint -----------------------------


def test_principal_endpoints(run: Runner, server: FakeAdminServer, policy: Path):
    created = run(*ADMIN_ARGS, "principal", "add", "matt", "--kind", "human-device", "--admin", "--description", "mac")
    assert created.code == 0 and "created principal matt (human-device)" in created.out
    request = last(server)
    assert (request.method, path_of(request)) == ("POST", "/api/v1/admin/principals")
    assert json.loads(request.content) == {"name": "matt", "kind": "human-device", "description": "mac", "admin": True}
    assert request.headers["X-API-Key"] == ADMIN_KEY
    assert load_policy(policy).principal("matt") is not None

    assert run(*ADMIN_ARGS, "principal", "add", "bot", "--kind", "agent").code == 0
    assert json.loads(last(server).content)["description"] == ""

    listed = json.loads(run(*ADMIN_ARGS, "principal", "list", "--json").out)
    assert (last(server).method, path_of(last(server))) == ("GET", "/api/v1/admin/principals")
    assert [p["name"] for p in listed] == ["matt", "bot"]
    assert "NAME" in run(*ADMIN_ARGS, "principal", "list").out

    shown = json.loads(run(*ADMIN_ARGS, "principal", "show", "bot", "--json").out)
    assert path_of(last(server)) == "/api/v1/admin/principals/bot" and shown["grants"] == []
    assert "name:        bot" in run(*ADMIN_ARGS, "principal", "show", "bot").out

    assert run(*ADMIN_ARGS, "principal", "disable", "bot").out.strip() == "bot: disabled"
    request = last(server)
    assert (request.method, path_of(request), json.loads(request.content)) == (
        "PATCH",
        "/api/v1/admin/principals/bot",
        {"disabled": True},
    )
    assert load_policy(policy).principal("bot").disabled is True  # type: ignore[union-attr]
    assert run(*ADMIN_ARGS, "principal", "enable", "bot").out.strip() == "bot: enabled"
    assert json.loads(last(server).content) == {"disabled": False}

    assert run(*ADMIN_ARGS, "principal", "update", "bot", "--description", "renamed").out.strip() == "bot: admin=no"
    request = last(server)
    assert (request.method, path_of(request), json.loads(request.content)) == (
        "PATCH",
        "/api/v1/admin/principals/bot",
        {"description": "renamed"},
    )
    refused = run(*ADMIN_ARGS, "principal", "update", "bot", "--admin")
    assert refused.code == 1 and json.loads(last(server).content) == {"admin": True}

    removed = run(*ADMIN_ARGS, "principal", "remove", "bot", "--yes")
    assert removed.code == 0 and "removed principal bot (0 grants removed)" in removed.out
    assert (last(server).method, path_of(last(server))) == ("DELETE", "/api/v1/admin/principals/bot")
    assert load_policy(policy).principal("bot") is None


def test_token_endpoints(run: Runner, server: FakeAdminServer, policy: Path):
    run(*ADMIN_ARGS, "principal", "add", "bot", "--kind", "agent")
    issued = run(*ADMIN_ARGS, "token", "issue", "bot", "--expires", "90d", "--description", "ci")
    assert issued.code == 0
    token = issued.out.strip()
    assert TOKEN_RE.fullmatch(token) and "\n" not in issued.out.strip()
    request = last(server)
    assert (request.method, path_of(request)) == ("POST", "/api/v1/admin/principals/bot/tokens")
    assert json.loads(request.content) == {"expires": "90d", "description": "ci"}
    token_id = token.split("_")[1]
    assert token not in issued.err and token_id in issued.err and "Shown once" in issued.err
    assert verify_token_hash(load_policy(policy).principal("bot").tokens[0].hash, token)  # type: ignore[union-attr]

    listed = json.loads(run(*ADMIN_ARGS, "token", "list", "bot", "--json").out)
    assert path_of(last(server)) == "/api/v1/admin/principals/bot/tokens" and listed[0]["id"] == token_id
    assert token_id in run(*ADMIN_ARGS, "token", "list", "bot").out

    rotated = run(*ADMIN_ARGS, "token", "rotate", "bot", token_id, "--grace", "24h", "--expires", "30d")
    request = last(server)
    assert rotated.code == 0 and TOKEN_RE.fullmatch(rotated.out.strip())
    assert path_of(request) == f"/api/v1/admin/principals/bot/tokens/{token_id}/rotate"
    assert json.loads(request.content) == {"grace": "24h", "expires": "30d", "description": ""}
    assert "stays valid until" in rotated.err

    new_id = rotated.out.strip().split("_")[1]
    revoked = run(*ADMIN_ARGS, "token", "revoke", "bot", token_id)
    assert revoked.code == 0 and (last(server).method, path_of(last(server))) == (
        "DELETE",
        f"/api/v1/admin/principals/bot/tokens/{token_id}",
    )
    assert [t.id for t in load_policy(policy).principal("bot").tokens] == [new_id]  # type: ignore[union-attr]

    plain = run(*ADMIN_ARGS, "token", "rotate", "bot", new_id)
    assert json.loads(last(server).content) == {"description": ""} and "is revoked" in plain.err


def test_token_output_file_in_server_mode(run: Runner, server: FakeAdminServer, tmp_path: Path):
    run(*ADMIN_ARGS, "principal", "add", "bot", "--kind", "agent")
    target = tmp_path / "bot.token"
    result = run(*ADMIN_ARGS, "token", "issue", "bot", "--output-file", str(target))
    assert result.code == 0 and result.out == ""
    assert stat.S_IMODE(target.stat().st_mode) == 0o600 and TOKEN_RE.fullmatch(target.read_text().strip())
    token_id = target.read_text().strip().split("_")[1]
    again = run(*ADMIN_ARGS, "token", "issue", "bot", "--output-file", str(target))
    assert again.code == 1 and "refusing to overwrite" in again.err
    assert sum(r.method == "POST" and path_of(r).endswith("/tokens") for r in server.requests) == 1
    second = tmp_path / "second"
    rotated = run(*ADMIN_ARGS, "token", "rotate", "bot", token_id, "--output-file", str(second))
    assert rotated.code == 0 and rotated.out == "" and TOKEN_RE.fullmatch(second.read_text().strip())


def test_server_rejection_leaves_no_output_file(run: Runner, server: FakeAdminServer, tmp_path: Path):
    target = tmp_path / "t"
    result = run(*ADMIN_ARGS, "token", "issue", "nobody", "--output-file", str(target))
    assert result.code == exit_codes.NOT_FOUND and not target.exists()


def test_grant_endpoints(run: Runner, server: FakeAdminServer, policy: Path):
    run(*ADMIN_ARGS, "principal", "add", "bot", "--kind", "agent")
    added = run(*ADMIN_ARGS, "grant", "add", "bot", "--key", "firefly.*", "--expires", "7d", "--description", "d")
    grant_id = added.out.strip()
    request = last(server)
    assert added.code == 0 and grant_id.startswith("g_")
    assert (request.method, path_of(request)) == ("POST", "/api/v1/admin/grants")
    assert json.loads(request.content) == {
        "principal": "bot",
        "key": "firefly.*",
        "actions": ["list", "read"],
        "description": "d",
        "expires": "7d",
    }
    tagged = run(*ADMIN_ARGS, "grant", "add", "bot", "--tag", "ops", "--actions", "read,list,read")
    assert tagged.code == 0
    assert json.loads(last(server).content) == {
        "principal": "bot",
        "tag": "ops",
        "actions": ["read", "list"],
        "description": "",
    }

    everything = json.loads(run(*ADMIN_ARGS, "grant", "list", "--json").out)
    assert last(server).url.query == b"" and len(everything) == 2
    mine = run(*ADMIN_ARGS, "grant", "list", "--principal", "bot")
    assert dict(last(server).url.params) == {"principal": "bot"} and "key:firefly.*" in mine.out
    assert "tag:ops" in mine.out

    removed = run(*ADMIN_ARGS, "grant", "remove", grant_id)
    assert removed.code == 0 and (last(server).method, path_of(last(server))) == (
        "DELETE",
        f"/api/v1/admin/grants/{grant_id}",
    )
    assert [g.tag for g in load_policy(policy).grants] == ["ops"]


def test_check_endpoint(run: Runner, server: FakeAdminServer):
    run(*ADMIN_ARGS, "principal", "add", "bot", "--kind", "agent")
    grant_id = run(*ADMIN_ARGS, "grant", "add", "bot", "--key", "db.*").out.strip()
    allowed = run(*ADMIN_ARGS, "check", "bot", "read", "db.pw")
    assert (allowed.code, allowed.out) == (0, f"allowed (grant {grant_id})\n")
    request = last(server)
    assert (request.method, path_of(request)) == ("POST", "/api/v1/admin/check")
    assert json.loads(request.content) == {"principal": "bot", "action": "read", "name": "db.pw"}
    denied = run(*ADMIN_ARGS, "check", "bot", "write", "db.pw", "--tag", "a", "--tag", "b")
    assert (denied.code, denied.out) == (1, "denied (no-grant)\n")
    assert json.loads(last(server).content)["tags"] == ["a", "b"]
    unknown = run(*ADMIN_ARGS, "check", "nobody", "read", "x")
    assert unknown.code == exit_codes.NOT_FOUND and "Principal not found: nobody" in unknown.err


def test_access_log_endpoint(run: Runner, server: FakeAdminServer, tmp_path: Path):
    lines = [
        {"ts": "2026-10-18T10:00:00Z", "principal": "bot", "kind": "agent", "action": "read", "key": "a",
         "decision": "allowed", "client": "1.2.3.4", "status": 200},
        {"ts": "2099-01-01T10:00:00Z", "principal": "bot", "kind": "agent", "action": "read", "key": "b",
         "decision": "denied", "reason": "no-grant", "client": "1.2.3.4", "status": 404},
    ]  # fmt: skip
    (tmp_path / "access.jsonl").write_text("\n".join(json.dumps(line) for line in lines) + "\n")
    table = run(*ADMIN_ARGS, "log")
    assert table.code == 0 and "no-grant" in table.out and "1.2.3.4" in table.out
    assert dict(last(server).url.params) == {"limit": "100"}
    raw = run(
        *ADMIN_ARGS, "log", "--json", "--principal", "bot", "--decision", "denied", "--since", "24h", "--limit", "5"
    )
    assert dict(last(server).url.params) == {
        "limit": "5",
        "principal": "bot",
        "decision": "denied",
        "since": "24h",
    }
    assert [json.loads(line)["key"] for line in raw.out.splitlines()] == ["b"]
    assert run(*ADMIN_ARGS, "log", "--since", "nonsense").code == 1  # rejected before any request
    assert last(server).url.params.get("since") != "nonsense"


def test_access_log_not_configured(run: Runner, policy: Path, monkeypatch: pytest.MonkeyPatch):
    FakeAdminServer(policy, ADMIN_KEY, log_file=None).install(monkeypatch)
    result = run(*ADMIN_ARGS, "log")
    assert result.code == 1 and "No access log file configured (MATTSTASH_ACCESS_LOG_FILE)" in result.err


# ---- error mapping -----------------------------


def test_policy_validation_errors_show_the_servers_message(run: Runner, server: FakeAdminServer):
    result = run(*ADMIN_ARGS, "principal", "add", "evil", "--kind", "agent", "--admin")
    assert result.code == 1 and "HTTP 400" in result.err and "admin" in result.err.split("HTTP 400", 1)[1]
    run(*ADMIN_ARGS, "principal", "add", "bot", "--kind", "agent")
    dup = run(*ADMIN_ARGS, "principal", "add", "bot", "--kind", "agent")
    assert dup.code == 1 and "already exists" in dup.err


def test_lockout_message_surfaces_from_the_server(run: Runner, server: FakeAdminServer):
    run(*ADMIN_ARGS, "principal", "add", "matt", "--kind", "human-device", "--admin")
    token_id = run(*ADMIN_ARGS, "token", "issue", "matt").out.strip().split("_")[1]
    result = run(*ADMIN_ARGS, "token", "revoke", "matt", token_id)
    assert result.code == 1 and "no admin principal with a valid token" in result.err


def test_not_found_is_exit_2(run: Runner, server: FakeAdminServer):
    for argv in (["principal", "show", "nobody"], ["grant", "remove", "g_00000000"]):
        result = run(*ADMIN_ARGS, *argv)
        assert result.code == exit_codes.NOT_FOUND and "HTTP 404" in result.err
    assert "Principal not found: nobody" in run(*ADMIN_ARGS, "principal", "show", "nobody").err


def test_forbidden_for_non_admin_keys(run: Runner, server: FakeAdminServer):
    server.is_admin = False
    result = run(*ADMIN_ARGS, "principal", "list")
    assert result.code == 1 and "HTTP 403" in result.err and "Insufficient permissions" in result.err


def test_read_only_policy_and_missing_policy(run: Runner, server: FakeAdminServer):
    server.read_only = True
    result = run(*ADMIN_ARGS, "principal", "add", "x", "--kind", "agent")
    assert result.code == 1 and "HTTP 409" in result.err and "Policy file is read-only" in result.err
    server.read_only = False
    server.no_policy = True
    result = run(*ADMIN_ARGS, "principal", "add", "x", "--kind", "agent")
    assert result.code == 1 and "HTTP 503" in result.err and "No policy file configured" in result.err
    assert run(*ADMIN_ARGS, "principal", "list").code == 0  # reads are not mutations


def test_authentication_failure_does_not_echo_anything(run: Runner, server: FakeAdminServer):
    result = run("--server-url", URL, "--api-key", "wrong-key-" + "x" * 30, "admin", "principal", "list")
    assert result.code == 1 and "HTTP 401" in result.err and "authentication failed" in result.err
    assert "wrong-key" not in result.err


def test_the_api_key_never_appears_in_output(run: Runner, server: FakeAdminServer):
    """Even a server that echoes the key in its error text cannot make the CLI print it."""

    def echo(request: httpx.Request) -> Optional[httpx.Response]:
        return httpx.Response(400, json={"detail": f"bad request from {request.headers['X-API-Key']}"})

    server.forced = echo
    for argv in (["principal", "list"], ["principal", "add", "x", "--kind", "agent"], ["check", "x", "read", "y"]):
        result = run(*ADMIN_ARGS, *argv)
        assert result.code == 1 and ADMIN_KEY not in result.err + result.out and "***" in result.err
        assert ADMIN_KEY.split("_")[2] not in result.err


@pytest.mark.parametrize(
    ("response", "shown"),
    [
        (httpx.Response(400, text="<html>secret page</html>"), False),
        (httpx.Response(400, json={"detail": ["not", "a", "string"]}), False),
        (httpx.Response(400, json={"detail": "bad\x1b[31mnews"}), False),
        (httpx.Response(401, json={"detail": "Authentication failed: details"}), False),
        (httpx.Response(500, json={"detail": "Traceback: secret"}), False),
        (httpx.Response(400, json={"detail": "x" * 1000}), True),
    ],
)
def test_only_safe_admin_details_are_shown(run: Runner, server: FakeAdminServer, response: httpx.Response, shown: bool):
    server.forced = lambda _request: response
    result = run(*ADMIN_ARGS, "principal", "list")
    assert result.code == 1 and "secret" not in result.err and "Traceback" not in result.err
    assert "\x1b" not in result.err and "details" not in result.err
    assert ("x" * 300 in result.err and "x" * 301 not in result.err) is shown


def test_rate_limit_and_unreachable_server(run: Runner, server: FakeAdminServer, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("time.sleep", lambda _seconds: None)
    server.forced = lambda _request: httpx.Response(429, headers={"Retry-After": "7"}, json={"detail": "slow"})
    result = run(*ADMIN_ARGS, "principal", "add", "x", "--kind", "agent")  # mutations are not retried
    assert result.code == 1 and "HTTP 429" in result.err and "retry after 7s" in result.err
    assert len(server.requests) == 1

    def refuse(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    server.forced = refuse
    unreachable = run(*ADMIN_ARGS, "principal", "list")
    assert unreachable.code == 1 and "request to server failed" in unreachable.err


@pytest.mark.parametrize(
    "argv",
    [
        ["principal", "list"],
        ["principal", "add", "x", "--kind", "agent"],
        ["principal", "show", "x"],
        ["principal", "disable", "x"],
        ["principal", "remove", "x", "--yes"],
        ["token", "list", "x"],
        ["token", "issue", "x"],
        ["token", "revoke", "x", "tid"],
        ["token", "rotate", "x", "tid"],
        ["grant", "list"],
        ["grant", "add", "x", "--key", "a"],
        ["grant", "remove", "g_1"],
        ["check", "x", "read", "a"],
        ["log"],
    ],
)
def test_malformed_success_answers_are_errors_not_crashes(run: Runner, server: FakeAdminServer, argv: list[str]):
    for payload in ({"unexpected": True}, {"principals": "x", "tokens": 1, "grants": {}, "records": None}):
        server.forced = lambda _request, payload=payload: httpx.Response(200, json=payload)
        result = run(*ADMIN_ARGS, *argv)
        assert result.code == 1 and "unexpected response" in result.err, argv


@pytest.mark.parametrize("argv", [["principal", "list"], ["token", "list", "x"], ["grant", "list"], ["log"]])
def test_lists_of_non_objects_are_errors(run: Runner, server: FakeAdminServer, argv: list[str]):
    server.forced = lambda _request: httpx.Response(
        200, json={"principals": [1], "tokens": [1], "grants": [1], "records": [1]}
    )
    result = run(*ADMIN_ARGS, *argv)
    assert result.code == 1 and "unexpected response" in result.err


def test_names_are_percent_encoded(run: Runner, server: FakeAdminServer):
    server.forced = lambda _request: httpx.Response(404, json={"detail": "Principal not found: a/b"})
    run(*ADMIN_ARGS, "token", "revoke", "a/b#c", "t?x")
    assert path_of(last(server)) == "/api/v1/admin/principals/a%2Fb%23c/tokens/t%3Fx"


def test_server_url_wins_over_policy_file(run: Runner, server: FakeAdminServer, tmp_path: Path):
    local = tmp_path / "local.json"
    result = run("--server-url", URL, "--api-key", ADMIN_KEY, "admin", "--policy-file", str(local), "principal", "list")
    assert result.code == 0 and "using the server" in result.err and not local.exists()


def test_server_mode_needs_an_api_key(run: Runner, server: FakeAdminServer):
    result = run("--server-url", URL, "admin", "principal", "list")
    assert result.code == 1 and "API key required" in result.err and server.requests == []


def test_api_key_file_and_environment(
    run: Runner, server: FakeAdminServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    key_file = tmp_path / "admin.key"
    key_file.write_text(ADMIN_KEY + "\n")
    assert run("--server-url", URL, "--api-key-file", str(key_file), "admin", "principal", "list").code == 0
    monkeypatch.setenv("MATTSTASH_SERVER_URL", URL)
    monkeypatch.setenv("MATTSTASH_API_KEY", ADMIN_KEY)
    assert run("admin", "principal", "list").code == 0


# ---- ordinary client mode with a principal token -----------------------------


def test_principal_tokens_pass_the_api_key_check():
    assert 55 <= len(ADMIN_KEY) <= 65 and api_key_problem(ADMIN_KEY) is None
    from mattstash.authz import generate_token

    _token_id, plaintext = generate_token()
    assert api_key_problem(plaintext) is None
    MattStashServerClient(URL, plaintext)  # accepted as an X-API-Key


def test_ordinary_commands_work_with_a_principal_token(run: Runner, monkeypatch: pytest.MonkeyPatch):
    fake = FakeServer(api_key=ADMIN_KEY).install(monkeypatch)
    fake.add("db.password", "s3cret")
    assert run("--server-url", URL, "--api-key", ADMIN_KEY, "keys").out.split() == ["db.password"]
    got = run("--server-url", URL, "--api-key", ADMIN_KEY, "get", "db.password", "--raw")
    assert got.code == 0 and got.out == "s3cret\n"
    assert fake.requests[-1].headers["X-API-Key"] == ADMIN_KEY


def test_list_and_keys_cope_with_null_fields(run: Runner, monkeypatch: pytest.MonkeyPatch):
    """A principal that may only ``list`` an entry gets name and version, with every other field null."""
    fake = FakeServer(api_key=ADMIN_KEY).install(monkeypatch)

    def listing(request: httpx.Request) -> Optional[httpx.Response]:
        if request.url.path == "/api/v1/credentials":
            entry = {
                "name": "limited",
                "username": None,
                "password": None,
                "url": None,
                "notes": None,
                "version": "0000000001",
            }
            return httpx.Response(200, json={"credentials": [entry], "count": 1})
        return None  # pragma: no cover

    fake.override = listing
    listed = run("--server-url", URL, "--api-key", ADMIN_KEY, "list")
    assert listed.code == 0 and listed.out == "- limited user=- url=- pwd=-\n"
    assert run("--server-url", URL, "--api-key", ADMIN_KEY, "keys").out == "limited\n"
    as_json = json.loads(run("--server-url", URL, "--api-key", ADMIN_KEY, "list", "--json").out)
    assert as_json[0]["username"] is None


def test_client_admin_methods_reject_bad_shapes():
    """The client validates what the server returns (a hostile or broken server must not cause a traceback)."""
    client = MattStashServerClient(URL, ADMIN_KEY)
    for call in (
        lambda: client.admin_principal_add("x", "agent"),
        lambda: client.admin_principal("x"),
        lambda: client.admin_principal_update("x", {}),
        lambda: client.admin_token_issue("x"),
        lambda: client.admin_check("x", "read", "y"),
    ):
        client._make_request = lambda *a, **k: {"allowed": "yes"}  # type: ignore[method-assign]
        with pytest.raises(ServerError, match="unexpected response"):
            call()


def test_show_marks_legacy_principals(run: Runner, server: FakeAdminServer):
    legacy = {"name": "legacy-env", "kind": "legacy", "admin": True, "legacy": True, "tokens": [], "grants": []}
    server.forced = lambda _request: httpx.Response(200, json=legacy)
    result = run(*ADMIN_ARGS, "principal", "show", "legacy-env")
    assert result.code == 0 and "legacy:      yes" in result.out and "kind:        legacy" in result.out


def test_json_output_never_contains_a_token_hash(run: Runner, server: FakeAdminServer):
    leaky = {"principals": [{"name": "x", "tokens": [{"id": "abc", "hash": "hmac-sha256:aa:bb"}]}]}
    server.forced = lambda _request: httpx.Response(200, json=leaky)
    result = run(*ADMIN_ARGS, "principal", "list", "--json")
    assert result.code == 0 and "hmac-sha256" not in result.out and '"id": "abc"' in result.out
