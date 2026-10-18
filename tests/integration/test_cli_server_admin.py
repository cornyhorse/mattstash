"""
Contract tests: the real ``mattstash admin`` CLI against the real API server (a subprocess with a policy file and an
access log), end to end: principals, tokens used for data calls, grants, ``check``, the access log, migration of v1
keys, and what a non-admin or list-only caller sees.

The server follows the admin API contract (docs/design/principals-and-grants.md, section 8); a test marked
``xfail(strict=True)`` would document a deviation of the server from it (there are none at the moment).
"""

import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import List

import httpx
import pytest

from integration.conftest import ADMIN_SERVER_SECRETS, AdminServer
from mattstash.authz import load_policy

TOKEN_RE = re.compile(r"mst_[a-z2-7]{12}_[A-Za-z0-9_-]+")
SECRET_VALUES = list(ADMIN_SERVER_SECRETS.values())
#: Every token plaintext issued in this module (the access log must contain none of them).
ISSUED: List[str] = []

Cli = Callable[..., "object"]


@pytest.fixture
def cli(admin_server: AdminServer, run_mattstash_cli):
    """``cli(*args, token=...)``: the real CLI in client mode (default: as the bootstrapped admin)."""

    def call(*args: str, token: str = "") -> object:
        return run_mattstash_cli(list(args), admin_server.env(token or admin_server.admin_token))

    return call


@pytest.fixture
def admin(cli):
    """``admin(*args)``: ``mattstash admin ...`` as the bootstrapped admin."""

    def call(*args: str):
        return cli("admin", *args)

    return call


def ok(result) -> str:
    """Assert success and return stdout."""
    assert result.returncode == 0, f"exit {result.returncode}\nstdout: {result.stdout}\nstderr: {result.stderr}"
    return result.stdout


def issue(admin, principal: str, *extra: str) -> str:
    """Issue a token; stdout must hold the token and nothing else, stderr must not repeat it."""
    result = admin("token", "issue", principal, *extra)
    token = ok(result).strip()
    assert TOKEN_RE.fullmatch(token), result.stdout
    assert token not in result.stderr and "token id" in result.stderr
    ISSUED.append(token)
    return token


def token_id(token: str) -> str:
    return token.split("_")[1]


def agent(admin, name: str, *grants: str) -> str:
    """A new agent principal with a token; each ``grants`` entry is ``"<pattern>:<actions>"``."""
    ok(admin("principal", "add", name, "--kind", "agent", "--description", f"contract test {name}"))
    token = issue(admin, name)
    for grant in grants:
        pattern, actions = grant.split(":")
        assert re.fullmatch(
            r"g_[0-9a-f]{8}", ok(admin("grant", "add", name, "--key", pattern, "--actions", actions)).strip()
        )
    return token


def assert_unauthorized(result) -> None:
    assert result.returncode == 1 and "401" in result.stderr and result.stdout == ""


def assert_not_found(result) -> None:
    assert result.returncode == 2 and "not found" in result.stderr.lower() and result.stdout == ""


def log_lines(admin, *args: str) -> list[dict]:
    return [json.loads(line) for line in ok(admin("log", "--json", *args)).splitlines()]


# ---- principals ----


def test_principal_lifecycle(admin, cli, admin_server: AdminServer) -> None:
    ok(admin("principal", "add", "lifecycle", "--kind", "agent", "--description", "first"))
    assert "lifecycle" in ok(admin("principal", "list"))
    listed = {p["name"]: p for p in json.loads(ok(admin("principal", "list", "--json")))}
    assert listed["lifecycle"] | {"tokens": []} == {
        "name": "lifecycle",
        "kind": "agent",
        "description": "first",
        "admin": False,
        "disabled": False,
        "created": listed["lifecycle"]["created"],
        "legacy": False,
        "tokens": [],
    }
    assert listed["root-admin"]["admin"] is True and listed["root-admin"]["tokens"]

    shown = json.loads(ok(admin("principal", "show", "lifecycle", "--json")))
    assert shown["grants"] == [] and shown["name"] == "lifecycle"
    assert "name:        lifecycle" in ok(admin("principal", "show", "lifecycle"))

    # the policy file the server reads has it too
    assert load_policy(admin_server.policy).principal("lifecycle") is not None

    # disabled: its token is rejected; enabled again: accepted
    ok(admin("grant", "add", "lifecycle", "--key", "app.*"))
    token = issue(admin, "lifecycle")
    assert "app.db-password" in ok(cli("keys", token=token))
    assert ok(admin("principal", "disable", "lifecycle")).strip() == "lifecycle: disabled"
    assert json.loads(ok(admin("principal", "show", "lifecycle", "--json")))["disabled"] is True
    assert "disabled" in ok(admin("principal", "list"))
    assert_unauthorized(cli("keys", token=token))
    assert ok(admin("principal", "enable", "lifecycle")).strip() == "lifecycle: enabled"
    assert "app.db-password" in ok(cli("keys", token=token))

    # duplicate and invalid names are errors, not crashes
    for args in (["lifecycle", "--kind", "agent"], ["LIFECYCLE", "--kind", "agent"], ["bad name", "--kind", "agent"]):
        result = admin("principal", "add", *args)
        assert result.returncode == 1 and result.stdout == "" and "Traceback" not in result.stderr
    assert admin("principal", "add", "an-admin-agent", "--kind", "agent", "--admin").returncode == 1

    removed = admin("principal", "remove", "lifecycle", "--yes")
    assert ok(removed).strip() == "removed principal lifecycle (1 grant removed)"
    assert_not_found(admin("principal", "show", "lifecycle"))
    assert_not_found(admin("principal", "remove", "lifecycle", "--yes"))
    assert_unauthorized(cli("keys", token=token))


def test_remove_without_yes_refuses_when_not_interactive(admin) -> None:
    ok(admin("principal", "add", "keepme", "--kind", "runner"))
    result = admin("principal", "remove", "keepme")
    assert result.returncode == 1 and "without --yes" in result.stderr
    assert "keepme" in ok(admin("principal", "list"))


def test_local_mode_sees_what_the_server_wrote(admin, run_mattstash_cli, admin_server: AdminServer) -> None:
    ok(admin("principal", "add", "shared-view", "--kind", "runner"))
    env = {k: v for k, v in admin_server.env("x").items() if not k.startswith("MATTSTASH_SERVER")}
    local = run_mattstash_cli(["admin", "--policy-file", str(admin_server.policy), "principal", "list", "--json"], env)
    assert "shared-view" in {p["name"] for p in json.loads(ok(local))}


# ---- tokens: issue, use, rotate, revoke ----


def test_issued_token_is_used_for_data_calls(admin, cli) -> None:
    token = agent(admin, "reader", "app.*:list,read")

    secret = ok(cli("get", "app.db-password", "--show-password", token=token))
    assert ADMIN_SERVER_SECRETS["app.db-password"] in secret
    assert "*****" in ok(cli("get", "app.db-password", token=token))
    listing = ok(cli("list", token=token))
    assert "app.db-password" in listing and "app.api-key" in listing and "other.secret" not in listing
    assert ok(cli("keys", token=token)).split() == ["app.api-key", "app.db-password"]

    # outside the grant: indistinguishable from missing (404), and no value leaks
    denied = cli("get", "other.secret", "--show-password", token=token)
    assert_not_found(denied)
    assert ADMIN_SERVER_SECRETS["other.secret"] not in denied.stdout + denied.stderr
    # no write grant: 403
    write = cli("put", "app.new", "--value", "x", token=token)
    assert write.returncode == 1 and "403" in write.stderr
    delete = cli("delete", "app.api-key", token=token)
    assert delete.returncode == 1 and "403" in delete.stderr
    assert "app.api-key" in ok(cli("keys", token=token))


def test_a_write_grant_allows_writes_only_where_granted(admin, cli) -> None:
    token = agent(admin, "writer", "scratch.*:list,read,write")
    ok(cli("put", "scratch.one", "--value", "w-1", token=token))
    assert "w-1" in ok(cli("get", "scratch.one", "--show-password", token=token))
    assert cli("put", "app.nope", "--value", "x", token=token).returncode == 1
    assert cli("delete", "scratch.one", token=token).returncode == 1  # no delete action
    ok(admin("grant", "add", "writer", "--key", "scratch.*", "--actions", "delete"))
    ok(cli("delete", "scratch.one", token=token))
    assert_not_found(cli("get", "scratch.one", token=token))


def test_rotate_without_grace_revokes_the_old_token(admin, cli) -> None:
    old = agent(admin, "rot-now", "app.*:list,read")
    assert "app.api-key" in ok(cli("keys", token=old))
    result = admin("token", "rotate", "rot-now", token_id(old))
    new = ok(result).strip()
    ISSUED.append(new)
    assert TOKEN_RE.fullmatch(new) and new != old and new not in result.stderr and "is revoked" in result.stderr
    assert_unauthorized(cli("keys", token=old))
    assert "app.api-key" in ok(cli("keys", token=new))
    ids = [t["id"] for t in json.loads(ok(admin("token", "list", "rot-now", "--json")))]
    assert ids == [token_id(new)]


def test_rotate_with_grace_keeps_the_old_token_for_a_while(admin, cli) -> None:
    old = agent(admin, "rot-grace", "app.*:list,read")
    result = admin("token", "rotate", "rot-grace", token_id(old), "--grace", "1h", "--expires", "30d")
    new = ok(result).strip()
    ISSUED.append(new)
    assert "stays valid until" in result.stderr
    assert "app.api-key" in ok(cli("keys", token=old)) and "app.api-key" in ok(cli("keys", token=new))
    tokens = {t["id"]: t for t in json.loads(ok(admin("token", "list", "rot-grace", "--json")))}
    assert tokens[token_id(old)]["expires"] and tokens[token_id(new)]["expires"]
    assert not tokens[token_id(old)]["expired"]

    ok(admin("token", "revoke", "rot-grace", token_id(old)))
    assert_unauthorized(cli("keys", token=old))
    ok(cli("keys", token=new))
    revoked_again = admin("token", "revoke", "rot-grace", token_id(old))
    assert_not_found(revoked_again)


def test_token_expiry_and_bad_arguments(admin, cli) -> None:
    ok(admin("principal", "add", "expiring", "--kind", "agent"))
    token = issue(admin, "expiring", "--expires", "90d", "--description", "short")
    listed = json.loads(ok(admin("token", "list", "expiring", "--json")))
    assert listed[0]["expires"].endswith("Z") and listed[0]["description"] == "short"
    assert "never" not in ok(admin("token", "list", "expiring"))
    assert token not in ok(admin("token", "list", "expiring"))
    for argv in (
        ["token", "issue", "expiring", "--expires", "2020-01-01"],
        ["token", "issue", "expiring", "--expires", "999999w"],
        ["token", "issue", "expiring", "--expires", "whenever"],
        ["token", "issue", "expiring", "--expires", ""],
        ["token", "rotate", "expiring", listed[0]["id"], "--grace", "2099-01-01"],
        ["token", "rotate", "expiring", listed[0]["id"], "--grace", "soon"],
    ):
        result = admin(*argv)
        assert result.returncode == 1 and result.stdout == "" and "Traceback" not in result.stderr, argv
    assert len(json.loads(ok(admin("token", "list", "expiring", "--json")))) == 1
    assert_not_found(admin("token", "issue", "nobody-at-all"))


def test_output_file_receives_the_token(admin, cli, tmp_path: Path) -> None:
    ok(admin("principal", "add", "filed", "--kind", "agent"))
    ok(admin("grant", "add", "filed", "--key", "app.*"))
    target = tmp_path / "token"
    result = admin("token", "issue", "filed", "--output-file", str(target))
    assert ok(result) == ""
    token = target.read_text().strip()
    ISSUED.append(token)
    assert TOKEN_RE.fullmatch(token) and token not in result.stderr
    assert (target.stat().st_mode & 0o777) == 0o600
    ok(cli("keys", token=token))
    again = admin("token", "issue", "filed", "--output-file", str(target))
    assert again.returncode == 1 and "refusing to overwrite" in again.stderr


# ---- grants and check ----


def test_grant_add_list_remove(admin, cli) -> None:
    token = agent(admin, "granted")
    assert ok(admin("grant", "list", "--principal", "granted")).strip() == "(none)"
    assert_not_found(cli("get", "app.db-password", token=token))

    key_grant = ok(
        admin("grant", "add", "granted", "--key", "app.db-*", "--actions", "list,read", "--description", "d")
    )
    key_id = key_grant.strip()
    tag_id = ok(admin("grant", "add", "granted", "--tag", "ops", "--expires", "30d")).strip()
    grants = {g["id"]: g for g in json.loads(ok(admin("grant", "list", "--principal", "granted", "--json")))}
    assert set(grants) == {key_id, tag_id}
    assert grants[key_id]["key"] == "app.db-*" and grants[key_id]["tag"] is None
    assert grants[key_id]["actions"] == ["list", "read"] and grants[key_id]["description"] == "d"
    assert grants[tag_id]["tag"] == "ops" and grants[tag_id]["expires"].endswith("Z")
    assert all(g["principal"] == "granted" and g["legacy"] is False and g["expired"] is False for g in grants.values())
    assert key_id in ok(admin("grant", "list")) and key_id in ok(admin("principal", "show", "granted"))

    assert ADMIN_SERVER_SECRETS["app.db-password"] in ok(cli("get", "app.db-password", "--show-password", token=token))
    assert_not_found(cli("get", "app.api-key", token=token))  # the pattern is narrower than app.*

    ok(admin("grant", "remove", key_id))
    assert_not_found(cli("get", "app.db-password", token=token))
    assert_not_found(admin("grant", "remove", key_id))
    assert [g["id"] for g in json.loads(ok(admin("grant", "list", "--principal", "granted", "--json")))] == [tag_id]

    # invalid grants are rejected whole
    for argv in (
        ["grant", "add", "granted", "--tag", "ops", "--actions", "write"],
        ["grant", "add", "granted", "--key", "a*b"],
        ["grant", "add", "granted", "--key", "app.", "--actions", "read"],
        ["grant", "add", "granted", "--key", "a", "--actions", "everything"],
    ):
        assert admin(*argv).returncode == 1, argv
    assert_not_found(admin("grant", "add", "no-such-principal", "--key", "a"))
    assert_not_found(admin("grant", "list", "--principal", "no-such-principal"))


def test_check_explains_decisions(admin) -> None:
    agent(admin, "checked", "app.*:list,read")
    allowed = admin("check", "checked", "read", "app.db-password")
    assert re.fullmatch(r"allowed \(grant g_[0-9a-f]{8}\)\n", ok(allowed))
    for action, name in (("write", "app.db-password"), ("read", "other.secret"), ("delete", "app.x")):
        denied = admin("check", "checked", action, name)
        assert denied.returncode == 1 and denied.stdout == "denied (no-grant)\n", (action, name)
    ok(admin("grant", "add", "checked", "--tag", "ops"))
    assert ok(admin("check", "checked", "read", "tagged.entry", "--tag", "ops")).startswith("allowed (grant g_")
    assert admin("check", "checked", "read", "tagged.entry", "--tag", "other").returncode == 1
    assert admin("check", "checked", "read", "tagged.entry").returncode == 1
    ok(admin("principal", "disable", "checked"))
    disabled = admin("check", "checked", "read", "app.db-password")
    assert disabled.returncode == 1 and disabled.stdout == "denied (disabled)\n"
    assert_not_found(admin("check", "no-such-principal", "read", "a"))


# ---- who may administer ----


def test_a_non_admin_token_cannot_use_admin_commands(admin, cli) -> None:
    token = agent(admin, "nosy", "*:list,read,write,delete")  # even a '*' grant is not admin
    for argv in (
        ["principal", "list"],
        ["principal", "show", "root-admin"],
        ["token", "list", "root-admin"],
        ["grant", "list"],
        ["check", "root-admin", "read", "a"],
        ["log"],
        ["principal", "add", "sneaky", "--kind", "agent"],
        ["token", "issue", "nosy"],
        ["grant", "add", "nosy", "--key", "*"],
        ["principal", "remove", "root-admin", "--yes"],
    ):
        result = cli("admin", *argv, token=token)
        assert result.returncode == 1 and result.stdout == "", argv
        assert "403" in result.stderr and "Insufficient permissions" in result.stderr, (argv, result.stderr)
    assert "sneaky" not in ok(admin("principal", "list"))
    assert len(json.loads(ok(admin("token", "list", "nosy", "--json")))) == 1


def test_an_invalid_token_cannot_use_admin_commands(cli) -> None:
    result = cli("admin", "principal", "list", token="mst_aaaaaaaaaaaa_" + "x" * 43)
    assert_unauthorized(result)


# ---- list-only callers ----


def test_a_list_only_principal_sees_names_but_no_fields(admin, cli) -> None:
    token = agent(admin, "lister", "app.*:list")
    listing = ok(cli("list", token=token))
    assert "app.db-password user=- url=- pwd='*****'" in listing and "other.secret" not in listing
    records = json.loads(ok(cli("list", "--json", token=token)))
    assert {r["name"] for r in records} == {"app.api-key", "app.db-password"}
    assert all(r["username"] is None and r["url"] is None and r["notes"] is None for r in records)
    assert not any(value in json.dumps(records) for value in SECRET_VALUES)
    assert ok(cli("keys", token=token)).split() == ["app.api-key", "app.db-password"]
    denied = cli("get", "app.db-password", "--show-password", token=token)
    assert_not_found(denied)
    assert not any(value in denied.stdout + denied.stderr for value in SECRET_VALUES)


# ---- the access log ----


def test_log_filters_and_contents(admin, cli, admin_server: AdminServer) -> None:
    token = agent(admin, "logged", "app.*:list,read")
    ok(cli("get", "app.db-password", "--show-password", token=token))
    assert_not_found(cli("get", "other.secret", token=token))
    assert cli("put", "app.z", "--value", "zzz", token=token).returncode == 1

    mine = log_lines(admin, "--principal", "logged")
    assert mine and all(r["principal"] == "logged" and r["kind"] == "agent" for r in mine)
    assert [r["decision"] for r in mine if r["action"] == "read"] == ["allowed", "denied"]
    allowed = next(r for r in mine if r["decision"] == "allowed")
    assert allowed["key"] == "app.db-password" and allowed["token"] == token_id(token) and allowed["status"] == 200
    assert allowed["grant"].startswith("g_")
    denied = log_lines(admin, "--principal", "logged", "--decision", "denied")
    assert denied and all(r["decision"] == "denied" for r in denied) and {r["reason"] for r in denied} == {"no-grant"}
    assert {r["action"] for r in denied} == {"read", "write"}
    assert all(r["decision"] == "allowed" for r in log_lines(admin, "--principal", "logged", "--decision", "allowed"))
    assert len(log_lines(admin, "--principal", "logged", "--limit", "1")) == 1
    assert log_lines(admin, "--principal", "logged", "--since", "1h") == mine
    assert log_lines(admin, "--principal", "logged", "--since", "2099-01-01") == []
    assert ok(admin("log", "--principal", "logged", "--since", "2099-01-01")).strip() == "(none)"
    assert log_lines(admin, "--principal", "nobody-at-all") == []
    table = ok(admin("log", "--principal", "logged"))
    assert table.splitlines()[0].split()[:3] == ["TS", "PRINCIPAL", "KIND"] and "denied" in table

    # the admin's own commands are logged under the admin
    routes = {r["route"] for r in log_lines(admin, "--principal", "root-admin")}
    assert {"admin.principal.add", "admin.token.issue", "admin.grant.add"} <= routes

    # the CLI refuses what the server would silently treat as "no filter" (see the server note in the report)
    for argv in (["log", "--principal", ""], ["log", "--since", ""], ["grant", "list", "--principal", ""]):
        result = admin(*argv)
        assert result.returncode == 1 and "empty value" in result.stderr, argv
    assert admin("log", "--since", "999999w").returncode == 1
    assert admin("log", "--since", "yesterday-ish").returncode == 1


def test_the_access_log_never_holds_tokens_or_secret_values(admin, cli, admin_server: AdminServer) -> None:
    token = agent(admin, "leakcheck", "app.*:list,read")
    ok(cli("get", "app.db-password", "--show-password", token=token))
    ok(cli("list", "--show-password", token=token))
    assert cli("get", "app.db-password", token=token + "tampered").returncode == 1  # a wrong secret for a known id
    text = admin_server.log.read_text()
    assert text.count('"principal":"leakcheck"') >= 2 and ISSUED
    for plaintext in [*ISSUED, token]:
        assert plaintext not in text
        assert plaintext.split("_", 2)[2] not in text  # not even the secret part
    for value in SECRET_VALUES:
        assert value not in text
    assert admin_server.admin_token not in text
    assert "hmac-sha256" not in text and "sha256:" not in text
    # and what the CLI prints for the log
    for result in (admin("log", "--json"), admin("log")):
        assert not any(t in result.stdout for t in ISSUED) and "hmac-sha256" not in result.stdout
    # the policy file holds hashes only
    policy_text = admin_server.policy.read_text()
    assert not any(t in policy_text for t in ISSUED) and "hmac-sha256:" in policy_text
    # nor does any admin listing show them
    for result in (admin("principal", "list", "--json"), admin("principal", "show", "root-admin", "--json")):
        assert "hmac-sha256" not in result.stdout and '"hash"' not in result.stdout


# ---- migrating v1 keys ----


def test_migrate_keys_locally_and_the_server_picks_them_up(
    admin, cli, run_mattstash_cli, admin_server: AdminServer, tmp_path: Path
) -> None:
    reader_key = "v1-reader-key-" + "r" * 24
    boss_key = "v1-boss-key-" + "b" * 26
    keys = tmp_path / "keys.json"
    keys.write_text(
        json.dumps(
            {
                "keys": [
                    {"id": "v1-reader", "key": reader_key, "ops": ["read"], "prefixes": ["app."]},
                    {"id": "v1-boss", "key": boss_key, "ops": ["read", "write", "admin"]},
                ]
            }
        )
    )
    env = {k: v for k, v in admin_server.env("x").items() if not k.startswith("MATTSTASH_SERVER")}
    result = run_mattstash_cli(
        ["admin", "migrate-keys", "--from", str(keys), "--policy-file", str(admin_server.policy)], env
    )
    assert ok(result).split() == ["v1-reader", "v1-boss"] and "migrated 2 keys" in result.stderr
    assert reader_key not in result.stdout + result.stderr
    policy_text = admin_server.policy.read_text()
    assert reader_key not in policy_text and "sha256:" in policy_text

    # the running server uses them without a restart
    assert ADMIN_SERVER_SECRETS["app.db-password"] in ok(
        cli("get", "app.db-password", "--show-password", token=reader_key)
    )
    assert_not_found(cli("get", "other.secret", token=reader_key))
    assert cli("put", "app.v1", "--value", "x", token=reader_key).returncode == 1
    assert cli("admin", "principal", "list", token=reader_key).returncode == 1  # read-only key: not an admin
    names = {p["name"]: p for p in json.loads(ok(admin("principal", "list", "--json")))}
    assert names["v1-reader"]["kind"] == "agent" and names["v1-boss"]["admin"] is True

    # the migrated admin key administers (a sha256-scheme token behaves like any other)
    assert "v1-boss" in ok(cli("admin", "principal", "list", token=boss_key))
    # a key can't be migrated twice, in the file or into the policy
    again = run_mattstash_cli(
        ["admin", "migrate-keys", "--from", str(keys), "--policy-file", str(admin_server.policy)], env
    )
    assert again.returncode == 1 and "already exists" in again.stderr
    renamed = tmp_path / "renamed.json"
    renamed.write_text(json.dumps({"keys": [{"id": "v1-copy", "key": reader_key, "ops": ["read"]}]}))
    duplicate = run_mattstash_cli(
        ["admin", "migrate-keys", "--from", str(renamed), "--policy-file", str(admin_server.policy)], env
    )
    assert duplicate.returncode == 1 and "more than once" in duplicate.stderr
    assert "v1-copy" not in ok(admin("principal", "list"))


# ---- the wire format of the contract ----


def request(admin_server: AdminServer, method: str, path: str, **kwargs) -> httpx.Response:
    return httpx.request(
        method, f"{admin_server.url}/api/v1/admin/{path}", headers={"X-API-Key": admin_server.admin_token}, **kwargs
    )


def test_wire_shapes_follow_the_contract(admin_server: AdminServer) -> None:
    created = request(admin_server, "POST", "principals", json={"name": "wire", "kind": "agent"})
    assert created.status_code == 201
    assert set(created.json()) == {"name", "kind", "description", "admin", "disabled", "created", "legacy", "tokens"}

    issued = request(admin_server, "POST", "principals/wire/tokens", json={"expires": "30d", "description": "w"})
    assert issued.status_code == 201 and issued.headers["cache-control"] == "no-store"
    body = issued.json()
    assert set(body) == {"token", "id", "expires"} and TOKEN_RE.fullmatch(body["token"])
    ISSUED.append(body["token"])

    listed = request(admin_server, "GET", "principals/wire/tokens").json()
    assert set(listed["tokens"][0]) == {"id", "created", "expires", "description", "expired"}
    assert body["token"] not in json.dumps(listed)

    rotated = request(admin_server, "POST", f"principals/wire/tokens/{body['id']}/rotate", json={"grace": "24h"})
    assert rotated.status_code == 201 and set(rotated.json()) == {"token", "id", "expires", "old_token_expires"}
    ISSUED.append(rotated.json()["token"])

    grant = request(admin_server, "POST", "grants", json={"principal": "wire", "key": "app.*"})
    assert grant.status_code == 201
    assert set(grant.json()) == {
        "id", "principal", "key", "tag", "actions", "expires", "description", "created", "expired", "legacy",
    }  # fmt: skip
    check = request(admin_server, "POST", "check", json={"principal": "wire", "action": "read", "name": "app.x"})
    assert check.json() == {"allowed": True, "reason": "granted", "grant": grant.json()["id"]}
    log = request(admin_server, "GET", "access-log", params={"limit": 3}).json()
    assert log["count"] == len(log["records"]) == 3

    gone = request(admin_server, "DELETE", "principals/wire")
    assert gone.json() == {"detail": "Principal removed: wire", "grants_removed": 1}
    missing = request(admin_server, "GET", "principals/wire")
    assert missing.status_code == 404 and missing.json() == {"detail": "Principal not found: wire"}


def test_admin_endpoints_require_authentication(admin_server: AdminServer) -> None:
    anonymous = httpx.get(f"{admin_server.url}/api/v1/admin/principals")
    assert anonymous.status_code == 401
    wrong = httpx.get(
        f"{admin_server.url}/api/v1/admin/principals", headers={"X-API-Key": "mst_aaaaaaaaaaaa_" + "y" * 43}
    )
    assert wrong.status_code == 401


def test_server_rejects_an_absolute_grace(admin_server: AdminServer) -> None:
    request(admin_server, "POST", "principals", json={"name": "grace-wire", "kind": "agent"})
    token = request(admin_server, "POST", "principals/grace-wire/tokens", json={}).json()
    ISSUED.append(token["token"])
    response = request(
        admin_server, "POST", f"principals/grace-wire/tokens/{token['id']}/rotate", json={"grace": "2098-01-01"}
    )
    if response.status_code == 201:
        ISSUED.append(response.json()["token"])
    assert response.status_code == 400
