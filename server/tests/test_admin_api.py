"""The admin API (principals, tokens, grants, check, access log) against the contract the CLI is built on."""

import errno
import json
import logging
import os
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from mattstash.authz import generate_token, load_policy
from mattstash.utils.exceptions import DatabaseLockError, DatabaseLockTimeoutError

from app.security import api_keys

from .conftest import FULL_KEY, RUNNER_PREFIXES, auth

READ_ONLY = {"detail": "Policy file is read-only; edit it and POST /admin/invalidate-api-key-cache"}
FORBIDDEN = {"detail": "Insufficient permissions"}
BASE = "/api/v1/admin"


def bearer(token: str) -> dict[str, str]:
    return auth(token)


@pytest.fixture
def log_path(tmp_path) -> str:
    return str(tmp_path / "logs" / "access.jsonl")


@pytest.fixture
def adm(make_client, policy_path, policy_tokens, log_path, data):
    """Client acting as the admin principal ``matt``; the access log is written to a file."""
    os.makedirs(os.path.dirname(log_path))
    client = make_client(POLICY_FILE=policy_path, ACCESS_LOG_FILE=log_path, ALLOW_WRITES=True)
    client.headers.update(bearer(policy_tokens["matt"]))
    return client


def on_disk(policy_path):
    return load_policy(policy_path)


def parse_time(text: str) -> datetime:
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z", text), text
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


# ---------------------------------------------------------------------------
# who may call
# ---------------------------------------------------------------------------

ENDPOINTS = [
    ("GET", "/principals", None),
    ("POST", "/principals", {"name": "n", "kind": "agent"}),
    ("GET", "/principals/hermes", None),
    ("PATCH", "/principals/hermes", {"disabled": True}),
    ("DELETE", "/principals/hermes", None),
    ("GET", "/principals/hermes/tokens", None),
    ("POST", "/principals/hermes/tokens", {}),
    ("POST", "/principals/hermes/tokens/import", {"key": "k" * 40}),
    ("DELETE", "/principals/hermes/tokens/abcdefghijkl", None),
    ("POST", "/principals/hermes/tokens/abcdefghijkl/rotate", {}),
    ("GET", "/grants", None),
    ("POST", "/grants", {"principal": "hermes", "key": "x"}),
    ("DELETE", "/grants/g_00000000", None),
    ("POST", "/check", {"principal": "hermes", "action": "read", "name": "x"}),
    ("GET", "/access-log", None),
    ("POST", "/reload", None),
    ("POST", "/invalidate-api-key-cache", None),
]


@pytest.mark.parametrize(("method", "path", "body"), ENDPOINTS)
def test_every_admin_endpoint_refuses_non_admins_before_looking_at_the_request(
    adm, policy_tokens, policy_path, method, path, body
):
    before = Path(policy_path).read_text()
    for who in ("hermes", "scribe", "runner", "lister"):  # agents and runners can never administer
        response = adm.request(method, BASE + path, json=body, headers=bearer(policy_tokens[who]))
        assert response.status_code == 403 and response.json() == FORBIDDEN, who
    # not even with a body that would be invalid: authorization comes first
    response = adm.request(method, BASE + path, content=b"{bad", headers=bearer(policy_tokens["hermes"]))
    assert response.status_code == 403
    assert Path(policy_path).read_text() == before


def test_an_agent_cannot_make_itself_an_admin_through_the_api(adm):
    assert adm.patch(f"{BASE}/principals/hermes", json={"admin": True}).status_code == 400
    assert adm.post(f"{BASE}/principals", json={"name": "bot", "kind": "agent", "admin": True}).status_code == 400
    assert adm.post(f"{BASE}/principals", json={"name": "ci", "kind": "runner", "admin": True}).status_code == 400


# ---------------------------------------------------------------------------
# principals
# ---------------------------------------------------------------------------


def test_list_principals_never_includes_hashes(adm, policy_tokens):
    response = adm.get(f"{BASE}/principals")
    assert response.status_code == 200
    by_name = {p["name"]: p for p in response.json()["principals"]}
    assert set(by_name) == {"matt", "hermes", "lister", "fireflyer", "scribe", "runner", "expired", "off"}
    assert "legacy" not in by_name["matt"]  # the field went with the legacy keys
    hermes = by_name["hermes"]
    assert hermes["kind"] == "agent" and hermes["disabled"] is False and hermes["admin"] is False
    (token,) = hermes["tokens"]
    assert set(token) == {"id", "created", "expires", "description", "expired"}
    assert token["expired"] is False and token["expires"] is None
    assert by_name["expired"]["tokens"][0]["expired"] is True
    assert "hmac" not in response.text and "sha256" not in response.text and "hash" not in response.text


def test_create_principal(adm, policy_path):
    response = adm.post(f"{BASE}/principals", json={"name": "bot-1", "kind": "agent", "description": "a bot"})
    assert response.status_code == 201
    body = response.json()
    assert body["name"] == "bot-1" and body["kind"] == "agent" and body["description"] == "a bot"
    assert body["admin"] is False and body["disabled"] is False and body["tokens"] == []
    assert "legacy" not in body
    parse_time(body["created"])
    assert on_disk(policy_path).principal("bot-1") is not None
    laptop = adm.post(f"{BASE}/principals", json={"name": "laptop", "kind": "human-device", "admin": True})
    assert laptop.status_code == 201 and laptop.json()["admin"] is True


@pytest.mark.parametrize(
    "body",
    [
        {"name": "HERMES", "kind": "agent"},  # names are unique without regard to case
        {"name": "legacy-x", "kind": "agent"},  # reserved
        {"name": "bad name", "kind": "agent"},
        {"name": "x", "kind": "robot"},
        {"name": "x", "kind": "legacy"},  # there is no such kind any more
    ],
)
def test_create_principal_validation_errors_are_400_with_the_library_message(adm, body):
    response = adm.post(f"{BASE}/principals", json=body)
    assert response.status_code == 400 and isinstance(response.json()["detail"], str)


def test_request_bodies_refuse_unknown_fields(adm):
    assert adm.post(f"{BASE}/principals", json={"name": "x", "kind": "agent", "admn": True}).status_code == 422
    assert adm.patch(f"{BASE}/principals/hermes", json={"kind": "human-device"}).status_code == 422
    assert adm.post(f"{BASE}/principals/hermes/tokens", json={"ttl": "1d"}).status_code == 422
    assert adm.post(f"{BASE}/grants", json={"principal": "hermes", "key": "x", "admin": True}).status_code == 422


def test_show_principal_includes_its_grants_and_ignores_case(adm):
    response = adm.get(f"{BASE}/principals/HERMES")
    assert response.status_code == 200
    body = response.json()
    assert body["name"] == "hermes" and len(body["grants"]) == 3
    assert {g["key"] or g["tag"] for g in body["grants"]} == {"firefly.*", "firefly-mcp", "shared"}
    assert all(g["principal"] == "hermes" and "legacy" not in g for g in body["grants"])
    assert adm.get(f"{BASE}/principals/nobody").json() == {"detail": "Principal not found: nobody"}
    assert adm.get(f"{BASE}/principals/nobody").status_code == 404


def test_patch_principal(adm, policy_path):
    response = adm.patch(f"{BASE}/principals/hermes", json={"disabled": True, "description": "paused"})
    assert response.status_code == 200 and response.json()["disabled"] is True
    assert response.json()["description"] == "paused"
    assert on_disk(policy_path).principal("hermes").disabled
    assert adm.patch(f"{BASE}/principals/hermes", json={"disabled": False}).json()["disabled"] is False
    assert adm.patch(f"{BASE}/principals/hermes", json={}).status_code == 200  # nothing to change
    assert adm.patch(f"{BASE}/principals/nobody", json={"disabled": True}).json() == {
        "detail": "Principal not found: nobody"
    }


def test_disabling_takes_effect_on_the_very_next_request(adm, policy_tokens):
    hermes = bearer(policy_tokens["hermes"])
    assert adm.get("/api/v1/credentials", headers=hermes).status_code == 200
    adm.patch(f"{BASE}/principals/hermes", json={"disabled": True})
    assert adm.get("/api/v1/credentials", headers=hermes).status_code == 401
    adm.patch(f"{BASE}/principals/hermes", json={"disabled": False})
    assert adm.get("/api/v1/credentials", headers=hermes).status_code == 200


def test_delete_principal_removes_its_grants_and_its_access(adm, policy_tokens, policy_path):
    response = adm.delete(f"{BASE}/principals/hermes")
    assert response.status_code == 200
    assert response.json() == {"detail": "Principal removed: hermes", "grants_removed": 3}
    assert on_disk(policy_path).principal("hermes") is None
    assert adm.get("/api/v1/credentials", headers=bearer(policy_tokens["hermes"])).status_code == 401
    assert adm.delete(f"{BASE}/principals/hermes").status_code == 404


def test_lockout_is_refused_for_the_last_admin(adm, policy_tokens):
    me = f"{BASE}/principals/matt"
    for response in (
        adm.patch(me, json={"disabled": True}),
        adm.patch(me, json={"admin": False}),
        adm.delete(me),
        adm.delete(f"{me}/tokens/{policy_tokens['matt'].split('_')[1]}"),
    ):
        assert response.status_code == 400 and "no admin principal" in response.json()["detail"]
    assert adm.get(f"{BASE}/principals").status_code == 200  # still in charge


def test_second_admin_makes_the_first_removable(adm):
    adm.post(f"{BASE}/principals", json={"name": "ipad", "kind": "human-device", "admin": True})
    token = adm.post(f"{BASE}/principals/ipad/tokens", json={}).json()["token"]
    assert adm.delete(f"{BASE}/principals/matt").status_code == 200
    # the caller was removed with that request; the new admin carries on
    assert adm.get(f"{BASE}/principals", headers=bearer(token)).status_code == 200


def test_the_old_legacy_principals_and_grants_no_longer_exist(adm):
    for response in (
        adm.patch(f"{BASE}/principals/legacy-env", json={"disabled": True}),
        adm.delete(f"{BASE}/principals/legacy-env"),
        adm.post(f"{BASE}/principals/legacy-env/tokens", json={}),
        adm.post(f"{BASE}/grants", json={"principal": "legacy-env", "key": "x"}),
        adm.delete(f"{BASE}/grants/legacy:legacy-env"),
        adm.get(f"{BASE}/grants", params={"principal": "legacy-env"}),
    ):
        assert response.status_code == 404 and "not found" in response.json()["detail"].lower()


# ---------------------------------------------------------------------------
# tokens
# ---------------------------------------------------------------------------


def test_issue_token_shows_the_plaintext_once_and_it_works_at_once(adm, policy_path):
    response = adm.post(f"{BASE}/principals/lister/tokens", json={"expires": "90d", "description": "ci"})
    assert response.status_code == 201
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert set(body) == {"token", "id", "expires"}
    assert (
        re.fullmatch(r"mst_[a-z2-7]{12}_[A-Za-z0-9_-]{43}", body["token"]) and body["token"].split("_")[1] == body["id"]
    )
    delta = parse_time(body["expires"]) - datetime.now(UTC)
    assert timedelta(days=89) < delta < timedelta(days=91)
    # it authenticates right away, as that principal
    assert adm.get("/api/v1/credentials", headers=bearer(body["token"])).status_code == 200
    # never again: not in listings, not in the file
    listing = adm.get(f"{BASE}/principals/lister/tokens")
    assert body["token"] not in listing.text and body["token"].split("_", 2)[2] not in listing.text
    assert body["id"] in [t["id"] for t in listing.json()["tokens"]]
    assert body["token"].split("_", 2)[2] not in Path(policy_path).read_text()


def test_issue_token_validation(adm):
    assert adm.post(f"{BASE}/principals/lister/tokens", json={"expires": "soon"}).status_code == 400
    assert adm.post(f"{BASE}/principals/nobody/tokens", json={}).json() == {"detail": "Principal not found: nobody"}
    absolute = adm.post(f"{BASE}/principals/lister/tokens", json={"expires": "2099-01-01"})
    assert parse_time(absolute.json()["expires"]).year == 2099
    no_expiry = adm.post(f"{BASE}/principals/lister/tokens", json={})
    assert no_expiry.json()["expires"] is None


IMPORTED = "imported-client-key-" + "m" * 30


def test_import_token_keeps_an_existing_key_working_and_never_shows_it_again(adm, policy_path, log_path, caplog):
    caplog.set_level(logging.DEBUG)
    response = adm.post(
        f"{BASE}/principals/fireflyer/tokens/import",
        json={"key": IMPORTED, "description": "old Mac key", "expires": "30d"},
    )
    assert response.status_code == 201 and response.headers.get("x-policy-active") is None
    body = response.json()
    assert set(body) == {"id", "expires"} and re.fullmatch(r"[a-z2-7]{12}", body["id"])
    assert timedelta(days=29) < parse_time(body["expires"]) - datetime.now(UTC) < timedelta(days=31)
    # the old key authenticates at once, as that principal, with that principal's grants
    ok = adm.get("/api/v1/credentials/firefly.token", headers=bearer(IMPORTED))
    assert ok.status_code == 200
    assert adm.get("/api/v1/credentials/other", headers=bearer(IMPORTED)).status_code == 404
    stored = next(t for t in on_disk(policy_path).principal("fireflyer").tokens if t.id == body["id"])
    assert stored.hash.startswith("sha256:") and stored.description == "old Mac key"
    listing = adm.get(f"{BASE}/principals/fireflyer/tokens")
    assert body["id"] in [t["id"] for t in listing.json()["tokens"]]
    # the key is nowhere: not in a response, the file, the access log or the server log
    for text in (response.text, listing.text, Path(policy_path).read_text(), Path(log_path).read_text(), caplog.text):
        assert IMPORTED not in text
    records = [json.loads(line) for line in Path(log_path).read_text().splitlines()]
    assert any(r.get("route") == "admin.token.import" and r["decision"] == "allowed" for r in records)


def test_import_token_refuses_what_it_should_without_echoing_the_key(adm, policy_path, log_path, caplog):
    caplog.set_level(logging.DEBUG)
    url = f"{BASE}/principals/fireflyer/tokens/import"
    _, issued = generate_token()
    refusals = [
        ({"key": "k" * 31}, 400, "shorter than 32"),
        ({"key": " " + IMPORTED}, 400, "control or non-ASCII"),
        ({"key": issued}, 400, "mst_ token format"),
        ({"key": IMPORTED, "expires": "soon"}, 400, "cannot read"),
        ({"key": IMPORTED, "min_length": 100}, 400, "shorter than 100"),
    ]
    before = Path(policy_path).read_bytes()
    for body, code, message in refusals:
        response = adm.post(url, json=body)
        assert response.status_code == code and message in response.json()["detail"], body
        assert body["key"].strip() not in response.text
    for body, loc in (
        ({"key": "k" * 300}, ["body", "key"]),  # too long
        ({"key": IMPORTED, "min_length": 15}, ["body", "min_length"]),  # below the floor
        ({"key": IMPORTED, "extra": 1}, ["body", "extra"]),
        ({}, ["body", "key"]),
    ):
        response = adm.post(url, json=body)
        assert response.status_code == 422 and response.json()["detail"][0]["loc"] == loc
        assert IMPORTED not in response.text and "k" * 300 not in response.text
    assert Path(policy_path).read_bytes() == before
    assert adm.post(f"{BASE}/principals/nobody/tokens/import", json={"key": IMPORTED}).status_code == 404
    assert IMPORTED not in caplog.text and IMPORTED not in Path(log_path).read_text()


def test_import_token_refuses_a_key_that_is_already_a_token(adm):
    url = f"{BASE}/principals/fireflyer/tokens/import"
    assert adm.post(url, json={"key": IMPORTED}).status_code == 201
    duplicate = adm.post(f"{BASE}/principals/hermes/tokens/import", json={"key": IMPORTED})
    assert duplicate.status_code == 400 and "already held by a token" in duplicate.json()["detail"]
    assert IMPORTED not in duplicate.text


def test_import_token_uses_the_servers_minimum_key_length_unless_the_request_lowers_it(
    make_client, policy_path, policy_tokens
):
    client = make_client(POLICY_FILE=policy_path, ALLOW_WRITES=True, MIN_KEY_LENGTH=40)
    client.headers.update(bearer(policy_tokens["matt"]))
    url = f"{BASE}/principals/fireflyer/tokens/import"
    assert "shorter than 40" in client.post(url, json={"key": "k" * 39}).json()["detail"]
    assert client.post(url, json={"key": "k" * 40}).status_code == 201
    assert client.post(url, json={"key": "j" * 20, "min_length": 20}).status_code == 201
    low = make_client(POLICY_FILE=policy_path, ALLOW_WRITES=True, MIN_KEY_LENGTH=8)
    low.headers.update(bearer(policy_tokens["matt"]))
    assert "shorter than 16" in low.post(url, json={"key": "h" * 12}).json()["detail"]  # never below 16


def test_list_tokens(adm, policy_tokens):
    response = adm.get(f"{BASE}/principals/hermes/tokens")
    assert [t["id"] for t in response.json()["tokens"]] == [policy_tokens["hermes"].split("_")[1]]
    assert adm.get(f"{BASE}/principals/nobody/tokens").status_code == 404


def test_revoke_token_stops_it_working_at_once(adm, policy_tokens):
    token_id = policy_tokens["hermes"].split("_")[1]
    assert adm.get("/api/v1/credentials", headers=bearer(policy_tokens["hermes"])).status_code == 200
    response = adm.delete(f"{BASE}/principals/hermes/tokens/{token_id}")
    assert response.status_code == 200 and response.json() == {"detail": f"Token revoked: {token_id}"}
    assert adm.get("/api/v1/credentials", headers=bearer(policy_tokens["hermes"])).status_code == 401
    assert adm.delete(f"{BASE}/principals/hermes/tokens/{token_id}").json() == {
        "detail": f"Token not found: {token_id}"
    }
    assert adm.delete(f"{BASE}/principals/nobody/tokens/{token_id}").status_code == 404


def test_rotate_without_grace_retires_the_old_token_immediately(adm, policy_tokens):
    old_id = policy_tokens["hermes"].split("_")[1]
    response = adm.post(f"{BASE}/principals/hermes/tokens/{old_id}/rotate", json={})
    assert response.status_code == 201 and response.headers["cache-control"] == "no-store"
    body = response.json()
    assert set(body) == {"token", "id", "expires", "old_token_expires"}
    assert body["old_token_expires"] is None and body["id"] != old_id
    assert adm.get("/api/v1/credentials", headers=bearer(policy_tokens["hermes"])).status_code == 401
    assert adm.get("/api/v1/credentials", headers=bearer(body["token"])).status_code == 200


def test_rotate_with_grace_keeps_the_old_token_for_a_while(adm, policy_tokens):
    old_id = policy_tokens["hermes"].split("_")[1]
    response = adm.post(
        f"{BASE}/principals/hermes/tokens/{old_id}/rotate",
        json={"grace": "24h", "expires": "90d", "description": "rotated"},
    )
    body = response.json()
    assert timedelta(hours=23) < parse_time(body["old_token_expires"]) - datetime.now(UTC) < timedelta(hours=25)
    assert parse_time(body["expires"]) > datetime.now(UTC) + timedelta(days=89)
    assert adm.get("/api/v1/credentials", headers=bearer(policy_tokens["hermes"])).status_code == 200
    assert adm.get("/api/v1/credentials", headers=bearer(body["token"])).status_code == 200
    tokens = {t["id"]: t for t in adm.get(f"{BASE}/principals/hermes/tokens").json()["tokens"]}
    assert tokens[old_id]["expires"] == body["old_token_expires"] and tokens[body["id"]]["description"] == "rotated"


def test_rotate_errors(adm, policy_tokens):
    old_id = policy_tokens["hermes"].split("_")[1]
    assert adm.post(f"{BASE}/principals/hermes/tokens/{old_id}/rotate", json={"grace": "soon"}).status_code == 400
    assert adm.post(f"{BASE}/principals/hermes/tokens/{old_id}/rotate", json={"expires": "x"}).status_code == 400
    assert adm.post(f"{BASE}/principals/hermes/tokens/{old_id}/rotate", json={"grace": "2020-01-01"}).status_code == 400
    assert adm.post(f"{BASE}/principals/hermes/tokens/zzzzzzzzzzzz/rotate", json={}).json() == {
        "detail": "Token not found: zzzzzzzzzzzz"
    }
    assert adm.post(f"{BASE}/principals/nobody/tokens/{old_id}/rotate", json={}).status_code == 404


# ---------------------------------------------------------------------------
# grants
# ---------------------------------------------------------------------------


def test_list_grants_with_and_without_a_principal_filter(adm):
    everything = adm.get(f"{BASE}/grants").json()["grants"]
    assert len(everything) == 7 + len(RUNNER_PREFIXES)
    mine = adm.get(f"{BASE}/grants", params={"principal": "SCRIBE"}).json()["grants"]
    assert len(mine) == 1 and mine[0]["key"] == "app-*" and mine[0]["actions"] == ["delete", "list", "read", "write"]
    assert set(mine[0]) == {
        "id", "principal", "key", "tag", "actions", "expires", "description", "created", "expired"
    }  # fmt: skip
    assert adm.get(f"{BASE}/grants", params={"principal": "nobody"}).status_code == 404


def test_create_grant_defaults_and_takes_effect_at_once(adm, policy_tokens):
    h = bearer(policy_tokens["lister"])
    assert adm.get("/api/v1/credentials/firefly.token", headers=h).status_code == 404
    response = adm.post(f"{BASE}/grants", json={"principal": "lister", "key": "firefly.token", "description": "x"})
    assert response.status_code == 201
    grant = response.json()
    assert re.fullmatch(r"g_[0-9a-f]{8}", grant["id"]) and grant["actions"] == ["list", "read"]
    assert grant["key"] == "firefly.token" and grant["tag"] is None and grant["expired"] is False
    assert grant["expires"] is None and "legacy" not in grant and grant["principal"] == "lister"
    assert adm.get("/api/v1/credentials/firefly.token", headers=h).status_code == 200  # no TTL wait


def test_create_grant_with_a_tag_actions_and_expiry(adm, policy_tokens):
    response = adm.post(
        f"{BASE}/grants", json={"principal": "lister", "tag": "shared", "actions": ["read"], "expires": "1h"}
    )
    assert response.status_code == 201
    assert response.json()["tag"] == "shared" and response.json()["key"] is None
    assert timedelta(minutes=59) < parse_time(response.json()["expires"]) - datetime.now(UTC) < timedelta(minutes=61)
    assert adm.get("/api/v1/credentials/shared-note", headers=bearer(policy_tokens["lister"])).status_code == 200


@pytest.mark.parametrize(
    "body",
    [
        {"principal": "lister"},  # neither key nor tag
        {"principal": "lister", "key": "a", "tag": "b"},  # both
        {"principal": "lister", "key": "a*b"},
        {"principal": "lister", "key": "firefly."},  # separator without *
        {"principal": "lister", "tag": "shared", "actions": ["write"]},  # tag grants cannot write
        {"principal": "lister", "key": "x", "actions": ["admin"]},
        {"principal": "lister", "key": "x", "actions": []},
        {"principal": "lister", "key": "x", "expires": "never"},
        {"principal": "lister", "tag": "a;b"},
    ],
)
def test_create_grant_validation(adm, body):
    response = adm.post(f"{BASE}/grants", json=body)
    assert response.status_code == 400 and isinstance(response.json()["detail"], str)


def test_create_grant_for_an_unknown_principal_is_404(adm):
    assert adm.post(f"{BASE}/grants", json={"principal": "nobody", "key": "x"}).json() == {
        "detail": "Principal not found: nobody"
    }


def test_delete_grant(adm, policy_tokens):
    h = bearer(policy_tokens["fireflyer"])
    grant_id = adm.get(f"{BASE}/grants", params={"principal": "fireflyer"}).json()["grants"][0]["id"]
    assert adm.get("/api/v1/credentials/firefly.token", headers=h).status_code == 200
    response = adm.delete(f"{BASE}/grants/{grant_id}")
    assert response.status_code == 200 and response.json() == {"detail": f"Grant removed: {grant_id}"}
    assert adm.get("/api/v1/credentials/firefly.token", headers=h).status_code == 404
    assert adm.delete(f"{BASE}/grants/{grant_id}").json() == {"detail": f"Grant not found: {grant_id}"}


def test_an_expired_grant_stops_granting(adm, policy_tokens, policy_path):
    from dataclasses import replace

    from mattstash.authz import dump_policy

    h = bearer(policy_tokens["fireflyer"])
    policy = on_disk(policy_path)
    past = datetime.now(UTC) - timedelta(minutes=1)
    expired = tuple(replace(g, expires=past) if g.principal == "fireflyer" else g for g in policy.grants)
    with open(policy_path, "w") as handle:
        handle.write(dump_policy(replace(policy, grants=expired)))
    assert adm.get("/api/v1/credentials/firefly.token", headers=h).status_code == 404  # picked up by stat
    listed = adm.get(f"{BASE}/grants", params={"principal": "fireflyer"}).json()["grants"]
    assert listed[0]["expired"] is True
    assert adm.get("/api/v1/credentials", headers=h).json()["count"] == 0


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------


def test_check_explains_decisions(adm, policy_path):
    grant_id = next(g.id for g in on_disk(policy_path).grants if g.key == "firefly-mcp")
    allowed = adm.post(f"{BASE}/check", json={"principal": "hermes", "action": "read", "name": "firefly-mcp"})
    assert allowed.status_code == 200 and allowed.json() == {"allowed": True, "reason": "granted", "grant": grant_id}
    denied = adm.post(f"{BASE}/check", json={"principal": "hermes", "action": "write", "name": "firefly-mcp"})
    assert denied.json() == {"allowed": False, "reason": "no-grant", "grant": None}
    by_tag = adm.post(
        f"{BASE}/check", json={"principal": "hermes", "action": "read", "name": "zzz", "tags": ["shared"]}
    )
    assert by_tag.json()["allowed"] is True
    assert (
        adm.post(f"{BASE}/check", json={"principal": "hermes", "action": "read", "name": "zzz"}).json()["allowed"]
        is False
    )
    assert adm.post(f"{BASE}/check", json={"principal": "off", "action": "read", "name": "a"}).json() == {
        "allowed": False, "reason": "disabled", "grant": None
    }  # fmt: skip


def test_check_errors(adm):
    assert adm.post(f"{BASE}/check", json={"principal": "nobody", "action": "read", "name": "x"}).status_code == 404
    bad = adm.post(f"{BASE}/check", json={"principal": "hermes", "action": "sudo", "name": "x"})
    assert bad.status_code == 400 and "unknown action" in bad.json()["detail"]


# ---------------------------------------------------------------------------
# access log endpoint
# ---------------------------------------------------------------------------


def test_access_log_endpoint_filters(adm, policy_tokens):
    adm.get("/api/v1/credentials/firefly.token", headers=bearer(policy_tokens["hermes"]))
    adm.get("/api/v1/credentials/other", headers=bearer(policy_tokens["hermes"]))
    adm.get("/api/v1/credentials", headers={"X-API-Key": "nope"})
    everything = adm.get(f"{BASE}/access-log").json()
    assert everything["count"] == len(everything["records"]) >= 3
    hermes = adm.get(f"{BASE}/access-log", params={"principal": "hermes"}).json()["records"]
    assert [r["key"] for r in hermes] == ["firefly.token", "other"]
    assert [r["decision"] for r in hermes] == ["allowed", "denied"]
    denied = adm.get(f"{BASE}/access-log", params={"decision": "denied"}).json()["records"]
    assert {r["reason"] for r in denied} >= {"no-grant", "bad-token"}
    assert len(adm.get(f"{BASE}/access-log", params={"limit": 2}).json()["records"]) == 2
    assert adm.get(f"{BASE}/access-log", params={"since": "1h"}).json()["count"] >= 3  # "1h" means one hour AGO
    assert adm.get(f"{BASE}/access-log", params={"since": "2999-01-01"}).json() == {"records": [], "count": 0}
    assert adm.get(f"{BASE}/access-log", params={"since": "2000-01-01"}).json()["count"] >= 3
    assert adm.get(f"{BASE}/access-log", params={"since": "whenever"}).status_code == 400
    assert adm.get(f"{BASE}/access-log", params={"decision": "maybe"}).status_code == 422
    assert adm.get(f"{BASE}/access-log", params={"limit": 0}).status_code == 422
    assert adm.get(f"{BASE}/access-log", params={"limit": 1001}).status_code == 422


def test_access_log_endpoint_without_a_file_is_503(make_client, policy_path, policy_tokens):
    client = make_client(POLICY_FILE=policy_path)
    response = client.get(f"{BASE}/access-log", headers=bearer(policy_tokens["matt"]))
    assert response.status_code == 503
    assert response.json() == {"detail": "No access log file configured (MATTSTASH_ACCESS_LOG_FILE)"}


# ---------------------------------------------------------------------------
# read-only file
# ---------------------------------------------------------------------------

MUTATIONS = [
    ("POST", "/principals", {"name": "n", "kind": "agent"}),
    ("PATCH", "/principals/n", {"disabled": True}),
    ("DELETE", "/principals/n", None),
    ("POST", "/principals/n/tokens", {}),
    ("DELETE", "/principals/n/tokens/abcdefghijkl", None),
    ("POST", "/principals/n/tokens/abcdefghijkl/rotate", {}),
    ("POST", "/grants", {"principal": "n", "key": "x"}),
    ("DELETE", "/grants/g_00000000", None),
]


def test_the_default_principal_is_listed_with_its_grant_and_checked_like_any_other(client):
    principals = client.get(f"{BASE}/principals", headers=auth(FULL_KEY)).json()["principals"]
    assert [(p["name"], p["kind"], p["admin"], len(p["tokens"])) for p in principals] == [
        ("full", "human-device", True, 1)
    ]
    grants = client.get(f"{BASE}/grants", headers=auth(FULL_KEY)).json()["grants"]
    assert [(g["principal"], g["key"]) for g in grants] == [("full", "*")] and grants[0]["id"].startswith("g_")
    checked = client.post(
        f"{BASE}/check", json={"principal": "full", "action": "delete", "name": "x"}, headers=auth(FULL_KEY)
    )
    assert checked.json() == {"allowed": True, "reason": "granted", "grant": grants[0]["id"]}


@pytest.mark.parametrize(("method", "path", "body"), MUTATIONS[:1] + MUTATIONS[3:4] + MUTATIONS[6:7])
def test_a_read_only_policy_file_answers_409_and_changes_nothing(adm, monkeypatch, policy_path, method, path, body):
    import mattstash.authz.store as store

    def refuse(*args, **kwargs):
        raise OSError(errno.EROFS, "Read-only file system")

    monkeypatch.setattr(store, "_write_atomic", refuse)
    before = Path(policy_path).read_text()
    path = path.replace("/n", "/hermes").replace('"n"', '"hermes"')
    body = {**body, "principal": "hermes"} if body and "principal" in body else body
    if method == "POST" and path == "/principals":
        body = {"name": "fresh", "kind": "agent"}
    response = adm.request(method, BASE + path, json=body)
    assert response.status_code == 409 and response.json() == READ_ONLY
    assert Path(policy_path).read_text() == before


@pytest.mark.skipif(os.geteuid() == 0, reason="root can write anywhere; the mocked variant above covers the mapping")
def test_a_really_read_only_directory_answers_409(adm, policy_path):
    directory = os.path.dirname(policy_path)
    os.chmod(directory, 0o500)
    try:
        response = adm.post(f"{BASE}/principals", json={"name": "fresh", "kind": "agent"})
    finally:
        os.chmod(directory, 0o700)
    assert response.status_code == 409 and response.json() == READ_ONLY


def test_lock_failures(adm, monkeypatch):
    import app.routers.admin as admin_module

    def cannot_lock(*args, **kwargs):
        raise DatabaseLockError("Cannot create lock file /x/policy.json.lock: Permission denied")

    monkeypatch.setattr(admin_module, "edit_policy", cannot_lock)
    response = adm.post(f"{BASE}/principals", json={"name": "fresh", "kind": "agent"})
    assert response.status_code == 409 and response.json() == READ_ONLY

    def wording_is_not_the_signal(*args, **kwargs):  # the TYPE says "timeout", never the message
        raise DatabaseLockError("Timed out after 30s: but this is a plain lock error")

    monkeypatch.setattr(admin_module, "edit_policy", wording_is_not_the_signal)
    assert adm.post(f"{BASE}/principals", json={"name": "fresh", "kind": "agent"}).status_code == 409

    def busy(*args, **kwargs):
        raise DatabaseLockTimeoutError("Timed out after 30s waiting for another MattStash process to release /x.lock")

    monkeypatch.setattr(admin_module, "edit_policy", busy)
    response = adm.post(f"{BASE}/principals", json={"name": "fresh", "kind": "agent"})
    assert response.status_code == 503 and response.json() == {"detail": "Service temporarily unavailable"}
    assert response.headers["retry-after"] == "2" and "/x.lock" not in response.text


def test_a_policy_file_that_vanished_is_503_for_mutations(adm, policy_path):
    os.unlink(policy_path)
    response = adm.post(f"{BASE}/principals", json={"name": "fresh", "kind": "agent"})
    assert response.status_code == 503 and "not found" in response.json()["detail"]


def test_a_mutation_is_not_turned_into_an_error_when_only_the_reload_fails(adm, monkeypatch, caplog, policy_path):
    import app.routers.admin as admin_module

    def broken():
        raise ValueError("reload broke")

    monkeypatch.setattr(admin_module, "reload_key_policy_now", broken)
    caplog.set_level(logging.ERROR, logger="mattstash.api")
    response = adm.post(f"{BASE}/principals/lister/tokens", json={})
    assert response.status_code == 201 and response.json()["token"]  # shown once: must not be lost
    assert "Policy saved but the reload failed: ValueError" in caplog.text
    assert response.json()["token"] not in caplog.text
    assert any(t.id == response.json()["id"] for t in on_disk(policy_path).principal("lister").tokens)


def test_policy_revision_increases_with_every_change(adm, policy_path):
    before = on_disk(policy_path).revision
    adm.post(f"{BASE}/principals", json={"name": "fresh", "kind": "agent"})
    adm.post(f"{BASE}/grants", json={"principal": "fresh", "key": "x"})
    assert on_disk(policy_path).revision == before + 2


def test_admin_mutations_are_rate_limited(adm):
    codes = [adm.patch(f"{BASE}/principals/lister", json={"description": str(i)}).status_code for i in range(31)]
    assert codes[:30] == [200] * 30 and codes[30] == 429


# ---------------------------------------------------------------------------
# existing operational endpoints, now guarded by can_admin
# ---------------------------------------------------------------------------


def test_invalidate_picks_up_an_edit_made_behind_the_servers_back(adm, policy_path, policy_tokens):
    with open(policy_path) as handle:
        edited = json.loads(handle.read())
    edited["principals"] = [p for p in edited["principals"] if p["name"] != "hermes"]
    edited["grants"] = [g for g in edited["grants"] if g["principal"] != "hermes"]
    with open(policy_path, "w") as handle:
        json.dump(edited, handle)
    response = adm.post(f"{BASE}/invalidate-api-key-cache")
    assert response.status_code == 200 and response.json()["status"] == "api_key_cache_invalidated"
    assert adm.get("/api/v1/credentials", headers=bearer(policy_tokens["hermes"])).status_code == 401
    api_keys.invalidate_api_key_cache()


def test_invalidate_reports_a_broken_policy_file_and_keeps_serving(adm, policy_path):
    with open(policy_path, "w") as handle:
        handle.write("{ nope")
    response = adm.post(f"{BASE}/invalidate-api-key-cache")
    assert response.status_code == 409 and "previous keys are still active" in response.json()["detail"]
    assert adm.get(f"{BASE}/principals").status_code == 200  # the previous policy is still in force
