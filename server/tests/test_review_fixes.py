"""Regression tests for the second review of the principals/grants server (admin API, access log, v1 scope)."""

import asyncio
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from mattstash import MattStash
from mattstash.authz import Policy, edit_policy, load_policy
from starlette.testclient import TestClient

from app import accesslog
from app.main import create_app
from app.security import api_keys

from .conftest import DB_PASSWORD, FULL_KEY, auth

BASE = "/api/v1/admin"
NOT_ACTIVE = (
    "Saved to the policy file but NOT active: the server could not reload its key sources (see the server log). "
    "The previous policy is still in force."
)
UNAVAILABLE = {"detail": "Service temporarily unavailable"}


def bearer(token: str) -> dict[str, str]:
    return auth(token)


def token_id(token: str) -> str:
    return token.split("_")[1]


def records(path) -> list[dict]:
    return [json.loads(line) for line in Path(path).read_text().splitlines()]


@pytest.fixture
def log_path(tmp_path) -> str:
    return str(tmp_path / "access.jsonl")


@pytest.fixture
def lc(make_client, policy_path, policy_tokens, log_path, data):
    """Client acting as ``matt`` (admin) against the policy file; writes on; a file sink."""
    client = make_client(POLICY_FILE=policy_path, ACCESS_LOG_FILE=log_path, ALLOW_WRITES=True)
    client.headers.update(bearer(policy_tokens["matt"]))
    return client


# ---------------------------------------------------------------------------
# a mutation whose reload fails: security-reducing ones are 409, the rest are flagged
# ---------------------------------------------------------------------------


@pytest.fixture
def broken(make_client, policy_path, policy_tokens, data, monkeypatch):
    """Client whose policy file cannot be loaded AFTER startup (an I/O error, a race with another writer), so every
    reload fails but the server keeps serving the previous policy. ``matt`` administers; a spare admin and a grant
    exist to remove. The check before saving still passes (it needs no I/O): only the reload afterwards fails."""
    with edit_policy(policy_path) as ed:
        ed.add_principal("deputy", "human-device", admin=True)
        ed.issue_token("deputy")
    client = make_client(POLICY_FILE=policy_path, ALLOW_WRITES=True)
    client.headers.update(bearer(policy_tokens["matt"]))

    def unreadable():
        raise OSError("input/output error")

    monkeypatch.setattr(api_keys, "load_auth_state", unreadable)
    return client


def grant_of(policy_path, principal: str) -> str:
    return next(g.id for g in load_policy(policy_path).grants if g.principal == principal)


def test_a_healthy_mutation_has_no_warning(lc):
    response = lc.post(f"{BASE}/principals", json={"name": "fresh", "kind": "agent"})
    assert response.status_code == 201 and "warning" not in response.json()
    assert "x-policy-active" not in response.headers


@pytest.mark.parametrize(
    "request_for",
    [
        lambda t, p: ("DELETE", f"/principals/hermes/tokens/{token_id(t['hermes'])}", None),
        lambda t, p: ("PATCH", "/principals/hermes", {"disabled": True}),
        lambda t, p: ("DELETE", "/principals/hermes", None),
        lambda t, p: ("PATCH", "/principals/deputy", {"admin": False}),
        lambda t, p: ("DELETE", f"/grants/{grant_of(p, 'hermes')}", None),
    ],
    ids=["revoke", "disable", "remove-principal", "admin-false", "remove-grant"],
)
def test_a_security_reducing_change_that_cannot_be_activated_is_409(broken, policy_path, policy_tokens, request_for):
    method, path, body = request_for(policy_tokens, policy_path)
    before = Path(policy_path).read_text()
    response = broken.request(method, BASE + path, json=body)
    assert response.status_code == 409
    assert response.json() == {"detail": NOT_ACTIVE}  # exactly: no token, no half-success body
    assert Path(policy_path).read_text() != before  # it IS saved ...
    # ... and the previous policy is still in force: the "revoked" token still works
    assert broken.get("/api/v1/credentials", headers=bearer(policy_tokens["hermes"])).status_code == 200


@pytest.mark.parametrize(
    ("method", "path", "body", "code"),
    [
        ("POST", "/principals", {"name": "fresh", "kind": "agent"}, 201),
        ("PATCH", "/principals/off", {"disabled": False}, 200),
        ("PATCH", "/principals/hermes", {"description": "renamed"}, 200),
        ("POST", "/principals/lister/tokens", {}, 201),
        ("POST", "/principals/hermes/tokens/{hermes}/rotate", {}, 201),
        ("POST", "/grants", {"principal": "lister", "key": "extra-*"}, 201),
    ],
)
def test_other_changes_that_cannot_be_activated_succeed_with_a_warning(broken, policy_tokens, method, path, body, code):
    path = path.format(hermes=token_id(policy_tokens["hermes"]))
    response = broken.request(method, BASE + path, json=body)
    assert response.status_code == code
    assert response.json()["warning"] == NOT_ACTIVE
    assert response.headers["x-policy-active"] == "false"
    if path.endswith(("/tokens", "/rotate")):  # the token is shown once and must not be lost with the warning
        assert response.json()["token"].startswith("mst_")
        assert response.headers["cache-control"] == "no-store"


def test_a_mixed_patch_that_reduces_access_is_409(broken, policy_path):
    response = broken.patch(f"{BASE}/principals/deputy", json={"admin": False, "description": "x"})
    assert response.status_code == 409 and response.json() == {"detail": NOT_ACTIVE}


# ---------------------------------------------------------------------------
# an admin edit can never produce a policy the server refuses to load
# ---------------------------------------------------------------------------


CANNOT_LOAD = "The change would leave a policy the server cannot load: "

CHANGES = [
    ("POST", "/principals", {"name": "fresh", "kind": "agent"}),
    ("PATCH", "/principals/hermes", {"description": "renamed"}),
    ("DELETE", "/principals/hermes", None),
    ("POST", "/principals/lister/tokens", {}),
    ("DELETE", "/principals/hermes/tokens/{hermes}", None),
    ("POST", "/principals/hermes/tokens/{hermes}/rotate", {}),
    ("POST", "/principals/lister/tokens/import", {"key": "i" * 40}),
    ("POST", "/grants", {"principal": "lister", "key": "extra-*"}),
    ("DELETE", "/grants/{grant}", None),
]


@pytest.mark.parametrize(("method", "path", "body"), CHANGES, ids=[f"{m} {p}" for m, p, _ in CHANGES])
def test_a_change_the_server_could_not_load_is_refused_before_anything_is_saved(
    lc, monkeypatch, policy_path, policy_tokens, method, path, body
):
    """Check-then-save: the merged state is built from the EDITED policy inside the edit, before the editor saves."""
    import app.routers.admin as admin_module

    seen = []

    def refuse(policy, signature):
        seen.append(policy)
        raise ValueError("no usable credential (test)")

    monkeypatch.setattr(admin_module, "build_auth_state", refuse)
    before_bytes, before = Path(policy_path).read_bytes(), load_policy(policy_path)
    path = path.format(hermes=token_id(policy_tokens["hermes"]), grant=grant_of(policy_path, "hermes"))
    response = lc.request(method, BASE + path, json=body)
    assert response.status_code == 409
    assert response.json() == {"detail": CANNOT_LOAD + "no usable credential (test)"}
    assert Path(policy_path).read_bytes() == before_bytes  # nothing saved: not even the revision moved
    assert load_policy(policy_path).revision == before.revision
    assert len(seen) == 1 and seen[0] != before  # the check saw the policy the change would have produced
    assert "mst_" not in response.text  # a token that was never saved is never shown
    assert lc.get(f"{BASE}/principals").status_code == 200  # the running policy is untouched too


def test_a_healthy_change_passes_the_check_and_is_saved(lc, monkeypatch, policy_path):
    import app.routers.admin as admin_module

    seen = []
    real = admin_module.build_auth_state
    monkeypatch.setattr(admin_module, "build_auth_state", lambda p, s: seen.append(p) or real(p, s))
    response = lc.post(f"{BASE}/principals", json={"name": "fresh", "kind": "agent"})
    assert response.status_code == 201 and "warning" not in response.json()
    assert seen and seen[0].principal("fresh") is not None
    assert load_policy(policy_path).principal("fresh") is not None


def test_the_check_runs_the_loaders_own_rules(lc, policy_path):
    """No request can ask for a policy without a usable credential: the library's lockout rule stops the obvious
    ways first (400), and what is left is the loader's own refusal (409), which `build_auth_state` raises."""
    from app.security.api_keys import build_auth_state

    edited = load_policy(policy_path)
    with pytest.raises(ValueError, match="no usable credential"):
        build_auth_state(Policy(), None)
    assert build_auth_state(edited, None).credential_count >= 1


# ---------------------------------------------------------------------------
# fail closed: a state-changing request whose access line cannot be written changes nothing
# ---------------------------------------------------------------------------


@pytest.fixture
def full_disk(monkeypatch):
    def write(self, line):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(accesslog.FileSink, "write", write)


def library(db_path) -> MattStash:
    return MattStash(path=str(db_path), password=DB_PASSWORD)


def test_a_credential_write_is_refused_before_it_happens(lc, policy_tokens, full_disk, db_path):
    scribe = bearer(policy_tokens["scribe"])
    response = lc.post("/api/v1/credentials/app-new", json={"value": "v"}, headers=scribe)
    assert response.status_code == 503 and response.json() == UNAVAILABLE
    assert library(db_path).get("app-new") is None  # nothing was created


def test_a_credential_delete_is_refused_before_it_happens(lc, policy_tokens, full_disk, db_path):
    response = lc.delete("/api/v1/credentials/app-db", headers=bearer(policy_tokens["scribe"]))
    assert response.status_code == 503 and response.json() == UNAVAILABLE
    assert library(db_path).get("app-db") is not None


def test_a_denied_write_whose_line_cannot_be_written_is_still_refused(lc, policy_tokens, full_disk):
    response = lc.post("/api/v1/credentials/other", json={"value": "v"}, headers=bearer(policy_tokens["hermes"]))
    assert response.status_code == 503  # not a bare 403: the decision itself could not be recorded


ADMIN_MUTATIONS = [
    ("POST", "/principals", {"name": "fresh", "kind": "agent"}),
    ("PATCH", "/principals/hermes", {"disabled": True}),
    ("DELETE", "/principals/hermes", None),
    ("POST", "/principals/hermes/tokens", {}),
    ("POST", "/principals/lister/tokens/aaaaaaaaaaaa/rotate", {}),
    ("DELETE", "/principals/lister/tokens/aaaaaaaaaaaa", None),
    ("POST", "/grants", {"principal": "hermes", "key": "all-*"}),
    ("DELETE", "/grants/g_00000000", None),
]


@pytest.mark.parametrize(("method", "path", "body"), ADMIN_MUTATIONS)
def test_an_admin_mutation_is_refused_before_it_happens(lc, policy_path, full_disk, method, path, body):
    before = Path(policy_path).read_bytes()
    response = lc.request(method, BASE + path, json=body)
    assert response.status_code == 503 and response.json() == UNAVAILABLE
    assert Path(policy_path).read_bytes() == before  # no principal, no token, no grant: not even a revision bump


def test_a_token_rotation_that_cannot_be_logged_mints_no_token(lc, policy_path, policy_tokens, full_disk):
    before = Path(policy_path).read_bytes()
    tid = token_id(policy_tokens["hermes"])
    response = lc.post(f"{BASE}/principals/hermes/tokens/{tid}/rotate", json={"grace": "1h"})
    assert response.status_code == 503 and "token" not in response.text
    assert Path(policy_path).read_bytes() == before


def test_reads_still_fail_closed_before_any_byte(lc, policy_tokens, full_disk):
    response = lc.get("/api/v1/credentials/firefly.token?show_password=true", headers=bearer(policy_tokens["hermes"]))
    assert response.status_code == 503 and "ff-secret" not in response.text


def test_each_request_is_exactly_one_line_and_write_lines_have_no_status(lc, log_path, policy_tokens):
    scribe = bearer(policy_tokens["scribe"])
    lc.post("/api/v1/credentials/app-new", json={"value": "v"}, headers=scribe)  # 201
    lc.delete("/api/v1/credentials/app-new", headers=scribe)  # 200
    lc.delete("/api/v1/credentials/app-new", headers=scribe)  # 404: decided (allowed) before it was found missing
    lc.post("/api/v1/credentials/other", json={"value": "v"}, headers=scribe)  # 403
    lc.post(f"{BASE}/principals", json={"name": "fresh", "kind": "agent"})  # 201
    lc.post(f"{BASE}/principals", json={"name": "fresh", "kind": "agent"})  # 400, after the decision
    lines = records(log_path)
    assert len(lines) == 6
    assert all("status" not in line and line["decision"] in ("allowed", "denied") for line in lines)
    assert [line["decision"] for line in lines] == ["allowed"] * 3 + ["denied"] + ["allowed"] * 2


def test_requests_rejected_before_a_decision_keep_their_status_and_have_no_decision(
    make_client, policy_path, policy_tokens, log_path, data
):
    ro = make_client(POLICY_FILE=policy_path, ACCESS_LOG_FILE=log_path)  # read-only server
    scribe = bearer(policy_tokens["scribe"])
    ro.post("/api/v1/credentials/app-new", json={"value": "v"}, headers=scribe)  # 405
    ro.post("/api/v1/credentials/bad name!", json={"value": "v"}, headers=scribe)  # read-only is checked first: 405
    ro.get("/api/v1/credentials", headers={"X-API-Key": "wrong"})  # 401
    ro.get("/api/v1/nope", headers=scribe)  # no such route
    lines = records(log_path)
    assert len(lines) == 4
    # these keep the status that was sent; only the failed login carries a decision (denied: it IS one)
    assert [(line["status"], line.get("decision")) for line in lines] == [
        (405, None),
        (405, None),
        (401, "denied"),
        (404, None),
    ]


def test_an_invalid_body_for_a_write_is_one_line_with_the_422(lc, log_path, policy_tokens):
    lc.post("/api/v1/credentials/app-new", json={"username": 5}, headers=bearer(policy_tokens["scribe"]))
    (line,) = records(log_path)
    assert line["status"] == 422 and "decision" not in line


# ---------------------------------------------------------------------------
# what the access log says about admin calls and revealed values
# ---------------------------------------------------------------------------


def test_admin_lines_name_the_token_grant_and_actions(lc, log_path, policy_tokens, policy_path):
    hermes_old = token_id(policy_tokens["hermes"])
    rotated = lc.post(f"{BASE}/principals/hermes/tokens/{hermes_old}/rotate", json={"grace": "1h"}).json()
    issued = lc.post(f"{BASE}/principals/lister/tokens", json={"expires": "7d"}).json()
    lc.delete(f"{BASE}/principals/hermes/tokens/{rotated['id']}")
    grant = lc.post(f"{BASE}/grants", json={"principal": "lister", "key": "pre-*", "actions": ["read", "list"]}).json()
    tag_grant = lc.post(f"{BASE}/grants", json={"principal": "lister", "tag": "shared"}).json()
    lc.delete(f"{BASE}/grants/{grant['id']}")
    rotate, issue, revoke, add_key, add_tag, remove = records(log_path)
    assert (rotate["route"], rotate["key"], rotate["target_token"]) == ("admin.token.rotate", "hermes", hermes_old)
    assert (revoke["route"], revoke["key"], revoke["target_token"]) == ("admin.token.revoke", "hermes", rotated["id"])
    assert issue["route"] == "admin.token.issue" and issue["key"] == "lister" and "target_token" not in issue
    assert issued["id"] not in json.dumps(issue)  # the new id is in the response only
    assert (add_key["route"], add_key["key"], add_key["grant_key"], add_key["actions"]) == (
        "admin.grant.add",
        "lister",
        "pre-*",
        "read,list",
    )
    assert "grant_tag" not in add_key
    assert add_tag["grant_tag"] == "shared" and "actions" not in add_tag  # none given: the server's default applies
    assert "grant_key" not in add_tag
    assert (remove["route"], remove["key"]) == ("admin.grant.remove", grant["id"])
    assert tag_grant["tag"] == "shared"
    text = Path(log_path).read_text()
    for secret in (rotated["token"], issued["token"]):
        assert secret not in text
    assert token_id(policy_tokens["matt"]) in text  # the caller's own token id is the `token` field


def test_a_new_principal_is_logged_by_its_name(lc, log_path):
    lc.post(f"{BASE}/principals", json={"name": "fresh", "kind": "agent"})
    lc.post(f"{BASE}/check", json={"principal": "hermes", "action": "read", "name": "x"})
    add, check = records(log_path)
    assert (add["key"], check["key"]) == ("fresh", "hermes")


def test_a_malformed_admin_body_logs_the_decision_without_inventing_fields(lc, log_path):
    for content in (b"{bad", b"[1, 2]", json.dumps({"principal": 5, "key": ["x"], "actions": "list"}).encode()):
        response = lc.post(f"{BASE}/grants", content=content, headers={"content-type": "application/json"})
        assert response.status_code == 422
    unparsable, wrong_shape, wrong_types = records(log_path)
    # JSON that cannot be parsed is rejected before any decision: its status is logged, there is no decision
    assert unparsable["status"] == 422 and "decision" not in unparsable
    # otherwise the line records the decision, which is all that exists when it is written (no status, no target)
    for line in (wrong_shape, wrong_types):
        assert line["decision"] == "allowed" and "status" not in line
        assert not {"key", "grant_key", "grant_tag", "actions"} & set(line)


def test_revealed_values_and_requested_versions_are_logged(lc, log_path, policy_tokens):
    runner = bearer(policy_tokens["runner"])
    lc.get("/api/v1/credentials/firefly.token?show_password=true", headers=runner)
    lc.get("/api/v1/credentials/firefly.token", headers=runner)
    lc.get("/api/v1/credentials/firefly.token?show_password=true&version=1", headers=runner)
    lc.get("/api/v1/credentials/missing-zzz?show_password=true", headers=runner)  # nothing was revealed
    lc.get("/api/v1/credentials?show_password=true", headers=runner)
    lc.get("/api/v1/credentials", headers=runner)
    lc.get("/api/v1/db-url/firefly.db?mask_password=false&database=d", headers=runner)
    lc.get("/api/v1/db-url/firefly.db?database=d", headers=runner)
    shown, masked, versioned, miss, listed, listed_masked, url_open, url_masked = records(log_path)
    assert shown["reveal"] is True and "version" not in shown
    assert "reveal" not in masked
    assert (versioned["reveal"], versioned["version"]) == (True, 1)
    assert miss["status"] == 404 and "reveal" not in miss
    assert listed["reveal"] is True and "reveal" not in listed_masked
    assert url_open["reveal"] is True and "reveal" not in url_masked


def test_version_zero_is_logged_as_requested(lc, log_path, policy_tokens):
    lc.get("/api/v1/credentials/firefly.token?version=0", headers=bearer(policy_tokens["runner"]))
    assert records(log_path)[0]["version"] == 0


# ---------------------------------------------------------------------------
# small fixes
# ---------------------------------------------------------------------------


def test_token_issue_and_rotate_accept_a_missing_body(lc, policy_tokens):
    issued = lc.post(f"{BASE}/principals/lister/tokens")
    assert issued.status_code == 201 and issued.json()["expires"] is None
    rotated = lc.post(f"{BASE}/principals/hermes/tokens/{token_id(policy_tokens['hermes'])}/rotate")
    assert rotated.status_code == 201 and rotated.json()["old_token_expires"] is None  # grace 0: removed at once


@pytest.mark.parametrize("grace", ["2099-01-01", "2099-01-01T00:00:00Z", "tomorrow", "999999w", "-1h", "1.5h"])
def test_rotate_grace_must_be_a_relative_duration(lc, policy_tokens, policy_path, grace):
    before = Path(policy_path).read_bytes()
    response = lc.post(
        f"{BASE}/principals/hermes/tokens/{token_id(policy_tokens['hermes'])}/rotate", json={"grace": grace}
    )
    assert response.status_code == 400, grace
    assert "token" not in response.text
    assert Path(policy_path).read_bytes() == before


def test_rotate_with_a_relative_grace_keeps_the_old_token_for_that_long(lc, policy_tokens):
    response = lc.post(
        f"{BASE}/principals/hermes/tokens/{token_id(policy_tokens['hermes'])}/rotate", json={"grace": "2h"}
    )
    expires = datetime.fromisoformat(response.json()["old_token_expires"].replace("Z", "+00:00"))
    assert 7000 < (expires - datetime.now(UTC)).total_seconds() <= 7200


@pytest.mark.parametrize("expires", ["2000-01-01", "2020-01-01T00:00:00Z"])
def test_a_grant_that_has_already_expired_is_refused(lc, policy_path, expires):
    before = Path(policy_path).read_bytes()
    response = lc.post(f"{BASE}/grants", json={"principal": "hermes", "key": "x", "expires": expires})
    assert response.status_code == 400 and "must be in the future" in response.json()["detail"]
    assert Path(policy_path).read_bytes() == before
    assert lc.post(f"{BASE}/grants", json={"principal": "hermes", "key": "x", "expires": "1d"}).status_code == 201


def test_empty_query_values_are_treated_as_absent(lc, log_path, policy_tokens):
    lc.get("/api/v1/credentials", headers=bearer(policy_tokens["hermes"]))  # something to find in the log
    plain = lc.get(f"{BASE}/access-log").json()
    assert plain["count"] >= 1
    empty = lc.get(f"{BASE}/access-log", params={"principal": "", "decision": "", "since": ""})
    assert empty.status_code == 200
    assert [r["route"] for r in empty.json()["records"]][: plain["count"]] == [r["route"] for r in plain["records"]]
    assert lc.get(f"{BASE}/access-log", params={"principal": "hermes", "decision": "allowed"}).json()["count"] == 1
    assert lc.get(f"{BASE}/access-log", params={"decision": "maybe"}).status_code == 422
    all_grants = lc.get(f"{BASE}/grants").json()
    assert lc.get(f"{BASE}/grants", params={"principal": ""}).json() == all_grants
    assert len(all_grants["grants"]) > 3


def test_since_accepts_durations_and_dates_and_rejects_the_unreadable(lc, policy_tokens):
    lc.get("/api/v1/credentials", headers=bearer(policy_tokens["hermes"]))
    assert lc.get(f"{BASE}/access-log", params={"since": "1h"}).json()["count"] >= 1
    assert lc.get(f"{BASE}/access-log", params={"since": "2000-01-01"}).json()["count"] >= 1
    assert lc.get(f"{BASE}/access-log", params={"since": "2999-01-01"}).json()["count"] == 0
    for bad in ("soon", "999999w"):
        assert lc.get(f"{BASE}/access-log", params={"since": bad}).status_code == 400, bad


def test_search_evaluates_with_one_clock(lc, policy_tokens, monkeypatch):
    import app.routers.credentials as credentials

    seen = []
    real = credentials.visible

    def spy(*args, **kwargs):
        seen.append(args[4:] or kwargs.get("now"))
        return real(*args, **kwargs)

    monkeypatch.setattr(credentials, "visible", spy)
    assert lc.get("/api/v1/search?q=fire", headers=bearer(policy_tokens["runner"])).status_code == 200
    assert seen and all(seen)  # `now` was passed explicitly


def test_the_tag_check_does_not_list_the_vault(lc, policy_tokens, monkeypatch):
    def forbidden(self, *args, **kwargs):
        raise AssertionError("the whole vault was listed to find one entry's tags")

    monkeypatch.setattr(MattStash, "list", forbidden)
    hermes = bearer(policy_tokens["hermes"])
    assert lc.get("/api/v1/credentials/shared-note?show_password=true", headers=hermes).json()["password"] == (
        "tagged-secret"
    )  # allowed by the tag `shared`, which the password-only entry carries
    assert lc.get("/api/v1/credentials/other", headers=hermes).status_code == 404  # untagged: no tag grant matches
    assert lc.get("/api/v1/credentials/demoted", headers=hermes).status_code == 404  # the latest version decides
    assert lc.get("/api/v1/credentials/retag", headers=hermes).status_code == 200


def test_a_client_that_goes_away_is_logged_without_a_made_up_status(make_client, log_path, db_path):
    client = make_client(ACCESS_LOG_FILE=log_path)
    application = client.app

    @application.get("/api/v1/slow")
    async def slow() -> dict[str, str]:
        await asyncio.sleep(30)
        return {}  # pragma: no cover

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "path": "/api/v1/slow",
        "raw_path": b"/api/v1/slow",
        "query_string": b"",
        "headers": [(b"x-api-key", FULL_KEY.encode())],
        "client": ("127.0.0.1", 5555),
        "server": ("testserver", 80),
        "state": {},
        "app": application,
    }
    sent = []

    async def drive() -> None:
        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            sent.append(message)

        task = asyncio.ensure_future(application(scope, receive, send))
        await asyncio.sleep(0.3)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(drive())
    assert sent == []  # nothing was answered
    (line,) = records(log_path)
    assert line["error"] == "client-disconnected" and "status" not in line
    assert line["principal"] == "full"


def test_the_log_file_is_closed_when_startup_fails_after_opening_it(configure, log_path, db_path):
    configure(ACCESS_LOG_FILE=log_path, KDBX_PASSWORD="not-the-password")  # opens the sink, then cannot open the DB
    with pytest.raises(Exception):  # noqa: B017 - whatever the library raises for a wrong password
        with TestClient(create_app()):
            pass  # pragma: no cover
    assert accesslog._sink is None


# ---------------------------------------------------------------------------
# migrated v1 keys without `read` (200-empty / 404, as they have been since principals and grants)
# ---------------------------------------------------------------------------


@pytest.fixture
def no_read_client(make_client, tmp_path, data):
    keys = {
        "keys": [
            {"id": "writeonly", "key_sha256": hashlib.sha256(b"w" * 40).hexdigest(), "ops": ["write"]},
            {"id": "adminonly", "key_sha256": hashlib.sha256(b"a" * 40).hexdigest(), "ops": ["admin"]},
        ]
    }
    with edit_policy(tmp_path / "migrated.json", create=True) as ed:
        ed.import_v1(json.dumps(keys), 32, "human-device")  # no prefixes: the write-only key needs '*'
    return make_client(POLICY_FILE=str(tmp_path / "migrated.json"), ALLOW_WRITES=True)


@pytest.mark.parametrize("key", ["w" * 40, "a" * 40])
def test_a_v1_key_without_read_sees_an_empty_list_and_not_found(no_read_client, key):
    headers = auth(key)
    listed = no_read_client.get("/api/v1/credentials", headers=headers)
    assert listed.status_code == 200 and listed.json() == {"credentials": [], "count": 0}
    missing = {"detail": "Credential not found: app-db"}
    for path in ("/credentials/app-db", "/credentials/app-db/versions"):
        response = no_read_client.get("/api/v1" + path, headers=headers)
        assert (response.status_code, response.json()) == (404, missing), path
    url = no_read_client.get("/api/v1/db-url/app-db", headers=headers)
    assert (url.status_code, url.json()) == (404, {"detail": "Credential not found or unsuitable: app-db"})
    search = no_read_client.get("/api/v1/search?q=app", headers=headers)
    assert search.json() == {"results": [], "count": 0}
