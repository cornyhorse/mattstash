"""Authentication and authorization over HTTP against the real app and a real database."""

import logging

import pytest

from .conftest import ADMIN_KEY, APP_KEY, FULL_KEY, READ_KEY, WRITE_KEY, auth

SECRET = "s3cr3t-value"


@pytest.fixture
def scoped(make_client, key_policy_file, seed):
    """Policy with reader / app(prefix app-) / writer / ops(admin) keys, writes enabled, data seeded."""
    seed(
        app__db={"username": "dbuser", "password": SECRET, "url": "db.internal:5432"},
        app__token={"value": "tok"},
        other={"value": "private"},
    )
    return make_client(API_KEY=None, API_KEYS_FILE=str(key_policy_file), ALLOW_WRITES=True)


# ---------------------------------------------------------------------------
# authentication
# ---------------------------------------------------------------------------


def test_missing_and_wrong_keys_get_401(client):
    for headers in ({}, auth("wrong-key"), {"X-API-Key": ""}, auth(FULL_KEY + "x")):
        response = client.get("/api/v1/credentials", headers=headers)
        assert response.status_code == 401
        assert response.json() == {"detail": "Authentication failed"}


def test_non_ascii_key_header_is_401_not_500(client):
    """compare_digest used to raise TypeError on non-ASCII str -> unauthenticated 500."""
    import asyncio

    # Raw header bytes cannot be produced through httpx; drive the ASGI app with a hand-built scope.

    async def call() -> int:
        sent: list[dict] = []

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            sent.append(message)

        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "GET",
            "path": "/api/v1/credentials",
            "raw_path": b"/api/v1/credentials",
            "query_string": b"",
            "root_path": "",
            "scheme": "http",
            "headers": [(b"x-api-key", "café".encode("latin-1")), (b"host", b"testserver")],
            "client": ("203.0.113.5", 1234),
            "server": ("testserver", 80),
            "state": {},
        }
        await client.app(scope, receive, send)
        return next(m["status"] for m in sent if m["type"] == "http.response.start")

    assert asyncio.run(call()) == 401


def test_valid_key_works(client, seed):
    seed(x={"value": "1"})
    assert client.get("/api/v1/credentials", headers=auth()).status_code == 200


def test_health_needs_no_key_but_data_endpoints_do(client):
    assert client.get("/health").status_code == 200
    for path in ("/api/v1/credentials", "/api/v1/credentials/x", "/api/v1/credentials/x/versions", "/api/v1/db-url/x"):
        assert client.get(path).status_code == 401
    assert client.post("/api/v1/admin/reload").status_code == 401
    assert client.post("/api/v1/credentials/x", json={"value": "v"}).status_code == 401
    assert client.delete("/api/v1/credentials/x").status_code == 401


def test_unauthenticated_requests_learn_nothing_about_server_mode(client):
    """Auth runs before the read-only check: an anonymous POST is 401, not 405."""
    assert client.post("/api/v1/credentials/x", json={"value": "v"}).status_code == 401


# ---------------------------------------------------------------------------
# legacy key: full access (non-breaking upgrade)
# ---------------------------------------------------------------------------


def test_legacy_key_has_full_access(rw_client):
    h = auth(FULL_KEY)
    assert rw_client.post("/api/v1/credentials/legacy-one", json={"value": "v"}, headers=h).status_code == 201
    assert rw_client.get("/api/v1/credentials/legacy-one?show_password=true", headers=h).json()["password"] == "v"
    assert rw_client.post("/api/v1/admin/invalidate-api-key-cache", headers=h).status_code == 200
    assert rw_client.delete("/api/v1/credentials/legacy-one", headers=h).status_code == 200


# ---------------------------------------------------------------------------
# scoped keys
# ---------------------------------------------------------------------------


def test_read_only_key_can_read_but_not_write_delete_or_admin(scoped):
    h = auth(READ_KEY)
    assert scoped.get("/api/v1/credentials/other?show_password=true", headers=h).json()["password"] == "private"
    assert scoped.get("/api/v1/credentials", headers=h).status_code == 200
    assert scoped.get("/api/v1/credentials/other/versions", headers=h).status_code == 200
    for response in (
        scoped.post("/api/v1/credentials/new-one", json={"value": "v"}, headers=h),
        scoped.delete("/api/v1/credentials/other", headers=h),
        scoped.post("/api/v1/admin/reload", headers=h),
        scoped.post("/api/v1/admin/invalidate-api-key-cache", headers=h),
    ):
        assert response.status_code == 403
        assert response.json() == {"detail": "Insufficient permissions"}
    assert scoped.get("/api/v1/credentials/other", headers=h).status_code == 200  # nothing was deleted


def test_prefix_scoped_key_sees_only_its_names(scoped):
    h = auth(APP_KEY)
    names = [c["name"] for c in scoped.get("/api/v1/credentials", headers=h).json()["credentials"]]
    assert sorted(names) == ["app-db", "app-token"]
    assert scoped.get("/api/v1/credentials/app-db?show_password=true", headers=h).json()["password"] == SECRET
    assert scoped.get("/api/v1/credentials/app-db/versions", headers=h).status_code == 200
    assert scoped.get("/api/v1/db-url/app-db", params={"database": "d"}, headers=h).status_code == 200


def test_out_of_scope_reads_are_indistinguishable_from_missing(scoped):
    """A scoped key must not be able to probe which names exist outside its scope."""
    h = auth(APP_KEY)
    for path in ("credentials/{}", "credentials/{}/versions", "db-url/{}"):
        forbidden = scoped.get("/api/v1/" + path.format("other"), headers=h)  # exists, out of scope
        missing = scoped.get("/api/v1/" + path.format("nonexistent"), headers=h)  # does not exist at all
        assert forbidden.status_code == missing.status_code == 404
        assert forbidden.json()["detail"].replace("other", "X") == missing.json()["detail"].replace("nonexistent", "X")
        assert forbidden.headers.get("content-type") == missing.headers.get("content-type")


def test_prefix_scoped_key_cannot_write_or_delete_outside_scope(scoped):
    h = auth(APP_KEY)
    assert scoped.post("/api/v1/credentials/app-new", json={"value": "v"}, headers=h).status_code == 201
    assert scoped.post("/api/v1/credentials/other", json={"value": "pwned"}, headers=h).status_code == 403
    assert scoped.delete("/api/v1/credentials/other", headers=h).status_code == 403
    assert scoped.delete("/api/v1/credentials/app-new", headers=h).status_code == 200
    # the out-of-scope secret is untouched
    full = auth(FULL_KEY)  # not valid in this policy:
    assert scoped.get("/api/v1/credentials/other", headers=full).status_code == 401
    assert (
        scoped.get("/api/v1/credentials/other?show_password=true", headers=auth(READ_KEY)).json()["password"]
        == "private"
    )


def test_prefix_filter_cannot_widen_scope(scoped):
    h = auth(APP_KEY)
    assert scoped.get("/api/v1/credentials", params={"prefix": "oth"}, headers=h).json()["count"] == 0
    assert scoped.get("/api/v1/credentials", params={"prefix": "app-t"}, headers=h).json()["count"] == 1


def test_write_key_cannot_delete_and_delete_key_scopes_apply(scoped):
    h = auth(WRITE_KEY)
    assert scoped.post("/api/v1/credentials/anything", json={"value": "v"}, headers=h).status_code == 201
    assert scoped.delete("/api/v1/credentials/anything", headers=h).status_code == 403


def test_admin_key_only_does_admin(scoped):
    h = auth(ADMIN_KEY)
    assert scoped.post("/api/v1/admin/reload", headers=h).status_code == 200
    assert scoped.get("/api/v1/credentials", headers=h).status_code == 403


def test_unknown_key_in_a_scoped_policy_is_401(scoped):
    assert scoped.get("/api/v1/credentials", headers=auth(FULL_KEY)).status_code == 401


# ---------------------------------------------------------------------------
# rotation through the admin API
# ---------------------------------------------------------------------------


def test_key_rotation_without_restart(make_client, tmp_path, seed):
    seed(x={"value": "1"})
    keys = tmp_path / "keys.txt"
    keys.write_text("o" * 40 + "\n")
    client = make_client(API_KEY=None, API_KEYS_FILE=str(keys))
    old, new = {"X-API-Key": "o" * 40}, {"X-API-Key": "n" * 40}
    assert client.get("/api/v1/credentials", headers=old).status_code == 200

    keys.write_text("o" * 40 + "\n" + "n" * 40 + "\n")  # add a key, keep the old one while clients migrate
    client.post("/api/v1/admin/invalidate-api-key-cache", headers=old)
    assert client.get("/api/v1/credentials", headers=new).status_code == 200

    keys.write_text("n" * 40 + "\n")  # revoke the old key
    client.post("/api/v1/admin/invalidate-api-key-cache", headers=new)
    assert client.get("/api/v1/credentials", headers=old).status_code == 401
    assert client.get("/api/v1/credentials", headers=new).status_code == 200


# ---------------------------------------------------------------------------
# audit trail
# ---------------------------------------------------------------------------


def test_audit_log_names_the_key_id_and_never_the_key_or_secret(scoped, caplog):
    caplog.set_level(logging.INFO)
    scoped.get("/api/v1/credentials/app-db?show_password=true", headers=auth(APP_KEY))
    scoped.post("/api/v1/credentials/app-new", json={"value": "write-secret-xyz"}, headers=auth(APP_KEY))
    scoped.delete("/api/v1/credentials/app-new", headers=auth(APP_KEY))
    scoped.get("/api/v1/credentials/other", headers=auth(READ_KEY))

    audit = [r.getMessage() for r in caplog.records if r.name == "mattstash.audit"]
    assert any("key=app" in m and "action=get" in m and "name=app-db" in m and "reveal=True" in m for m in audit)
    assert any(
        "key=app" in m and "action=put" in m and "name=app-new" in m and "version=0000000001" in m for m in audit
    )
    assert any("key=app" in m and "action=delete" in m and "name=app-new" in m for m in audit)
    assert any("key=reader" in m and "name=other" in m for m in audit)

    everything = caplog.text
    for secret in (APP_KEY, READ_KEY, SECRET, "write-secret-xyz", "tok", "private"):
        assert secret not in everything.replace("action=", ""), f"{secret!r} leaked into logs"


def test_access_log_carries_key_id_and_status_but_not_query_string(scoped, caplog):
    caplog.set_level(logging.INFO, logger="mattstash.api")
    scoped.get("/api/v1/credentials/app-db?show_password=true", headers=auth(APP_KEY))
    line = next(r.getMessage() for r in caplog.records if r.getMessage().startswith("GET /api/v1/credentials/app-db"))
    assert "-> 200" in line and "key=app" in line and "show_password" not in line


def test_failed_auth_is_logged_with_client_but_without_the_presented_key(client, caplog):
    caplog.set_level(logging.INFO, logger="mattstash.api")
    client.get("/api/v1/credentials", headers=auth("definitely-not-valid-key"))
    text = caplog.text
    assert "-> 401" in text and "key=-" in text and "definitely-not-valid-key" not in text
