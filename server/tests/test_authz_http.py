"""Authentication and authorization over HTTP against the real app and a real database, route by route.

Every route is covered for: allowed, denied (a denied read must be byte-for-byte what a missing name answers), and each
kind of legacy key (env key, plain keys file, v1 JSON policy).
"""

import json
from pathlib import Path

import pytest

from .conftest import ADMIN_KEY, APP_KEY, FULL_KEY, READ_KEY, WRITE_KEY, auth


def bearer(token: str) -> dict[str, str]:
    return auth(token)


@pytest.fixture
def pc(make_client, policy_path, data):
    """Client for the v2 policy file, writes enabled."""
    return make_client(API_KEY=None, POLICY_FILE=policy_path, ALLOW_WRITES=True)


@pytest.fixture
def pro(make_client, policy_path, data):
    """Same, read-only server."""
    return make_client(API_KEY=None, POLICY_FILE=policy_path)


@pytest.fixture
def legacy(make_client, tmp_path, key_policy_file, data):
    """``legacy("env" | "plain" | "v1")``: a client for one kind of legacy key source (one at a time: the server
    configuration is process-wide, so the cached key state is dropped when switching)."""
    from app.security import api_keys

    plain = tmp_path / "plain.txt"
    plain.write_text("# plain list\n" + "p" * 40 + "\n")

    def _client(kind: str):
        api_keys._state = None
        sources = {
            "env": {"API_KEY": FULL_KEY},
            "plain": {"API_KEY": None, "API_KEYS_FILE": str(plain)},
            "v1": {"API_KEY": None, "API_KEYS_FILE": str(key_policy_file)},
        }
        return make_client(ALLOW_WRITES=True, **sources[kind])

    return _client


PLAIN = "p" * 40


def names(response) -> list[str]:
    return sorted(c["name"] for c in response.json()["credentials"])


def same_as_missing(client, headers, template: str, existing: str, missing: str = "nonexistent-zzz"):
    """A denied-but-existing name must answer exactly what a missing name answers (status, headers, body)."""
    denied = client.get(template.format(existing), headers=headers)
    absent = client.get(template.format(missing), headers=headers)
    assert denied.status_code == absent.status_code == 404
    assert denied.headers["content-type"] == absent.headers["content-type"]
    assert denied.headers["cache-control"] == absent.headers["cache-control"]
    assert denied.text.replace(existing, "X") == absent.text.replace(missing, "X")
    return denied


# ---------------------------------------------------------------------------
# authentication
# ---------------------------------------------------------------------------


def test_missing_and_wrong_keys_get_401(client):
    for headers in ({}, auth("wrong-key"), {"X-API-Key": ""}, auth(FULL_KEY + "x")):
        response = client.get("/api/v1/credentials", headers=headers)
        assert response.status_code == 401
        assert response.json() == {"detail": "Authentication failed"}


def test_every_failure_kind_answers_the_same_401(pc, policy_tokens):
    from mattstash.authz import generate_token

    bodies = set()
    for token in (
        None,
        generate_token()[1],  # unknown id
        policy_tokens["hermes"][:-2] + "xx",  # wrong secret
        policy_tokens["expired"],
        policy_tokens["off"],  # disabled principal
        "mst_garbage",
    ):
        response = pc.get("/api/v1/credentials", headers=bearer(token) if token else {})
        assert response.status_code == 401
        bodies.add(response.text)
    assert bodies == {'{"detail":"Authentication failed"}'}


def test_non_ascii_key_header_is_401_not_500(client):
    """compare_digest used to raise TypeError on non-ASCII str -> unauthenticated 500."""
    import asyncio

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


def test_health_needs_no_key_but_every_data_and_admin_route_does(make_client):
    client = make_client(AUTH_FAIL_LIMIT=1000)  # this test makes more anonymous requests than the default throttle
    assert client.get("/health").status_code == 200
    for path in (
        "/api/v1/credentials",
        "/api/v1/credentials/x",
        "/api/v1/credentials/x/versions",
        "/api/v1/db-url/x",
        "/api/v1/search?q=x",
        "/api/v1/admin/principals",
        "/api/v1/admin/grants",
        "/api/v1/admin/access-log",
    ):
        assert client.get(path).status_code == 401, path
    assert client.post("/api/v1/admin/reload").status_code == 401
    assert client.post("/api/v1/admin/principals", json={"name": "x", "kind": "agent"}).status_code == 401
    assert client.post("/api/v1/credentials/x", json={"value": "v"}).status_code == 401
    assert client.delete("/api/v1/credentials/x").status_code == 401


def test_unauthenticated_requests_learn_nothing_about_server_mode(client):
    """Auth runs before the read-only check: an anonymous POST is 401, not 405."""
    assert client.post("/api/v1/credentials/x", json={"value": "v"}).status_code == 401


def test_expired_and_disabled_tokens_get_401_on_data_routes(pc, policy_tokens):
    for who in ("expired", "off"):
        for response in (
            pc.get("/api/v1/credentials", headers=bearer(policy_tokens[who])),
            pc.get("/api/v1/credentials/firefly.token", headers=bearer(policy_tokens[who])),
            pc.post("/api/v1/credentials/app-x", json={"value": "v"}, headers=bearer(policy_tokens[who])),
        ):
            assert response.status_code == 401 and response.json() == {"detail": "Authentication failed"}


# ---------------------------------------------------------------------------
# GET /credentials (list)
# ---------------------------------------------------------------------------


def test_list_shows_only_entries_with_list_and_fills_fields_only_with_read(pc, policy_tokens):
    hermes = pc.get("/api/v1/credentials?show_password=true", headers=bearer(policy_tokens["hermes"]))
    assert hermes.status_code == 200
    # firefly-mcp (read only, no list) and everything else is absent; tagged entries come in through the tag grant
    assert names(hermes) == ["firefly.db", "firefly.token", "retag", "shared-db", "shared-note"]
    by_name = {c["name"]: c for c in hermes.json()["credentials"]}
    assert by_name["firefly.token"]["password"] == "ff-secret"
    assert by_name["firefly.db"]["username"] == "dbuser" and by_name["firefly.db"]["url"] == "db.internal:5432"
    assert by_name["shared-note"]["password"] == "tagged-secret"
    assert hermes.json()["count"] == 5


def test_list_only_entries_have_null_fields_and_a_masked_password_even_with_show_password(pc, policy_tokens):
    response = pc.get("/api/v1/credentials?show_password=true", headers=bearer(policy_tokens["lister"]))
    assert names(response) == ["firefly.db", "firefly.token"]
    for entry in response.json()["credentials"]:
        assert entry["username"] is None and entry["url"] is None and entry["notes"] is None
        assert entry["password"] == "*****"
        assert entry["version"]  # name and version are what list alone gives
    assert "db-secret" not in response.text and "ff-secret" not in response.text and "dbuser" not in response.text


def test_read_without_list_does_not_enumerate(pc, policy_tokens, data):
    # hermes may READ firefly-mcp but must not see it listed
    assert "firefly-mcp" not in names(pc.get("/api/v1/credentials", headers=bearer(policy_tokens["hermes"])))
    assert pc.get("/api/v1/credentials/firefly-mcp", headers=bearer(policy_tokens["hermes"])).status_code == 200


def test_list_prefix_cannot_widen_what_is_visible(pc, policy_tokens):
    h = bearer(policy_tokens["fireflyer"])
    assert names(pc.get("/api/v1/credentials", params={"prefix": "fire"}, headers=h)) == ["firefly.db", "firefly.token"]
    assert pc.get("/api/v1/credentials", params={"prefix": "oth"}, headers=h).json()["count"] == 0
    assert pc.get("/api/v1/credentials", params={"prefix": "firefly."}, headers=h).json()["count"] == 2


def test_list_with_nothing_visible_is_200_and_empty(pc, policy_tokens):
    response = pc.get("/api/v1/credentials", headers=bearer(policy_tokens["matt"]))  # admin without data grants
    assert response.status_code == 200 and response.json() == {"credentials": [], "count": 0}


def test_list_is_filtered_by_name_grants(pc, policy_tokens):
    assert names(pc.get("/api/v1/credentials", headers=bearer(policy_tokens["scribe"]))) == ["app-db", "app-token"]
    everything = names(pc.get("/api/v1/credentials", headers=bearer(policy_tokens["runner"])))
    assert "other" in everything and "firefly-mcp" in everything and len(everything) == 11


def test_list_for_legacy_keys(legacy):
    assert len(names(legacy("env").get("/api/v1/credentials", headers=auth(FULL_KEY)))) == 11
    assert len(names(legacy("plain").get("/api/v1/credentials", headers=auth(PLAIN)))) == 11
    v1 = legacy("v1")
    assert names(v1.get("/api/v1/credentials", headers=auth(APP_KEY))) == ["app-db", "app-token"]
    assert len(names(v1.get("/api/v1/credentials", headers=auth(READ_KEY)))) == 11
    assert v1.get("/api/v1/credentials", headers=auth(ADMIN_KEY)).json()["count"] == 0  # admin only


# ---------------------------------------------------------------------------
# GET /search
# ---------------------------------------------------------------------------


def results(response) -> dict[str, list[str]]:
    return {r["name"]: r["tags"] for r in response.json()["results"]}


def test_search_by_name_is_a_case_insensitive_substring_over_what_the_principal_may_list(pc, policy_tokens):
    response = pc.get("/api/v1/search", params={"q": "FIREFLY"}, headers=bearer(policy_tokens["hermes"]))
    assert response.status_code == 200
    assert sorted(results(response)) == ["firefly.db", "firefly.token"]  # firefly-mcp: read only; firefly: no grant
    assert response.json()["count"] == 2
    runner = pc.get("/api/v1/search", params={"q": "fire"}, headers=bearer(policy_tokens["runner"]))
    assert sorted(results(runner)) == ["firefly", "firefly-mcp", "firefly.db", "firefly.token"]
    assert sorted(results(pc.get("/api/v1/search?q=ire", headers=bearer(policy_tokens["fireflyer"])))) == [
        "firefly.db",
        "firefly.token",
    ]


def test_search_by_tag_returns_tags_of_the_latest_version(pc, policy_tokens):
    response = pc.get("/api/v1/search", params={"tag": "shared"}, headers=bearer(policy_tokens["runner"]))
    assert results(response) == {
        "shared-note": ["shared"],
        "shared-db": ["shared"],
        "retag": ["shared"],
    }
    # tag and name together narrow the result
    both = pc.get("/api/v1/search", params={"tag": "shared", "q": "note"}, headers=bearer(policy_tokens["runner"]))
    assert results(both) == {"shared-note": ["shared"]}
    assert pc.get("/api/v1/search?tag=Shared", headers=bearer(policy_tokens["runner"])).json()["count"] == 0  # exact


def test_search_never_reads_values_or_notes_and_returns_only_name_and_tags(pc, policy_tokens, data):
    data.put("noted", value=None, password="pw", notes="mentions-needle-in-notes")
    response = pc.get("/api/v1/search", params={"q": "needle"}, headers=bearer(policy_tokens["runner"]))
    assert response.json() == {"results": [], "count": 0}
    assert pc.get("/api/v1/search?q=ff-secret", headers=bearer(policy_tokens["runner"])).json()["count"] == 0
    hit = pc.get("/api/v1/search?q=noted", headers=bearer(policy_tokens["runner"])).json()["results"][0]
    assert set(hit) == {"name", "tags"}


def test_search_needs_a_filter_and_validates_it(pc, policy_tokens):
    h = bearer(policy_tokens["runner"])
    for params in ({}, {"q": ""}, {"tag": ""}, {"q": "", "tag": ""}):
        response = pc.get("/api/v1/search", params=params, headers=h)
        assert response.status_code == 400 and response.json() == {"detail": "Provide q, tag or both"}
    assert pc.get("/api/v1/search", params={"q": "x" * 256}, headers=h).status_code == 422


def test_search_is_denied_nothing_but_filtered(pc, policy_tokens):
    # list-only grants find names; a principal without list on them finds nothing, with the usual 200
    assert sorted(results(pc.get("/api/v1/search?q=fire", headers=bearer(policy_tokens["lister"])))) == [
        "firefly.db",
        "firefly.token",
    ]
    assert pc.get("/api/v1/search?q=fire", headers=bearer(policy_tokens["scribe"])).json() == {
        "results": [],
        "count": 0,
    }
    assert pc.get("/api/v1/search?q=fire", headers=bearer(policy_tokens["matt"])).json() == {"results": [], "count": 0}


def test_search_for_legacy_keys(legacy):
    assert legacy("env").get("/api/v1/search?q=firefly", headers=auth(FULL_KEY)).json()["count"] == 4
    assert legacy("plain").get("/api/v1/search?q=firefly", headers=auth(PLAIN)).json()["count"] == 4
    v1 = legacy("v1")
    assert v1.get("/api/v1/search?q=firefly", headers=auth(READ_KEY)).json()["count"] == 4
    assert v1.get("/api/v1/search?q=db", headers=auth(APP_KEY)).json()["count"] == 1  # app-db only: prefix app-
    assert v1.get("/api/v1/search?q=db", headers=auth(ADMIN_KEY)).json()["count"] == 0


# ---------------------------------------------------------------------------
# GET /credentials/{name}, /versions, /db-url/{name}: read, 404 for everything not granted
# ---------------------------------------------------------------------------

READ_ROUTES = [
    ("/api/v1/credentials/{}?show_password=true", "Credential not found: {}"),
    ("/api/v1/credentials/{}/versions", "Credential not found: {}"),
    ("/api/v1/db-url/{}?database=d", "Credential not found or unsuitable: {}"),
]


@pytest.mark.parametrize(("template", "detail"), READ_ROUTES)
def test_denied_reads_are_indistinguishable_from_missing_names(pc, policy_tokens, template, detail):
    for who, hidden in (
        ("fireflyer", "other"),  # outside every grant
        ("fireflyer", "firefly-mcp"),  # `firefly.*` is a prefix of the dotted names only
        ("fireflyer", "firefly"),  # ... and does not cover the bare name
        ("scribe", "firefly.token"),
        ("lister", "firefly.token"),  # list without read
        ("hermes", "demoted"),  # old version carried the tag; the latest does not
        ("matt", "firefly.token"),  # admin is not data access
    ):
        denied = same_as_missing(pc, bearer(policy_tokens[who]), template, hidden)
        assert denied.json() == {"detail": detail.format(hidden)}


def test_get_allowed(pc, policy_tokens):
    h = bearer(policy_tokens["fireflyer"])
    ok = pc.get("/api/v1/credentials/firefly.token?show_password=true", headers=h)
    assert ok.status_code == 200 and ok.json()["password"] == "ff-secret"
    assert pc.get("/api/v1/credentials/firefly.token", headers=h).json()["password"] == "*****"
    assert pc.get("/api/v1/credentials/firefly.db?show_password=true", headers=h).json()["username"] == "dbuser"
    exact = pc.get("/api/v1/credentials/firefly-mcp?show_password=true", headers=bearer(policy_tokens["hermes"]))
    assert exact.json()["password"] == "mcp-secret"  # exact-name grant
    # an allowed name that does not exist is the same 404 as ever
    assert pc.get("/api/v1/credentials/firefly.zzz", headers=h).json() == {
        "detail": "Credential not found: firefly.zzz"
    }


def test_versions_and_db_url_allowed(pc, policy_tokens):
    h = bearer(policy_tokens["fireflyer"])
    versions = pc.get("/api/v1/credentials/firefly.db/versions", headers=h)
    assert versions.status_code == 200 and versions.json()["latest"] == "0000000001"
    url = pc.get("/api/v1/db-url/firefly.db", params={"database": "d", "mask_password": "false"}, headers=h)
    assert url.status_code == 200 and "db-secret" in url.json()["url"]
    # an allowed simple secret is "unsuitable", exactly as before
    unsuitable = pc.get("/api/v1/db-url/firefly.token", params={"database": "d"}, headers=h)
    assert unsuitable.json() == {"detail": "Credential not found or unsuitable: firefly.token"}


def test_list_without_read_cannot_fetch(pc, policy_tokens):
    h = bearer(policy_tokens["lister"])
    assert pc.get("/api/v1/credentials/firefly.token", headers=h).status_code == 404
    assert pc.get("/api/v1/credentials/firefly.token/versions", headers=h).status_code == 404
    assert pc.get("/api/v1/db-url/firefly.db?database=d", headers=h).status_code == 404


def test_tag_grants_decide_by_the_tags_of_the_latest_version(pc, policy_tokens):
    h = bearer(policy_tokens["hermes"])
    # a password-only entry with a tag: get() hands back a bare dict, the server still finds its tags
    note = pc.get("/api/v1/credentials/shared-note?show_password=true", headers=h)
    assert note.status_code == 200 and note.json()["password"] == "tagged-secret"
    assert pc.get("/api/v1/credentials/shared-db/versions", headers=h).status_code == 200
    assert pc.get("/api/v1/db-url/shared-db?database=d", headers=h).status_code == 200
    # the latest version is tagged, the first was not: every version is readable
    assert pc.get("/api/v1/credentials/retag?show_password=true", headers=h).json()["password"] == "v2-tagged"
    assert pc.get("/api/v1/credentials/retag?version=1&show_password=true", headers=h).json()["password"] == (
        "v1-untagged"
    )
    # the first version was tagged, the latest is not: nothing is readable, old versions included
    assert pc.get("/api/v1/credentials/demoted", headers=h).status_code == 404
    assert pc.get("/api/v1/credentials/demoted?version=1", headers=h).status_code == 404
    assert pc.get("/api/v1/credentials/demoted/versions", headers=h).status_code == 404
    # someone without the tag grant does not get in by name either
    assert pc.get("/api/v1/credentials/shared-note", headers=bearer(policy_tokens["fireflyer"])).status_code == 404


def test_read_for_legacy_keys(legacy):
    path = "/api/v1/credentials/other?show_password=true"
    assert legacy("env").get(path, headers=auth(FULL_KEY)).json()["password"] == "private"
    assert legacy("plain").get(path, headers=auth(PLAIN)).json()["password"] == "private"
    v1 = legacy("v1")
    assert v1.get(path, headers=auth(READ_KEY)).json()["password"] == "private"
    assert v1.get("/api/v1/credentials/other/versions", headers=auth(READ_KEY)).status_code == 200
    assert (
        v1.get("/api/v1/credentials/app-db?show_password=true", headers=auth(APP_KEY)).json()["password"] == "db-secret"
    )
    assert v1.get("/api/v1/db-url/app-db", params={"database": "d"}, headers=auth(APP_KEY)).status_code == 200
    for template, _ in READ_ROUTES:  # out of the v1 prefix: indistinguishable from missing
        same_as_missing(v1, auth(APP_KEY), template, "other")
        same_as_missing(v1, auth(ADMIN_KEY), template, "app-db")  # an admin-only v1 key has no data grants


# ---------------------------------------------------------------------------
# POST /credentials/{name}
# ---------------------------------------------------------------------------


def stored(data, name: str):
    return data.get(name, show_password=True)


def test_put_allowed_by_a_name_grant(pc, policy_tokens, data):
    h = bearer(policy_tokens["scribe"])
    created = pc.post("/api/v1/credentials/app-new", json={"value": "v"}, headers=h)
    assert created.status_code == 201 and created.json()["created"] is True
    again = pc.post("/api/v1/credentials/app-new", json={"value": "v2"}, headers=h)
    assert again.json()["version"] == "0000000002"
    assert stored(data, "app-new")["value"] == "v2"


def test_put_denied_is_403_before_the_database_is_touched(pc, policy_tokens, data):
    scribe = bearer(policy_tokens["scribe"])
    for name in ("other", "firefly.token", "appx", "app"):  # `app-*` needs the dash
        denied = pc.post(f"/api/v1/credentials/{name}", json={"value": "pwned"}, headers=scribe)
        assert denied.status_code == 403 and denied.json() == {"detail": "Insufficient permissions"}
    assert stored(data, "other")["value"] == "private"
    assert stored(data, "firefly.token")["value"] == "ff-secret"
    # the answer cannot tell whether the name exists
    exists = pc.post("/api/v1/credentials/other", json={"value": "x"}, headers=scribe)
    missing = pc.post("/api/v1/credentials/nonexistent-zzz", json={"value": "x"}, headers=scribe)
    assert exists.status_code == missing.status_code == 403 and exists.text == missing.text


def test_put_without_any_write_grant_is_403_for_every_name(pc, policy_tokens):
    for who in ("hermes", "lister", "fireflyer", "runner", "matt"):
        response = pc.post("/api/v1/credentials/app-new", json={"value": "v"}, headers=bearer(policy_tokens[who]))
        assert response.status_code == 403 and response.json() == {"detail": "Insufficient permissions"}, who


def test_put_ordering_403_beats_405_for_a_principal_that_can_never_write(pro, policy_tokens):
    assert (
        pro.post("/api/v1/credentials/x", json={"value": "v"}, headers=bearer(policy_tokens["hermes"])).status_code
        == 403
    )
    assert (
        pro.post("/api/v1/credentials/app-x", json={"value": "v"}, headers=bearer(policy_tokens["scribe"])).status_code
        == 405
    )
    assert pro.delete("/api/v1/credentials/app-x", headers=bearer(policy_tokens["scribe"])).status_code == 405
    assert pro.delete("/api/v1/credentials/app-x", headers=bearer(policy_tokens["hermes"])).status_code == 403


def test_put_for_legacy_keys(legacy, data):
    env_post = legacy("env").post("/api/v1/credentials/legacy-one", json={"value": "v"}, headers=auth(FULL_KEY))
    assert env_post.status_code == 201
    plain_post = legacy("plain").post("/api/v1/credentials/legacy-two", json={"value": "v"}, headers=auth(PLAIN))
    assert plain_post.status_code == 201
    v1 = legacy("v1")
    assert v1.post("/api/v1/credentials/app-new", json={"value": "v"}, headers=auth(APP_KEY)).status_code == 201
    assert v1.post("/api/v1/credentials/anything", json={"value": "v"}, headers=auth(WRITE_KEY)).status_code == 201
    for key, name in ((APP_KEY, "other"), (READ_KEY, "app-x"), (ADMIN_KEY, "app-x")):
        response = v1.post(f"/api/v1/credentials/{name}", json={"value": "pwned"}, headers=auth(key))
        assert response.status_code == 403 and response.json() == {"detail": "Insufficient permissions"}
    assert stored(data, "other")["value"] == "private"


# ---------------------------------------------------------------------------
# DELETE /credentials/{name}
# ---------------------------------------------------------------------------


def test_delete_allowed_and_denied(pc, policy_tokens, data):
    scribe = bearer(policy_tokens["scribe"])
    assert pc.delete("/api/v1/credentials/app-token", headers=scribe).json() == {
        "detail": "Credential deleted: app-token"
    }
    assert pc.delete("/api/v1/credentials/app-token", headers=scribe).status_code == 404  # allowed, but gone
    denied = pc.delete("/api/v1/credentials/other", headers=scribe)
    assert denied.status_code == 403 and denied.json() == {"detail": "Insufficient permissions"}
    assert stored(data, "other")["value"] == "private"
    for who in ("hermes", "runner", "fireflyer"):
        assert pc.delete("/api/v1/credentials/other", headers=bearer(policy_tokens[who])).status_code == 403


def test_delete_for_legacy_keys(legacy):
    assert legacy("env").delete("/api/v1/credentials/other", headers=auth(FULL_KEY)).status_code == 200
    assert legacy("plain").delete("/api/v1/credentials/app-db", headers=auth(PLAIN)).status_code == 200
    v1 = legacy("v1")
    assert v1.delete("/api/v1/credentials/app-token", headers=auth(APP_KEY)).status_code == 200
    assert v1.delete("/api/v1/credentials/firefly", headers=auth(APP_KEY)).status_code == 403
    for key in (WRITE_KEY, READ_KEY, ADMIN_KEY):  # no `delete` op
        assert v1.delete("/api/v1/credentials/firefly", headers=auth(key)).status_code == 403


# ---------------------------------------------------------------------------
# admin gates (the endpoints themselves are in test_admin_api.py)
# ---------------------------------------------------------------------------


def test_only_admins_reach_admin_routes(pc, policy_tokens):
    for who in ("hermes", "lister", "scribe", "runner", "fireflyer"):
        for response in (
            pc.get("/api/v1/admin/principals", headers=bearer(policy_tokens[who])),
            pc.post("/api/v1/admin/reload", headers=bearer(policy_tokens[who])),
            pc.post("/api/v1/admin/invalidate-api-key-cache", headers=bearer(policy_tokens[who])),
        ):
            assert response.status_code == 403 and response.json() == {"detail": "Insufficient permissions"}, who
    assert pc.post("/api/v1/admin/reload", headers=bearer(policy_tokens["matt"])).status_code == 200


def test_legacy_admins(legacy):
    assert legacy("env").post("/api/v1/admin/invalidate-api-key-cache", headers=auth(FULL_KEY)).status_code == 200
    v1 = legacy("v1")
    assert v1.post("/api/v1/admin/reload", headers=auth(ADMIN_KEY)).status_code == 200
    for key in (READ_KEY, APP_KEY, WRITE_KEY):
        assert v1.post("/api/v1/admin/reload", headers=auth(key)).status_code == 403


# ---------------------------------------------------------------------------
# rotation of legacy keys without a restart (unchanged behaviour)
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


def test_migrated_policy_serves_the_old_plain_keys_over_http(make_client, tmp_path, key_policy_file, data):
    from mattstash.authz import edit_policy

    with edit_policy(tmp_path / "migrated.json", create=True) as ed:
        ed.import_v1(key_policy_file.read_text(), 32)
    client = make_client(API_KEY=None, POLICY_FILE=str(tmp_path / "migrated.json"), ALLOW_WRITES=True)
    assert names(client.get("/api/v1/credentials", headers=auth(APP_KEY))) == ["app-db", "app-token"]
    assert client.post("/api/v1/credentials/other", json={"value": "x"}, headers=auth(APP_KEY)).status_code == 403
    assert client.post("/api/v1/credentials/app-new", json={"value": "x"}, headers=auth(APP_KEY)).status_code == 201
    assert client.get("/api/v1/credentials/other", headers=auth(READ_KEY)).status_code == 200
    assert client.post("/api/v1/admin/reload", headers=auth(ADMIN_KEY)).status_code == 200
    assert client.get("/api/v1/credentials", headers=auth("n" * 40)).status_code == 401
    assert json.loads(client.get("/api/v1/admin/principals", headers=auth(ADMIN_KEY)).text)["principals"]


# ---------------------------------------------------------------------------
# v1 `ops: ["admin"]` stays what it was: reload and invalidate only
# ---------------------------------------------------------------------------

_MUTATING_AND_READING = [
    ("GET", "/principals", None),
    ("POST", "/principals", {"name": "intruder", "kind": "agent"}),
    ("GET", "/principals/reader", None),
    ("PATCH", "/principals/matt", {"disabled": True}),
    ("DELETE", "/principals/hermes", None),
    ("GET", "/principals/hermes/tokens", None),
    ("POST", "/principals/hermes/tokens", {}),
    ("GET", "/grants", None),
    ("POST", "/grants", {"principal": "hermes", "key": "*", "actions": ["list", "read", "write", "delete"]}),
    ("DELETE", "/grants/g_00000000", None),
    ("POST", "/check", {"principal": "hermes", "action": "read", "name": "x"}),
    ("GET", "/access-log", None),
]


@pytest.mark.parametrize(("method", "path", "body"), _MUTATING_AND_READING)
def test_a_v1_admin_only_key_cannot_use_the_new_admin_endpoints(
    make_client, key_policy_file, policy_path, policy_tokens, tmp_path, method, path, body
):
    log = tmp_path / "access.jsonl"
    client = make_client(
        API_KEY=None,
        API_KEYS_FILE=str(key_policy_file),
        POLICY_FILE=policy_path,
        ACCESS_LOG_FILE=str(log),
        ALLOW_WRITES=True,
    )
    before = Path(policy_path).read_text()
    for key in (ADMIN_KEY, READ_KEY, WRITE_KEY, APP_KEY):
        response = client.request(method, "/api/v1/admin" + path, json=body, headers=auth(key))
        assert response.status_code == 403 and response.json() == {"detail": "Insufficient permissions"}, key
    assert Path(policy_path).read_text() == before
    # what v1 admin meant still works
    assert client.post("/api/v1/admin/reload", headers=auth(ADMIN_KEY)).status_code == 200
    assert client.post("/api/v1/admin/invalidate-api-key-cache", headers=auth(ADMIN_KEY)).status_code == 200
    # ... and the file's own admin is unaffected
    assert client.get("/api/v1/admin/principals", headers=bearer(policy_tokens["matt"])).status_code == 200
    denied = [json.loads(line) for line in log.read_text().splitlines()]
    assert {r["reason"] for r in denied if r["principal"] == "ops" and r["decision"] == "denied"} == {"legacy-scoped"}


def test_full_access_legacy_keys_keep_every_admin_endpoint(make_client, policy_path, policy_tokens, tmp_path):
    plain = tmp_path / "plain.txt"
    plain.write_text("p" * 40 + "\n")
    for kwargs, key in (({"API_KEY": FULL_KEY}, FULL_KEY), ({"API_KEY": None, "API_KEYS_FILE": str(plain)}, "p" * 40)):
        client = make_client(POLICY_FILE=policy_path, **kwargs)
        assert client.get("/api/v1/admin/principals", headers=auth(key)).status_code == 200
        assert client.get("/api/v1/admin/grants", headers=auth(key)).status_code == 200
        check = {"principal": "hermes", "action": "read", "name": "firefly.x"}
        assert client.post("/api/v1/admin/check", json=check, headers=auth(key)).json()["allowed"] is True
