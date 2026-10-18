"""MATTSTASH_ALLOW_SLASH_NAMES on the server: ``/`` in names is a 404 unless enabled, then path-style routes work."""

import pytest

from .conftest import DB, auth


@pytest.fixture
def tokens(tmp_path):
    from mattstash.authz import edit_policy

    out: dict[str, str] = {}
    with edit_policy(tmp_path / "policy.json", create=True) as ed:
        ed.add_principal("matt", "human-device", "laptop", admin=True)
        ed.add_principal("viewer", "agent")
        ed.add_principal("writer", "agent")
        ed.add_principal("mixed", "agent")
        ed.add_grant("mixed", key="plain", actions=["list", "read", "write"])
        ed.add_grant("mixed", key="cloud", actions=["read"])
        ed.add_grant("viewer", key="cloud/*", actions=["list", "read"])
        ed.add_grant("writer", key="cloud/*", actions=["list", "read", "write", "delete"])
        for name in ("matt", "viewer", "writer", "mixed"):
            out[name] = ed.issue_token(name)[1]
    return out


@pytest.fixture
def seeded(seed):
    return seed(
        **{
            "cloud/hetzner/s3-key": {"value": "s3-secret", "allow_slash": True},
            "cloud/db": {**DB, "allow_slash": True},
            "other/thing": {"value": "private", "allow_slash": True},
            "cloud/versions": {"value": "named-versions", "allow_slash": True},
            "plain": {"value": "p"},
        }
    )


def make(make_client, tmp_path, **overrides):
    return make_client(POLICY_FILE=str(tmp_path / "policy.json"), ALLOW_WRITES=True, **overrides)


NAMES = ["cloud/hetzner/s3-key", "cloud%2Fhetzner%2Fs3-key"]


@pytest.mark.parametrize("name", NAMES)
def test_off_by_default_slash_names_are_404_on_every_route(make_client, tmp_path, tokens, seeded, name):
    client = make(make_client, tmp_path)
    h = auth(tokens["writer"])
    assert client.get(f"/api/v1/credentials/{name}", headers=h).status_code == 404
    assert client.post(f"/api/v1/credentials/{name}", json={"value": "v"}, headers=h).status_code == 404
    assert client.delete(f"/api/v1/credentials/{name}", headers=h).status_code == 404
    assert client.get(f"/api/v1/db-url/{name}", headers=h).status_code == 404
    assert client.get(f"/api/v1/versions/{name}", headers=h).status_code == 404
    assert client.get("/api/v1/credentials", headers=h).json()["credentials"] == []  # not listed either
    assert client.get("/api/v1/search?q=hetzner", headers=h).json()["count"] == 0
    assert client.get("/api/v1/credentials?prefix=cloud/", headers=h).status_code == 400
    # nothing was written or deleted
    assert seeded.get("cloud/hetzner/s3-key", show_password=True)["value"] == "s3-secret"


def test_off_by_default_plain_names_and_both_versions_routes_still_work(make_client, tmp_path, tokens, seeded):
    client = make(make_client, tmp_path)
    h = auth(tokens["mixed"])
    assert client.get("/api/v1/credentials/plain", headers=h).status_code == 200
    assert client.get("/api/v1/credentials/plain/versions", headers=h).json()["versions"] == ["0000000001"]
    assert client.get("/api/v1/versions/plain", headers=h).json()["versions"] == ["0000000001"]
    assert client.post("/api/v1/credentials/cloud.plain", json={"value": "x"}, headers=h).status_code == 403
    assert client.get("/api/v1/credentials/", headers=h, follow_redirects=False).status_code == 307  # as before


@pytest.fixture
def on(make_client, tmp_path, tokens, seeded):
    return make(make_client, tmp_path, ALLOW_SLASH_NAMES=True)


@pytest.mark.parametrize("name", NAMES)
def test_literal_and_encoded_slashes_route_alike(on, tokens, name):
    h = auth(tokens["viewer"])
    got = on.get(f"/api/v1/credentials/{name}?show_password=true", headers=h)
    assert got.status_code == 200
    assert got.json()["name"] == "cloud/hetzner/s3-key" and got.json()["password"] == "s3-secret"
    assert on.get(f"/api/v1/versions/{name}", headers=h).json() == {
        "name": "cloud/hetzner/s3-key",
        "versions": ["0000000001"],
        "latest": "0000000001",
    }


def test_db_url_for_a_slash_name(on, tokens):
    response = on.get("/api/v1/db-url/cloud/db?database=app", headers=auth(tokens["viewer"]))
    assert response.status_code == 200 and "dbuser" in response.json()["url"]


@pytest.mark.parametrize("sep", ["/", "%2F"])
def test_create_read_versions_and_delete_a_slash_name(on, tokens, sep):
    h = auth(tokens["writer"])
    name = f"cloud{sep}new{sep}key"
    created = on.post(f"/api/v1/credentials/{name}", json={"value": "v1"}, headers=h)
    assert created.status_code == 201 and created.json()["name"] == "cloud/new/key"
    on.post(f"/api/v1/credentials/{name}", json={"value": "v2"}, headers=h)
    assert on.get(f"/api/v1/versions/{name}", headers=h).json()["versions"] == ["0000000001", "0000000002"]
    assert on.get(f"/api/v1/credentials/{name}?show_password=true&version=1", headers=h).json()["password"] == "v1"
    assert on.delete(f"/api/v1/credentials/{name}?version=1", headers=h).status_code == 200
    assert on.delete(f"/api/v1/credentials/{name}", headers=h).status_code == 200
    assert on.get(f"/api/v1/credentials/{name}", headers=h).status_code == 404
    assert on.delete(f"/api/v1/credentials/{name}", headers=h).status_code == 404


def test_a_name_ending_in_versions_uses_the_new_versions_route(on, tokens):
    assert on.get("/api/v1/versions/cloud/versions", headers=auth(tokens["viewer"])).json()["name"] == "cloud/versions"
    # the old route reads the same URL as "the versions of cloud": it keeps its meaning for names without '/'
    old = on.get("/api/v1/credentials/cloud/versions", headers=auth(tokens["viewer"]))
    assert old.status_code == 404  # 'cloud' is not in the viewer's grant: the request was about 'cloud'
    assert (
        on.get("/api/v1/credentials/cloud/versions", headers=auth(tokens["mixed"])).status_code == 404
    )  # no such entry


def test_both_versions_routes_serve_plain_names_when_enabled(on, tokens):
    h = auth(tokens["mixed"])
    assert on.get("/api/v1/versions/plain", headers=h).json()["name"] == "plain"
    assert on.get("/api/v1/credentials/plain/versions", headers=h).json()["name"] == "plain"


@pytest.mark.parametrize(
    "name",
    ["%2Fcloud%2Fx", "cloud%2Fx%2F", "cloud%2F%2Fx", "cloud/%2E/x", "cloud/%2E%2E/x", "cloud%2F..%2Fx"],
)
def test_segment_rules_are_400(on, tokens, name):
    h = auth(tokens["writer"])
    assert on.post(f"/api/v1/credentials/{name}", json={"value": "v"}, headers=h).status_code in (400, 404)
    for response in (
        on.get(f"/api/v1/credentials/{name}", headers=h),
        on.get(f"/api/v1/versions/{name}", headers=h),
        on.get(f"/api/v1/db-url/{name}", headers=h),
        on.delete(f"/api/v1/credentials/{name}", headers=h),
    ):
        assert response.status_code in (400, 404)


@pytest.mark.parametrize("name", ["%2Fcloud%2Fx", "cloud%2Fx%2F", "cloud%2F%2Fx", "cloud%2F%2E%2E%2Fx", "cloud%2F%2Ex"])
def test_malformed_slash_names_are_refused_with_400_on_write(on, tokens, name):
    expected = 400 if name != "cloud%2F%2Ex" else 201  # '.x' as a later segment is fine; only '.'/'..' segments are not
    response = on.post(f"/api/v1/credentials/{name}", json={"value": "v"}, headers=auth(tokens["writer"]))
    assert response.status_code == expected


def test_a_character_outside_the_name_set_is_still_400(on, tokens):
    assert on.get("/api/v1/credentials/cloud%2Fa%20b", headers=auth(tokens["viewer"])).status_code == 400
    assert on.get("/api/v1/credentials/cloud%2Fa%0A", headers=auth(tokens["viewer"])).status_code == 400


def test_grants_match_slash_names_literally_and_denied_looks_like_missing(on, tokens):
    h = auth(tokens["viewer"])
    denied = on.get("/api/v1/credentials/other/thing", headers=h)  # exists, not granted
    missing = on.get("/api/v1/credentials/other/nothing", headers=h)  # does not exist
    assert denied.status_code == missing.status_code == 404
    assert denied.json()["detail"].replace("thing", "X") == missing.json()["detail"].replace("nothing", "X")
    assert on.get("/api/v1/versions/other/thing", headers=h).status_code == 404
    assert on.get("/api/v1/db-url/other/thing", headers=h).status_code == 404
    assert "private" not in denied.text
    # 'cloud/*' is a literal prefix: it does not match 'cloud' or 'cloudx/..'
    assert on.get("/api/v1/credentials/cloud", headers=h).status_code == 404


def test_write_and_delete_outside_the_grant_are_403_even_for_slash_names(on, tokens):
    h = auth(tokens["writer"])
    assert on.post("/api/v1/credentials/other/new", json={"value": "v"}, headers=h).status_code == 403
    assert on.delete("/api/v1/credentials/other/thing", headers=h).status_code == 403
    assert (
        on.post("/api/v1/credentials/cloud/ok", json={"value": "v"}, headers=auth(tokens["viewer"])).status_code == 403
    )


def test_list_and_search_filter_slash_names_by_grant(on, tokens):
    h = auth(tokens["viewer"])
    names = sorted(c["name"] for c in on.get("/api/v1/credentials", headers=h).json()["credentials"])
    assert names == ["cloud/db", "cloud/hetzner/s3-key", "cloud/versions"]  # 'other/thing' and 'plain' are not granted
    prefixed = on.get("/api/v1/credentials?prefix=cloud/h", headers=h).json()
    assert [c["name"] for c in prefixed["credentials"]] == ["cloud/hetzner/s3-key"]
    found = on.get("/api/v1/search?q=HETZNER", headers=h).json()
    assert [r["name"] for r in found["results"]] == ["cloud/hetzner/s3-key"]


def test_the_access_log_names_the_slash_name(on, tokens, tmp_path, caplog):
    import json
    import logging

    caplog.set_level(logging.INFO)
    on.get("/api/v1/credentials/cloud%2Fhetzner%2Fs3-key", headers=auth(tokens["viewer"]))
    lines = [json.loads(r.getMessage()) for r in caplog.records if r.name == "mattstash.access"]
    assert lines[-1]["key"] == "cloud/hetzner/s3-key" and lines[-1]["decision"] == "allowed"
