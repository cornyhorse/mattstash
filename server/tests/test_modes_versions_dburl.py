"""Read-only default (Q1), version handling over HTTP (M-4), list collapsing, db-url encoding (M-3), validation."""

from urllib.parse import unquote, urlsplit

import pytest

from .conftest import auth

H = auth()


# ---------------------------------------------------------------------------
# read-only by default
# ---------------------------------------------------------------------------


def test_writes_are_disabled_by_default_with_a_clear_405(client, seed):
    seed(keep={"value": "1"})
    for response in (
        client.post("/api/v1/credentials/new", json={"value": "v"}, headers=H),
        client.delete("/api/v1/credentials/keep", headers=H),
    ):
        assert response.status_code == 405
        assert response.headers["allow"] == "GET"
        assert "read-only" in response.json()["detail"] and "MATTSTASH_ALLOW_WRITES" in response.json()["detail"]
    # nothing changed, and (the old bug) no phantom in-memory state either
    assert client.get("/api/v1/credentials/new", headers=H).status_code == 404
    assert client.get("/api/v1/credentials/keep", headers=H).status_code == 200


def test_reads_work_in_read_only_mode(client, seed):
    seed(svc={"username": "u", "password": "p", "url": "h:1"})
    assert client.get("/api/v1/credentials/svc?show_password=true", headers=H).json()["password"] == "p"


def test_writes_work_when_enabled_and_persist_to_disk(rw_client, db_path):
    from mattstash import MattStash

    assert rw_client.post("/api/v1/credentials/stored", json={"value": "persisted"}, headers=H).status_code == 201
    on_disk = MattStash(path=str(db_path), password="test-db-password-123")
    assert on_disk.get("stored", show_password=True)["value"] == "persisted"


def test_server_picks_up_external_writes_without_restart(client, db_path):
    """The CLI (or another process) writes the database; the read-only server serves the new data."""
    from mattstash import MattStash

    assert client.get("/api/v1/credentials/external", headers=H).status_code == 404
    MattStash(path=str(db_path), password="test-db-password-123").put("external", value="from-cli")
    assert client.get("/api/v1/credentials/external?show_password=true", headers=H).json()["password"] == "from-cli"


def test_server_and_external_writer_do_not_lose_each_others_writes(rw_client, db_path):
    from mattstash import MattStash

    rw_client.get("/api/v1/credentials", headers=H)  # server has the DB loaded
    MattStash(path=str(db_path), password="test-db-password-123").put("by-cli", value="1")
    rw_client.post("/api/v1/credentials/by-server", json={"value": "2"}, headers=H)
    names = sorted(c["name"] for c in rw_client.get("/api/v1/credentials", headers=H).json()["credentials"])
    assert names == ["by-cli", "by-server"]


# ---------------------------------------------------------------------------
# versions
# ---------------------------------------------------------------------------


def test_post_reports_the_real_version_for_full_credentials(rw_client):
    """Full-credential writes always claimed version 0000000001."""
    results = [
        rw_client.post("/api/v1/credentials/svc", json={"username": "u", "password": f"p{i}"}, headers=H).json()
        for i in range(3)
    ]
    assert [r["version"] for r in results] == ["0000000001", "0000000002", "0000000003"]
    assert [r["created"] for r in results] == [True, False, False]
    assert rw_client.get("/api/v1/credentials/svc/versions", headers=H).json()["latest"] == "0000000003"


def test_post_reports_versions_for_simple_secrets_too(rw_client):
    versions = [
        rw_client.post("/api/v1/credentials/tok", json={"value": str(i)}, headers=H).json()["version"] for i in range(2)
    ]
    assert versions == ["0000000001", "0000000002"]


def test_get_specific_version_and_latest(rw_client):
    for i in range(3):
        rw_client.post("/api/v1/credentials/svc", json={"username": "u", "password": f"p{i}"}, headers=H)
    latest = rw_client.get("/api/v1/credentials/svc?show_password=true", headers=H).json()
    assert (latest["password"], latest["version"]) == ("p2", "0000000003")
    old = rw_client.get("/api/v1/credentials/svc?show_password=true&version=1", headers=H).json()
    assert (old["password"], old["version"]) == ("p0", "0000000001")
    assert rw_client.get("/api/v1/credentials/svc?version=9", headers=H).status_code == 404
    assert rw_client.get("/api/v1/credentials/svc?version=-1", headers=H).status_code == 422


def test_delete_one_version_or_all(rw_client):
    for i in range(3):
        rw_client.post("/api/v1/credentials/svc", json={"value": str(i)}, headers=H)
    assert rw_client.delete("/api/v1/credentials/svc?version=2", headers=H).status_code == 200
    assert rw_client.get("/api/v1/credentials/svc/versions", headers=H).json()["versions"] == [
        "0000000001",
        "0000000003",
    ]
    assert rw_client.delete("/api/v1/credentials/svc?version=2", headers=H).status_code == 404  # already gone
    assert rw_client.delete("/api/v1/credentials/svc", headers=H).status_code == 200  # all remaining versions
    assert rw_client.get("/api/v1/credentials/svc", headers=H).status_code == 404
    assert rw_client.delete("/api/v1/credentials/svc", headers=H).status_code == 404


def test_listing_collapses_versions_to_addressable_names(rw_client, db_path):
    """Listed names used to be 'svc@0000000001' which the API itself rejects as a name."""
    from mattstash import MattStash

    for i in range(3):
        rw_client.post("/api/v1/credentials/svc", json={"username": "u", "password": f"p{i}"}, headers=H)
    rw_client.post("/api/v1/credentials/tok", json={"value": "t"}, headers=H)
    # an entry created by another KeePass tool with a title the API cannot address
    MattStash(path=str(db_path), password="test-db-password-123").put("Folder-x", value="v", autoincrement=False)
    kp_stash = MattStash(path=str(db_path), password="test-db-password-123")
    kp_stash.put("has space ok?", value="v", autoincrement=False) if False else None

    body = rw_client.get("/api/v1/credentials?show_password=true", headers=H).json()
    by_name = {c["name"]: c for c in body["credentials"]}
    assert set(by_name) == {"Folder-x", "svc", "tok"} and body["count"] == 3
    assert (by_name["svc"]["version"], by_name["svc"]["password"]) == ("0000000003", "p2")
    for name in by_name:  # every listed name is fetchable
        assert rw_client.get(f"/api/v1/credentials/{name}", headers=H).status_code == 200


def test_listing_hides_titles_the_api_cannot_address(client, db_path):
    from pykeepass import PyKeePass

    kp = PyKeePass(str(db_path), password="test-db-password-123")
    kp.add_entry(kp.root_group, title="AWS/prod key", username="u", password="p")
    kp.add_entry(kp.root_group, title="fine-name", username="u", password="p")
    kp.save()
    names = [c["name"] for c in client.get("/api/v1/credentials", headers=H).json()["credentials"]]
    assert names == ["fine-name"]


def test_list_masks_passwords_by_default_and_prefix_filters(rw_client):
    for name in ("db-prod", "db-dev", "api-key"):
        rw_client.post(f"/api/v1/credentials/{name}", json={"username": "u", "password": "topsecret"}, headers=H)
    masked = rw_client.get("/api/v1/credentials?prefix=db-", headers=H)
    assert masked.headers["cache-control"] == "no-store"
    assert sorted(c["name"] for c in masked.json()["credentials"]) == ["db-dev", "db-prod"]
    assert {c["password"] for c in masked.json()["credentials"]} == {"*****"}
    assert "topsecret" not in masked.text


# ---------------------------------------------------------------------------
# request validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["foo%0A", "foo%0D%0A", ".hidden", "a%20b", "a@1", "%C3%BCber", "a%2Fb"])
def test_bad_names_are_400_everywhere(rw_client, name):
    """'^…$' accepted 'foo\\n'; names are now matched with fullmatch + ASCII."""
    for request in (
        lambda: rw_client.get(f"/api/v1/credentials/{name}", headers=H),
        lambda: rw_client.get(f"/api/v1/credentials/{name}/versions", headers=H),
        lambda: rw_client.get(f"/api/v1/db-url/{name}", headers=H),
        lambda: rw_client.post(f"/api/v1/credentials/{name}", json={"value": "v"}, headers=H),
        lambda: rw_client.delete(f"/api/v1/credentials/{name}", headers=H),
    ):
        assert request().status_code in (400, 404)  # 404 only where the router cannot match the path at all
    assert rw_client.get(f"/api/v1/credentials/{name}", headers=H).status_code in (400, 404)


def test_trailing_newline_name_is_explicitly_400(client):
    assert client.get("/api/v1/credentials/foo%0A", headers=H).status_code == 400


def test_invalid_prefix_is_400(client):
    assert client.get("/api/v1/credentials", params={"prefix": "a b"}, headers=H).status_code == 400
    assert client.get("/api/v1/credentials", params={"prefix": "x" * 300}, headers=H).status_code == 400


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"value": "v", "password": "p"},
        {"value": "x" * 70_000},
        {"username": "u" * 256},
        {"url": "u" * 2049},
        {"value": "v", "notes": "n" * 65_536},
        {"value": "v", "tags": ["t"] * 51},
        {"value": "v", "tags": ["t" * 101]},
        {"value": 5},
    ],
)
def test_request_body_validation(rw_client, body):
    assert rw_client.post("/api/v1/credentials/x", json=body, headers=H).status_code == 422


def test_unicode_and_special_characters_round_trip(rw_client):
    value = "p@ss/w:rd#1?x=y% 测试🚀\n\"quoted\" 'single' <tag>"
    rw_client.post("/api/v1/credentials/special", json={"value": value}, headers=H)
    assert rw_client.get("/api/v1/credentials/special?show_password=true", headers=H).json()["password"] == value


# ---------------------------------------------------------------------------
# db-url
# ---------------------------------------------------------------------------


def seed_db(rw_client, password="p@ss/w:rd#1?x=y%", url="db.internal:5432"):
    rw_client.post(
        "/api/v1/credentials/pg",
        json={"username": "app user", "password": password, "url": url, "notes": "n"},
        headers=H,
    )


def test_db_url_encodes_special_characters_over_http(rw_client):
    seed_db(rw_client)
    url = rw_client.get("/api/v1/db-url/pg", params={"database": "orders", "mask_password": "false"}, headers=H).json()[
        "url"
    ]
    parts = urlsplit(url)
    assert (parts.hostname, parts.port, parts.path) == ("db.internal", 5432, "/orders")
    assert unquote(parts.username) == "app user" and unquote(parts.password) == "p@ss/w:rd#1?x=y%"


def test_db_url_is_masked_by_default(rw_client):
    seed_db(rw_client)
    body = rw_client.get("/api/v1/db-url/pg", params={"database": "orders"}, headers=H)
    assert body.headers["cache-control"] == "no-store"
    assert body.json()["url"] == "postgresql+psycopg://app%20user:*****@db.internal:5432/orders"


def test_db_url_errors(rw_client):
    seed_db(rw_client)
    assert rw_client.get("/api/v1/db-url/pg?driver=nope", headers=H).status_code == 400
    assert rw_client.get("/api/v1/db-url/nope", headers=H).status_code == 404
    assert rw_client.get("/api/v1/db-url/pg", headers=H).status_code == 400  # no database name known
    rw_client.post("/api/v1/credentials/simple", json={"value": "v"}, headers=H)
    assert rw_client.get("/api/v1/db-url/simple?database=d", headers=H).status_code == 404
    assert rw_client.get("/api/v1/db-url/pg", params={"database": "x" * 129}, headers=H).status_code == 422


def test_db_url_mysql_and_mariadb_dialects(rw_client):
    seed_db(rw_client, url="db.internal:3306")
    get = lambda **params: rw_client.get("/api/v1/db-url/pg", params={"database": "orders", **params}, headers=H)  # noqa: E731
    assert get(dialect="mysql").json()["url"] == "mysql://app%20user:*****@db.internal:3306/orders"
    assert (
        get(dialect="mysql", driver="pymysql").json()["url"]
        == "mysql+pymysql://app%20user:*****@db.internal:3306/orders"
    )
    assert get(dialect="mariadb", driver="mariadbconnector").status_code == 200
    # the PostgreSQL default is unchanged when neither parameter is given
    assert get().json()["url"] == "postgresql+psycopg://app%20user:*****@db.internal:3306/orders"
    assert get(driver="auto").json()["url"].startswith("postgresql+psycopg://")


def test_db_url_rejects_unknown_dialect_and_mismatched_driver(rw_client):
    seed_db(rw_client)
    base = {"database": "orders"}
    for params in (
        {"dialect": "oracle"},
        {"dialect": "postgresql", "driver": "pymysql"},  # a MySQL driver on PostgreSQL
        {"dialect": "mysql", "driver": "psycopg"},
        {"driver": "x" * 40},
    ):
        response = rw_client.get("/api/v1/db-url/pg", params={**base, **params}, headers=H)
        assert response.status_code == 400, params
        assert "pymysql" not in response.text and "oracle" not in response.text, "no echo of the input"


def test_db_url_rejects_hostile_host_in_the_stored_entry(rw_client):
    seed_db(rw_client, url="evil.example/path@x:5432")
    assert rw_client.get("/api/v1/db-url/pg", params={"database": "d"}, headers=H).status_code == 400


def test_db_url_sslmode_cannot_be_used_for_parameter_injection(rw_client):
    seed_db(rw_client)
    response = rw_client.get("/api/v1/db-url/pg", params={"database": "d&sslmode=disable"}, headers=H)
    # the database name is percent-encoded into the path; it cannot add query parameters
    assert response.status_code == 200 and "?" not in response.json()["url"].split("@")[1]
