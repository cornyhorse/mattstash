"""Final-review fixes: lockout with scoped v1 admin keys, deep bodies, pasted tokens, empty durations, log fields."""

import json
import logging
import os
from pathlib import Path

import pytest
from mattstash.authz import load_policy

from .conftest import FULL_KEY, auth

BASE = "/api/v1/admin"


def bearer(token: str) -> dict[str, str]:
    return auth(token)


@pytest.fixture
def log_path(tmp_path) -> str:
    return str(tmp_path / "logs" / "access.jsonl")


@pytest.fixture
def admin_client(make_client, policy_path, policy_tokens, log_path, data):
    os.makedirs(os.path.dirname(log_path))
    client = make_client(API_KEY=None, POLICY_FILE=policy_path, ACCESS_LOG_FILE=log_path, ALLOW_WRITES=True)
    client.headers.update(bearer(policy_tokens["matt"]))
    return client


def records(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle]


# 1 --------------------------------------------------------------------------------------------------------------


def test_a_scoped_v1_admin_key_does_not_waive_the_lockout_check(
    make_client, policy_path, policy_tokens, key_policy_file
):
    client = make_client(API_KEY=None, POLICY_FILE=policy_path, API_KEYS_FILE=str(key_policy_file))
    matt = policy_tokens["matt"]
    response = client.delete(f"{BASE}/principals/matt/tokens/{matt.split('_')[1]}", headers=bearer(matt))
    assert response.status_code == 400 and "no admin principal" in response.json()["detail"]
    assert load_policy(policy_path).principal("matt").tokens  # nothing changed


def test_an_unscoped_legacy_key_still_waives_the_lockout_check(make_client, policy_path, policy_tokens):
    client = make_client(API_KEY=FULL_KEY, POLICY_FILE=policy_path)
    matt = policy_tokens["matt"]
    response = client.delete(f"{BASE}/principals/matt/tokens/{matt.split('_')[1]}", headers=bearer(matt))
    assert response.status_code == 200


# 2 --------------------------------------------------------------------------------------------------------------

DEEP = b"[" * 100_000  # deeper than any interpreter's parser recursion limit (5000 is not on 3.13)


def test_a_deeply_nested_body_is_not_parsed_where_nothing_of_it_is_logged(admin_client):
    response = admin_client.post(f"{BASE}/reload", content=DEEP, headers={"Content-Type": "application/json"})
    assert response.status_code == 200


@pytest.mark.parametrize("path", ["/principals", "/grants", "/check"])
def test_a_deeply_nested_body_is_a_client_error_not_a_crash(admin_client, path):
    response = admin_client.post(BASE + path, content=DEEP, headers={"Content-Type": "application/json"})
    assert 400 <= response.status_code < 500


# 3 --------------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("suffix", ["", "/rotate"])
def test_a_full_token_used_as_a_token_id_is_not_echoed_or_logged(
    admin_client, policy_tokens, log_path, caplog, tmp_path, suffix
):
    secret = policy_tokens["hermes"]
    caplog.set_level(logging.DEBUG)
    call = admin_client.delete if not suffix else admin_client.post
    response = call(f"{BASE}/principals/hermes/tokens/{secret}{suffix}")
    assert response.status_code == 404 and response.json() == {"detail": "Token not found"}
    assert secret not in response.text
    secret_part = secret.split("_", 2)[2]
    server_records = [r for r in caplog.records if r.name.startswith("mattstash")]  # not the test client's own
    for record in server_records:
        assert secret_part not in record.getMessage() and secret not in record.getMessage()
        assert secret_part not in repr(record.__dict__)
    assert any("mst_…" in r.getMessage() for r in server_records if r.name == "mattstash.api")
    text = Path(log_path).read_text(encoding="utf-8")
    assert secret_part not in text and secret not in text
    last = records(log_path)[-1]
    assert last["decision"] == "allowed" and "target_token" not in last
    assert load_policy(tmp_path / "policy.json").principal("hermes").tokens  # nothing was revoked


def test_a_well_formed_token_id_is_still_logged_as_the_target(admin_client, policy_tokens, log_path):
    token_id = policy_tokens["hermes"].split("_")[1]
    assert admin_client.delete(f"{BASE}/principals/hermes/tokens/{token_id}").status_code == 200
    assert records(log_path)[-1]["target_token"] == token_id


# 5 --------------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("POST", "/principals/lister/tokens", {"expires": ""}),
        ("POST", "/grants", {"principal": "lister", "key": "x", "expires": ""}),
        ("POST", "/principals/hermes/tokens/{id}/rotate", {"expires": ""}),
        ("POST", "/principals/hermes/tokens/{id}/rotate", {"grace": ""}),
    ],
)
def test_an_empty_expiry_or_grace_is_refused_not_read_as_never(
    admin_client, policy_tokens, policy_path, method, path, body
):
    before = Path(policy_path).read_text()
    response = admin_client.request(method, BASE + path.format(id=policy_tokens["hermes"].split("_")[1]), json=body)
    assert response.status_code == 422
    assert Path(policy_path).read_text() == before


# 6 --------------------------------------------------------------------------------------------------------------


def test_delete_of_one_version_records_the_version_in_the_access_line(
    make_client, policy_path, policy_tokens, log_path, data
):
    os.makedirs(os.path.dirname(log_path))
    client = make_client(API_KEY=None, POLICY_FILE=policy_path, ACCESS_LOG_FILE=log_path, ALLOW_WRITES=True)
    scribe = bearer(policy_tokens["scribe"])
    client.delete("/api/v1/credentials/app-db?version=1", headers=scribe)
    client.delete("/api/v1/credentials/other?version=3", headers=scribe)  # denied: still names the version
    allowed, denied = records(log_path)
    assert allowed["decision"] == "allowed" and allowed["version"] == 1
    assert denied["decision"] == "denied" and denied["version"] == 3


def test_json_object_gives_nothing_for_unparseable_or_too_deep_input():
    from app.dependencies import _json_object

    assert _json_object(DEEP) == {} and _json_object(b"{bad") == {} and _json_object(b"[1]") == {}
    assert _json_object(b'{"a": 1}') == {"a": 1}
