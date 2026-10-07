"""Regression tests for the independent security review of the server (findings numbered as in the review).

Findings without a test here either concern the library (tested in tests/test_review_findings.py at the repo root)
or were confirmed as "not an issue".
"""

import asyncio
import json
import logging
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest
from mattstash import MattStash

from app.client_ip import client_bucket, client_ip, parse_address
from app.config import Config
from app.logging_setup import configure_logging
from app.logsafe import printable
from app.security import api_keys
from app.security.api_keys import load_key_policy
from app.security.throttle import FailureTracker

from .conftest import ADMIN_KEY, APP_KEY, DB_PASSWORD, FULL_KEY, READ_KEY, auth

H = auth()
SERVER_DIR = Path(__file__).resolve().parent.parent


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


# ---------------------------------------------------------------------------
# #1 audit trail and access log are emitted by a REAL server process
# ---------------------------------------------------------------------------


def test_real_server_process_writes_audit_and_access_logs_with_key_ids(db_path, tmp_path):
    """`caplog` attaches a root handler, which hid that nothing configured these loggers in a real process."""
    from app.keytool import build_entry

    keys = tmp_path / "keys.json"
    keys.write_text(json.dumps({"keys": [build_entry("auditor", FULL_KEY, ["read"], [])]}))
    port = free_port()
    env = {
        **os.environ,
        "MATTSTASH_DB_PATH": str(db_path),
        "KDBX_PASSWORD": DB_PASSWORD,
        "MATTSTASH_API_KEYS_FILE": str(keys),
        "MATTSTASH_PORT": str(port),
        "MATTSTASH_HOST": "127.0.0.1",
        "MATTSTASH_LOG_LEVEL": "warning",  # the audit trail must not depend on the operational log level
    }
    proc = subprocess.Popen(
        [sys.executable, "-m", "app"],
        cwd=SERVER_DIR,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(100):
            try:
                if httpx.get(base + "/health", timeout=1).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.2)
        httpx.get(base + "/api/v1/credentials/some-secret?show_password=true", headers=auth(FULL_KEY))
        httpx.get(base + "/api/v1/credentials", headers=auth("definitely-not-a-valid-key-0123456789"))
        time.sleep(0.3)
    finally:
        proc.terminate()
        output = proc.communicate(timeout=20)[0]

    audit_lines = [line for line in output.splitlines() if " mattstash.audit " in line]
    assert any(
        "audit key=auditor" in line and "action=get" in line and "name=some-secret" in line and "reveal=True" in line
        for line in audit_lines
    ), output
    # (access log lines are operational: with LOG_LEVEL=warning they are correctly absent, the audit trail is not)
    assert FULL_KEY not in output and "definitely-not-a-valid-key" not in output


def test_real_server_access_log_has_client_status_and_key_id(db_path, tmp_path):
    port = free_port()
    env = {
        **os.environ,
        "MATTSTASH_DB_PATH": str(db_path),
        "KDBX_PASSWORD": DB_PASSWORD,
        "MATTSTASH_API_KEY": FULL_KEY,
        "MATTSTASH_PORT": str(port),
        "MATTSTASH_HOST": "127.0.0.1",
        "MATTSTASH_LOG_LEVEL": "info",
    }
    proc = subprocess.Popen(
        [sys.executable, "-m", "app"],
        cwd=SERVER_DIR,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(100):
            try:
                if httpx.get(base + "/health", timeout=1).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.2)
        httpx.get(base + "/api/v1/credentials", headers=auth(FULL_KEY))
        httpx.get(base + "/api/v1/credentials", headers=auth("wrong-key-0123456789012345678901234567"))
        time.sleep(0.3)
    finally:
        proc.terminate()
        output = proc.communicate(timeout=20)[0]

    access = [line for line in output.splitlines() if " mattstash.api GET /api/v1/credentials " in line]
    assert any("-> 200" in line and "client=127.0.0.1" in line and "key=legacy-env" in line for line in access), output
    assert any("-> 401" in line and "key=-" in line for line in access), output
    assert not any("HTTP/1.1" in line for line in output.splitlines() if "uvicorn" in line.lower()), (
        "uvicorn's anonymous access log should be off (ours has the key id)"
    )


def test_configure_logging_is_idempotent_and_audit_is_always_info(monkeypatch):
    monkeypatch.setattr(Config, "LOG_LEVEL", "error")
    for name in ("mattstash.api", "mattstash.audit"):
        logging.getLogger(name).handlers.clear()
    configure_logging()
    configure_logging()
    api, audit = logging.getLogger("mattstash.api"), logging.getLogger("mattstash.audit")
    assert len(api.handlers) == 1 and len(audit.handlers) == 1
    assert api.level == logging.ERROR and audit.level == logging.INFO  # audit ignores MATTSTASH_LOG_LEVEL
    monkeypatch.setattr(Config, "LOG_LEVEL", "nonsense")
    configure_logging()
    assert api.level == logging.INFO  # unknown level falls back to info


# ---------------------------------------------------------------------------
# #2 throttle cannot be bypassed by concurrency
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_burst_of_bad_keys_cannot_exceed_the_limit(configure, monkeypatch):
    """check and record used to be separated by awaits: ~1500 attempts passed against a limit of 10."""
    configure()
    monkeypatch.setattr(Config, "AUTH_FAIL_LIMIT", 10)
    from app.main import create_app

    transport = httpx.ASGITransport(app=create_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        responses = await asyncio.gather(
            *[http.get("/api/v1/credentials", headers=auth(f"bad-key-{i:04d}-" + "x" * 30)) for i in range(300)]
        )
    codes = [r.status_code for r in responses]
    assert codes.count(401) == 10 and codes.count(429) == 290


@pytest.mark.asyncio
async def test_concurrent_burst_mixing_valid_and_invalid_keys(configure, monkeypatch):
    configure()
    monkeypatch.setattr(Config, "AUTH_FAIL_LIMIT", 5)
    from app.main import create_app

    transport = httpx.ASGITransport(app=create_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        responses = await asyncio.gather(
            *[
                http.get("/api/v1/credentials", headers=auth(FULL_KEY if i % 2 else f"bad-{i:04d}" + "y" * 30))
                for i in range(100)
            ]
        )
    assert sum(r.status_code == 401 for r in responses) <= 5  # never more failures than the limit allows


# ---------------------------------------------------------------------------
# #3 IPv6 /64 buckets, address normalisation  /  #4b X-Forwarded-For shapes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text, expected",
    [
        ("1.2.3.4", "1.2.3.4"),
        ("1.2.3.4:5555", "1.2.3.4"),
        (" 1.2.3.4 ", "1.2.3.4"),
        ("2001:db8::1", "2001:db8::1"),
        ("[2001:db8::1]", "2001:db8::1"),
        ("[2001:db8::1]:443", "2001:db8::1"),
        ("fe80::1%eth0", "fe80::1"),  # scope id dropped
        ("::ffff:1.2.3.4", "1.2.3.4"),  # IPv4-mapped is the IPv4 address
        ("[::ffff:1.2.3.4]:80", "1.2.3.4"),
        ("unknown", None),
        ("01.02.03.04", None),
        ("1.2.3.4:99999x", None),
        ("[2001:db8::1", None),
        ("[2001:db8::1]junk", None),
        ("fe80::1%a\nb", "fe80::1"),  # the scope id (where control characters hide) is discarded entirely
        ("", None),
    ],
)
def test_parse_address(text, expected):
    ip = parse_address(text)
    assert (str(ip) if ip is not None else None) == expected


def scope(peer="10.0.0.1", xff=None):
    headers = [(b"x-forwarded-for", xff.encode())] if xff else []
    return {"client": (peer, 5555), "headers": headers}


def test_ipv6_clients_share_one_bucket_per_64(monkeypatch):
    buckets = {client_bucket(scope(peer=f"2001:db8:abcd:12::{i:x}")) for i in range(1, 40)}
    assert buckets == {"2001:db8:abcd:12::/64"}
    assert client_bucket(scope(peer="2001:db8:abcd:13::1")) != "2001:db8:abcd:12::/64"  # a different /64 is separate
    assert client_bucket(scope(peer="::ffff:1.2.3.4")) == client_bucket(scope(peer="1.2.3.4")) == "1.2.3.4"


def test_client_ip_is_clean_for_logging(monkeypatch):
    monkeypatch.setattr(Config, "TRUSTED_PROXY_HOPS", 1)
    assert (
        client_ip(scope(xff="fe80::1%a\nb")) == "fe80::1"
    )  # the scope id, and any control characters in it, is dropped
    assert client_ip(scope(xff="6.6.6.6, [2001:db8::7]:443")) == "2001:db8::7"
    assert client_ip({"headers": []}) == "unknown"


def test_forwarded_for_with_ports_is_understood_not_ignored(monkeypatch):
    """A header the parser rejected used to collapse every client into the proxy's single bucket."""
    monkeypatch.setattr(Config, "TRUSTED_PROXY_HOPS", 1)
    assert client_bucket(scope(xff="203.0.113.5:51234")) == "203.0.113.5"
    assert client_bucket(scope(xff="203.0.113.6:51234")) == "203.0.113.6"


def test_ipv6_attacker_cannot_dodge_the_throttle_by_rotating_addresses(make_client, monkeypatch):
    monkeypatch.setattr(Config, "AUTH_FAIL_LIMIT", 5)
    monkeypatch.setattr(Config, "TRUSTED_PROXY_HOPS", 1)
    client = make_client()
    codes = [
        client.get(
            "/api/v1/credentials", headers={"X-Forwarded-For": f"2001:db8:1:2::{i:x}", **auth(f"bad-{i}" + "z" * 30)}
        ).status_code
        for i in range(1, 31)
    ]
    assert codes.count(401) == 5 and codes.count(429) == 25  # was: 30 x 401, one fresh budget per address
    other_subscriber = {"X-Forwarded-For": "2001:db8:99::1", **auth()}
    assert client.get("/api/v1/credentials", headers=other_subscriber).status_code == 200


# ---------------------------------------------------------------------------
# #4a probes are never throttled  /  #4c tracker eviction is O(1)
# ---------------------------------------------------------------------------


def test_health_and_ready_are_exempt_from_the_throttle(make_client, monkeypatch):
    """A blocked address (e.g. an ingress shared by everyone) must not fail the pod's own probes."""
    monkeypatch.setattr(Config, "AUTH_FAIL_LIMIT", 2)
    client = make_client()
    for i in range(3):
        client.get("/api/v1/credentials", headers=auth(f"bad-{i}" + "q" * 30))
    assert client.get("/api/v1/credentials", headers=auth()).status_code == 429  # blocked...
    for path in ("/health", "/api/health", "/ready", "/api/ready"):
        assert client.get(path).status_code == 200  # ...but probes still pass


def test_tracker_eviction_does_not_scan_and_evicts_least_recently_active():
    tracker = FailureTracker(lambda: 3, lambda: 60, max_clients=1000)
    started = time.perf_counter()
    for i in range(30_000):  # 29k inserts beyond the cap; a full scan per insert took ~2 ms each
        tracker.record_failure(f"client-{i}")
    assert time.perf_counter() - started < 2.0
    assert len(tracker._failures) == 1000
    assert "client-29999" in tracker._failures and "client-0" not in tracker._failures

    tracker.record_failure("client-29000")  # activity refreshes a client...
    for i in range(30_000, 30_999):
        tracker.record_failure(f"client-{i}")
    assert "client-29000" in tracker._failures  # ...so an active attacker is not the one evicted


# ---------------------------------------------------------------------------
# #9 key revocation
# ---------------------------------------------------------------------------


def test_invalidate_works_on_a_freshly_booted_host(monkeypatch, tmp_path):
    """time.monotonic() counts from boot; a stale marker of 0.0 meant 'loaded just now' on a young host."""
    keys = tmp_path / "keys"
    keys.write_text("o" * 40 + "\n")
    monkeypatch.setattr(Config, "API_KEYS_FILE", str(keys))
    monkeypatch.setattr(api_keys.time, "monotonic", lambda: 100.0)  # host booted 100 s ago
    assert api_keys.verify_api_key("o" * 40)
    keys.write_text("n" * 40 + "\n")
    api_keys.invalidate_api_key_cache()
    assert not api_keys.verify_api_key("o" * 40) and api_keys.verify_api_key("n" * 40)


def test_admin_invalidate_reports_failure_when_the_new_policy_cannot_load(make_client, tmp_path):
    keys = tmp_path / "keys.json"
    keys.write_text(json.dumps({"keys": [{"id": "ops", "key": ADMIN_KEY, "ops": ["admin"]}]}))
    client = make_client(API_KEY=None, API_KEYS_FILE=str(keys))
    admin = auth(ADMIN_KEY)

    ok = client.post("/api/v1/admin/invalidate-api-key-cache", headers=admin)
    assert ok.status_code == 200 and ok.json() == {"status": "api_key_cache_invalidated", "keys": 1}

    keys.write_text("{ this is not valid json")  # a botched edit while trying to revoke a key
    failed = client.post("/api/v1/admin/invalidate-api-key-cache", headers=admin)
    assert failed.status_code == 409 and "previous keys are still active" in failed.json()["detail"]
    assert client.get("/api/v1/credentials", headers=admin).status_code == 403  # old policy still serves (admin only)


def test_reload_key_policy_now_replaces_the_policy_atomically(monkeypatch, tmp_path):
    keys = tmp_path / "keys"
    keys.write_text("o" * 40 + "\n")
    monkeypatch.setattr(Config, "API_KEYS_FILE", str(keys))
    assert api_keys.verify_api_key("o" * 40)
    keys.write_text("")
    with pytest.raises(ValueError):
        api_keys.reload_key_policy_now()
    assert api_keys.verify_api_key("o" * 40)  # a failed reload changes nothing
    keys.write_text("n" * 40 + "\n")
    assert len(api_keys.reload_key_policy_now()) == 1
    assert api_keys.verify_api_key("n" * 40) and not api_keys.verify_api_key("o" * 40)


# ---------------------------------------------------------------------------
# #10 log injection
# ---------------------------------------------------------------------------


def test_untrusted_path_cannot_forge_log_records(client, caplog):
    caplog.set_level(logging.INFO)
    forged = "/x%0A2026-10-07 12:00:00 INFO mattstash.audit audit key=admin action=delete name=prod-db-password"
    client.get(forged, headers=H)
    client.get(forged)  # unauthenticated too
    for record in caplog.records:
        message = record.getMessage()
        assert "\n" not in message and "\r" not in message, message
    assert any("\\x0a" in r.getMessage() for r in caplog.records)  # escaped, still visible to an operator
    assert not any(r.name == "mattstash.audit" and "name=prod-db-password" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("plain-text_1.2", "plain-text_1.2"),
        ("a\nb", "a\\x0ab"),
        ("a\r\nb", "a\\x0d\\x0ab"),
        ("é", "\\xe9"),
        ("\x1b[31m", "\\x1b[31m"),
    ],
)
def test_printable(raw, expected):
    assert printable(raw) == expected


# ---------------------------------------------------------------------------
# #11 key policy file parsing
# ---------------------------------------------------------------------------


def test_comment_plus_minified_json_is_a_policy_not_a_legacy_key(monkeypatch, tmp_path):
    """The whole JSON text used to be accepted as ONE legacy full-access key (fail open)."""
    from app.keytool import build_entry

    text = "# generated for billing\n" + json.dumps({"keys": [build_entry("billing", READ_KEY, ["read"], ["bill-"])]})
    path = tmp_path / "keys"
    path.write_text(text)
    monkeypatch.setattr(Config, "API_KEYS_FILE", str(path))
    policy = load_key_policy()
    assert policy.authenticate(text) is None  # the file's own text is not a credential
    assert policy.authenticate(READ_KEY).id == "billing" and policy.legacy_count == 0


def test_utf8_bom_is_tolerated(monkeypatch, tmp_path):
    path = tmp_path / "keys"
    path.write_bytes(b"\xef\xbb\xbf" + b"b" * 40 + b"\n" + b"c" * 40 + b"\n")
    monkeypatch.setattr(Config, "API_KEYS_FILE", str(path))
    policy = load_key_policy()
    assert policy.authenticate("b" * 40) and policy.authenticate("c" * 40)  # the first key used to carry the BOM

    path.write_bytes(b"\xef\xbb\xbf" + json.dumps({"keys": [{"id": "a", "key": APP_KEY}]}).encode())
    assert load_key_policy().authenticate(APP_KEY).id == "a"


def test_whitespace_inside_a_legacy_key_line_is_rejected(monkeypatch, tmp_path):
    path = tmp_path / "keys"
    path.write_text("k" * 40 + " trailing words\n")
    monkeypatch.setattr(Config, "API_KEYS_FILE", str(path))
    with pytest.raises(ValueError, match=r"line 1.*whitespace"):
        load_key_policy()


def test_duplicate_json_fields_are_rejected_not_last_wins(monkeypatch, tmp_path):
    entry = '{"id": "a", "key": "' + APP_KEY + '", "ops": ["read"], "ops": ["admin"]}'
    path = tmp_path / "keys.json"
    path.write_text('{"keys": [' + entry + "]}")
    monkeypatch.setattr(Config, "API_KEYS_FILE", str(path))
    with pytest.raises(ValueError, match="duplicate field 'ops'"):
        load_key_policy()


def test_legacy_principal_ids_are_positional_and_do_not_leak_a_key_hash(monkeypatch, tmp_path):
    import hashlib

    path = tmp_path / "keys"
    path.write_text("a" * 40 + "\n" + "b" * 40 + "\n")
    monkeypatch.setattr(Config, "API_KEY", FULL_KEY)
    monkeypatch.setattr(Config, "API_KEYS_FILE", str(path))
    policy = load_key_policy()
    ids = [policy.authenticate(k).id for k in (FULL_KEY, "a" * 40, "b" * 40)]
    assert ids == ["legacy-env", "legacy-1", "legacy-2"]
    keys = (FULL_KEY, "a" * 40, "b" * 40)
    assert not any(hashlib.sha256(k.encode()).hexdigest()[:8] in i for k, i in zip(keys, ids, strict=True))


# ---------------------------------------------------------------------------
# #12 db-url 404s, #13 422 bodies, #14 denied audit, #17 rate limit validation
# ---------------------------------------------------------------------------


@pytest.fixture
def scoped(make_client, key_policy_file, seed):
    seed(app__db={"username": "u", "password": "p", "url": "h:5432"}, app__token={"value": "t"}, other={"value": "x"})
    return make_client(API_KEY=None, API_KEYS_FILE=str(key_policy_file), ALLOW_WRITES=True)


def test_db_url_out_of_scope_matches_every_in_scope_miss(scoped):
    h = auth(APP_KEY)
    out_of_scope = scoped.get("/api/v1/db-url/other?database=d", headers=h)
    missing = scoped.get("/api/v1/db-url/app-nonexistent?database=d", headers=h)
    simple_secret = scoped.get("/api/v1/db-url/app-token?database=d", headers=h)
    assert out_of_scope.status_code == missing.status_code == simple_secret.status_code == 404
    normalised = {
        r.json()["detail"].replace("other", "N").replace("app-nonexistent", "N").replace("app-token", "N")
        for r in (out_of_scope, missing, simple_secret)
    }
    assert len(normalised) == 1  # the key's prefix boundary cannot be inferred from the wording


def test_validation_errors_do_not_echo_submitted_secrets(rw_client):
    mixed = rw_client.post("/api/v1/credentials/x", json={"value": "S3CRET-VALUE", "password": "S3CRET-PW"}, headers=H)
    wrong_type = rw_client.post("/api/v1/credentials/x", json={"password": 12345678, "username": "n" * 300}, headers=H)
    for response in (mixed, wrong_type):
        assert response.status_code == 422
        assert "S3CRET" not in response.text and "12345678" not in response.text and "nnnnnnnn" not in response.text
        detail = response.json()["detail"]
        assert detail and all(set(item) == {"loc", "msg", "type"} for item in detail)


def test_denied_requests_are_audited_with_key_id_and_name(scoped, caplog):
    caplog.set_level(logging.INFO)
    scoped.get("/api/v1/credentials/other", headers=auth(APP_KEY))  # read outside prefix
    scoped.post("/api/v1/credentials/other", json={"value": "v"}, headers=auth(APP_KEY))  # write outside prefix
    scoped.delete("/api/v1/credentials/other", headers=auth(APP_KEY))  # delete outside prefix
    scoped.post("/api/v1/credentials/app-x", json={"value": "v"}, headers=auth(READ_KEY))  # op not allowed
    lines = [
        r.getMessage() for r in caplog.records if r.name == "mattstash.audit" and "action=denied" in r.getMessage()
    ]
    assert sum("key=app " in line and "name=other" in line for line in lines) == 3
    assert any("key=reader " in line and "op=write" in line for line in lines)
    assert not any(APP_KEY in line or READ_KEY in line for line in lines)


@pytest.mark.parametrize("bad", ["bogus", "100", "5/fortnight", ""])
def test_invalid_rate_limit_fails_startup_instead_of_500ing_every_request(configure, bad):
    from fastapi.testclient import TestClient

    from app.main import create_app

    configure(RATE_LIMIT=bad)
    with pytest.raises(ValueError, match="MATTSTASH_RATE_LIMIT"):
        with TestClient(create_app()):
            pass


def test_valid_rate_limits_start(configure):
    from fastapi.testclient import TestClient

    from app.main import create_app

    for good in ("100/minute", "5/second", "1000 per hour", "10/minute;100/hour"):
        configure(RATE_LIMIT=good)
        with TestClient(create_app()):
            pass


# ---------------------------------------------------------------------------
# sidecar backups, path validation exactness
# ---------------------------------------------------------------------------


def test_sidecar_backups_next_to_the_database_are_flagged_too(configure, db_path, caplog):
    from fastapi.testclient import TestClient

    from app.main import create_app

    (db_path.parent / ".mattstash.txt.bak-20261007T000000Z").write_text("old-master-password")
    configure()
    caplog.set_level(logging.WARNING, logger="mattstash.api")
    with TestClient(create_app()):
        pass
    assert ".mattstash.txt.bak-20261007T000000Z" in caplog.text and "old-master-password" not in caplog.text


@pytest.mark.parametrize("name", ["foo%0A", "foo%0D%0A", ".hidden", "a%20b", "a@1", "%C3%BCber", "foo%00bar", ".x"])
def test_invalid_names_are_exactly_400_on_every_route(rw_client, name):
    """The earlier test accepted (400, 404): removing the validator from a route would have gone unnoticed."""
    for response in (
        rw_client.get(f"/api/v1/credentials/{name}", headers=H),
        rw_client.get(f"/api/v1/credentials/{name}/versions", headers=H),
        rw_client.get(f"/api/v1/db-url/{name}", headers=H),
        rw_client.post(f"/api/v1/credentials/{name}", json={"value": "v"}, headers=H),
        rw_client.delete(f"/api/v1/credentials/{name}", headers=H),
    ):
        assert response.status_code == 400, (name, response.request.method, response.request.url)


def test_encoded_slash_never_reaches_a_handler(rw_client):
    assert rw_client.get("/api/v1/credentials/a%2Fb", headers=H).status_code in (400, 404)


# ---------------------------------------------------------------------------
# Python-level sanity for the fast path used by the middleware
# ---------------------------------------------------------------------------


def test_public_paths_follow_the_docs_setting(monkeypatch):
    from app.middleware.security import public_paths

    assert "/api/v1/docs" in public_paths() and "/health" in public_paths()
    monkeypatch.setattr(Config, "DISABLE_DOCS", True)
    assert "/api/v1/docs" not in public_paths() and {"/health", "/ready"} <= public_paths()


# ---------------------------------------------------------------------------
# Round 2: F3 rate limit per route (not per URL), Retry-After; F4/F5 db-url
# ---------------------------------------------------------------------------


def test_f3_rate_limit_applies_per_route_not_per_secret_name(make_client, monkeypatch):
    """Every distinct name used to get its own bucket, so enumerating names was never limited."""
    monkeypatch.setattr(Config, "RATE_LIMIT", "5/minute")
    client = make_client()
    codes = [client.get(f"/api/v1/credentials/name-{n}", headers=H).status_code for n in range(12)]
    assert codes[:5] == [404] * 5 and set(codes[5:]) == {429}, codes
    limited = client.get("/api/v1/credentials/another-name", headers=H)
    assert limited.status_code == 429
    assert int(limited.headers["Retry-After"]) >= 1, "clients (the CLI's env/exec) back off using this"


def test_f3_write_limit_applies_across_names(make_client):
    client = make_client(ALLOW_WRITES=True)
    codes = [client.post(f"/api/v1/credentials/w-{n}", json={"value": "v"}, headers=H).status_code for n in range(34)]
    assert codes.count(201) == 30 and codes.count(429) == 4, "30/minute is a per-client limit, whatever the names"


def _seed_pg(client, **fields):
    body = {"username": "u", "password": "p", "url": "db.internal:5432", **fields}
    assert client.post("/api/v1/credentials/pg", json=body, headers=H).status_code == 201


def test_f4_driver_case_and_empty_driver(rw_client):
    _seed_pg(rw_client)
    get = lambda **params: rw_client.get(  # noqa: E731
        "/api/v1/db-url/pg", params={"database": "d", **params}, headers=H
    )
    assert get(driver="PSYCOPG").json()["url"].startswith("postgresql+psycopg://")
    assert get(driver=" psycopg ").status_code == 200
    assert get(driver="AUTO").json()["url"].startswith("postgresql+psycopg://")
    assert get(driver="").json()["url"].startswith("postgresql://"), "'' means: no driver suffix, as locally"


def test_f5_specific_but_value_free_reasons(rw_client):
    _seed_pg(rw_client, url="db.internal")  # no port
    response = rw_client.get("/api/v1/db-url/pg", params={"database": "d"}, headers=H)
    assert response.status_code == 400
    assert response.json()["detail"] == "Entry cannot be used for a database URL: the entry's URL has no port"
    _seed_pg(rw_client, url="db.internal:5432")  # fine now, but no database name given
    response = rw_client.get("/api/v1/db-url/pg", headers=H)
    assert response.status_code == 400 and "no database name" in response.json()["detail"]
    assert "db.internal" not in response.text, "nothing stored in the entry is echoed back"


def test_c3_queued_writes_are_capped_so_a_stuck_lock_cannot_use_up_every_worker_thread(make_client, monkeypatch):
    """Writers wait for the database lock inside worker threads; unbounded, 40 of them starve reads and /ready."""
    import threading

    monkeypatch.setattr(Config, "MAX_CONCURRENT_WRITES", 2)
    client = make_client(ALLOW_WRITES=True)
    real_put = MattStash.put

    def slow_put(self, *args, **kwargs):
        time.sleep(0.8)
        return real_put(self, *args, **kwargs)

    monkeypatch.setattr(MattStash, "put", slow_put)
    codes: list[int] = []
    retry_after: list[str] = []

    def write(n: int) -> None:
        response = client.post(f"/api/v1/credentials/slot-{n}", json={"value": "v"}, headers=H)
        codes.append(response.status_code)
        if response.status_code == 503:
            retry_after.append(response.headers.get("Retry-After", ""))

    threads = [threading.Thread(target=write, args=(n,)) for n in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert sorted(codes) == [201, 201, 503, 503, 503], codes
    assert set(retry_after) == {"1"}
    # the slots are released afterwards
    assert client.post("/api/v1/credentials/after", json={"value": "v"}, headers=H).status_code == 201
