"""Failed-auth throttling (H-2), streaming body limit (M-1), trusted proxies and security headers."""

import pytest

from app.client_ip import client_ip
from app.config import Config
from app.security.throttle import FailureTracker

from .conftest import FULL_KEY, auth


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


# ---------------------------------------------------------------------------
# FailureTracker (unit)
# ---------------------------------------------------------------------------


def make_tracker(limit=3, window=60, **kw):
    clock = Clock()
    return FailureTracker(lambda: limit, lambda: window, clock=clock, **kw), clock


def test_tracker_blocks_after_limit_and_reports_retry_after():
    tracker, clock = make_tracker(limit=3, window=60)
    for _ in range(2):
        tracker.record_failure("1.2.3.4")
    assert tracker.retry_after("1.2.3.4") == 0
    tracker.record_failure("1.2.3.4")
    assert tracker.retry_after("1.2.3.4") == 60
    clock.now += 10
    assert tracker.retry_after("1.2.3.4") == 50
    assert tracker.retry_after("5.6.7.8") == 0  # other clients unaffected


def test_tracker_window_slides():
    tracker, clock = make_tracker(limit=2, window=60)
    tracker.record_failure("c")
    clock.now += 40
    tracker.record_failure("c")
    assert tracker.retry_after("c") == 20  # blocked until the OLDEST failure ages out
    clock.now += 21
    assert tracker.retry_after("c") == 0


def test_tracker_continued_attacks_extend_the_block():
    tracker, clock = make_tracker(limit=2, window=60)
    for _ in range(5):
        tracker.record_failure("c")
        clock.now += 1
    assert tracker.retry_after("c") > 0
    clock.now += 62
    assert tracker.retry_after("c") == 0


def test_tracker_memory_is_bounded():
    tracker, _clock = make_tracker(limit=3, window=60, max_clients=50)
    for i in range(500):
        tracker.record_failure(f"10.0.{i // 250}.{i % 250}")
    assert len(tracker._failures) <= 50


def test_tracker_reset():
    tracker, _ = make_tracker(limit=1)
    tracker.record_failure("c")
    assert tracker.retry_after("c") > 0
    tracker.reset()
    assert tracker.retry_after("c") == 0


# ---------------------------------------------------------------------------
# throttling through the real app
# ---------------------------------------------------------------------------


def test_bad_keys_are_throttled_before_auth_runs(make_client, monkeypatch):
    """150 bad keys used to produce 150x401 and zero 429."""
    monkeypatch.setattr(Config, "AUTH_FAIL_LIMIT", 5)
    client = make_client()
    codes = [client.get("/api/v1/credentials", headers=auth(f"bad-{i}")).status_code for i in range(20)]
    assert codes[:5] == [401] * 5
    assert set(codes[5:]) == {429}


def test_blocked_client_gets_retry_after_and_security_headers(make_client, monkeypatch):
    monkeypatch.setattr(Config, "AUTH_FAIL_LIMIT", 2)
    client = make_client()
    for i in range(2):
        client.get("/api/v1/credentials", headers=auth(f"bad-{i}"))
    blocked = client.get("/api/v1/credentials", headers=auth(FULL_KEY))  # even a VALID key is refused while blocked
    assert blocked.status_code == 429
    assert 1 <= int(blocked.headers["retry-after"]) <= 60
    assert blocked.headers["x-content-type-options"] == "nosniff" and blocked.headers["cache-control"] == "no-store"
    assert blocked.json() == {"detail": "Too many failed authentication attempts"}


def test_throttle_does_not_touch_the_key_store(make_client, monkeypatch):
    monkeypatch.setattr(Config, "AUTH_FAIL_LIMIT", 1)
    client = make_client()
    client.get("/api/v1/credentials", headers=auth("bad"))
    import app.dependencies as deps

    def boom(*_a, **_k):
        raise AssertionError("authenticate() must not run for a throttled client")

    monkeypatch.setattr(deps, "authenticate", boom)
    assert client.get("/api/v1/credentials", headers=auth("bad-again")).status_code == 429


def test_successful_requests_never_count(make_client, monkeypatch):
    monkeypatch.setattr(Config, "AUTH_FAIL_LIMIT", 2)
    client = make_client()
    for _ in range(10):
        assert client.get("/api/v1/credentials", headers=auth()).status_code == 200


def test_valid_key_does_not_reset_the_failure_counter(make_client, monkeypatch):
    """Otherwise an attacker holding one low-privilege key could interleave it to stay under the limit."""
    monkeypatch.setattr(Config, "AUTH_FAIL_LIMIT", 3)
    client = make_client()
    codes = []
    for i in range(6):
        codes.append(client.get("/api/v1/credentials", headers=auth(f"bad-{i}")).status_code)
        codes.append(client.get("/api/v1/credentials", headers=auth()).status_code)
    assert 429 in codes


def test_forbidden_is_not_a_failed_authentication(make_client, monkeypatch, key_policy_file):
    monkeypatch.setattr(Config, "AUTH_FAIL_LIMIT", 2)
    from .conftest import READ_KEY

    client = make_client(API_KEY=None, API_KEYS_FILE=str(key_policy_file), ALLOW_WRITES=True)
    for _ in range(6):
        assert client.post("/api/v1/credentials/x", json={"value": "v"}, headers=auth(READ_KEY)).status_code == 403
    assert client.get("/api/v1/credentials", headers=auth(READ_KEY)).status_code == 200


def test_throttle_is_per_client_address_behind_trusted_proxies(make_client, monkeypatch):
    monkeypatch.setattr(Config, "AUTH_FAIL_LIMIT", 2)
    monkeypatch.setattr(Config, "TRUSTED_PROXY_HOPS", 1)
    client = make_client()
    attacker = {"X-Forwarded-For": "198.51.100.7"}
    bystander = {"X-Forwarded-For": "203.0.113.20"}
    for i in range(3):
        client.get("/api/v1/credentials", headers={**attacker, **auth(f"bad-{i}")})
    assert client.get("/api/v1/credentials", headers={**attacker, **auth()}).status_code == 429
    assert client.get("/api/v1/credentials", headers={**bystander, **auth()}).status_code == 200


def test_spoofed_forwarded_for_cannot_dodge_the_throttle(make_client, monkeypatch):
    """Only the entry appended by OUR proxy (rightmost) counts; client-supplied entries to its left are ignored."""
    monkeypatch.setattr(Config, "AUTH_FAIL_LIMIT", 2)
    monkeypatch.setattr(Config, "TRUSTED_PROXY_HOPS", 1)
    client = make_client()
    for i in range(3):  # attacker rotates fake leftmost addresses; our proxy always appends 198.51.100.7
        client.get("/api/v1/credentials", headers={"X-Forwarded-For": f"1.1.1.{i}, 198.51.100.7", **auth(f"bad-{i}")})
    blocked = client.get("/api/v1/credentials", headers={"X-Forwarded-For": "9.9.9.9, 198.51.100.7", **auth()})
    assert blocked.status_code == 429


def test_forwarded_for_is_ignored_when_no_proxies_are_trusted(make_client, monkeypatch):
    monkeypatch.setattr(Config, "AUTH_FAIL_LIMIT", 2)
    client = make_client()  # TRUSTED_PROXY_HOPS = 0
    for i in range(3):
        client.get("/api/v1/credentials", headers={"X-Forwarded-For": f"1.1.1.{i}", **auth(f"bad-{i}")})
    assert client.get("/api/v1/credentials", headers={"X-Forwarded-For": "8.8.8.8", **auth()}).status_code == 429


# ---------------------------------------------------------------------------
# client_ip
# ---------------------------------------------------------------------------


def scope(peer="10.0.0.1", xff=None):
    headers = [(b"x-forwarded-for", v.encode()) for v in ([xff] if isinstance(xff, str) else (xff or []))]
    return {"client": (peer, 5555), "headers": headers}


@pytest.mark.parametrize(
    "hops, xff, expected",
    [
        (0, "1.2.3.4", "10.0.0.1"),  # untrusted: header ignored
        (1, "1.2.3.4", "1.2.3.4"),
        (1, "6.6.6.6, 1.2.3.4", "1.2.3.4"),  # leftmost is client-controlled
        (2, "6.6.6.6, 1.2.3.4, 10.9.9.9", "1.2.3.4"),
        (2, "1.2.3.4", "10.0.0.1"),  # header shorter than the trusted chain: fall back to the peer
        (1, None, "10.0.0.1"),
        (1, "not-an-ip", "10.0.0.1"),
        (1, "1.2.3.4, <script>", "10.0.0.1"),
        (1, "2001:db8::1", "2001:db8::1"),
        (1, ["6.6.6.6", "1.2.3.4"], "1.2.3.4"),  # multiple header lines are joined
    ],
)
def test_client_ip(monkeypatch, hops, xff, expected):
    monkeypatch.setattr(Config, "TRUSTED_PROXY_HOPS", hops)
    assert client_ip(scope(xff=xff)) == expected


def test_client_ip_without_peer(monkeypatch):
    assert client_ip({"headers": []}) == "unknown"


# ---------------------------------------------------------------------------
# request body limit
# ---------------------------------------------------------------------------


def test_declared_oversized_body_is_rejected_unauthenticated(make_client):
    client = make_client(MAX_REQUEST_BODY_BYTES=1000)
    response = client.post("/api/v1/credentials/x", content=b"x" * 1001, headers={"Content-Type": "application/json"})
    assert response.status_code == 413
    assert response.headers["x-content-type-options"] == "nosniff"


def test_chunked_oversized_body_cannot_bypass_the_limit(make_client):
    """Only Content-Length was checked, so chunked bodies were buffered in full before auth."""
    client = make_client(MAX_REQUEST_BODY_BYTES=1000)
    received = []

    def body():
        for _ in range(100):
            received.append(1)
            yield b"[" + b"0," * 100  # ~300 bytes per chunk, no Content-Length

    response = client.post("/api/v1/credentials/x", content=body(), headers={"Content-Type": "application/json"})
    assert response.status_code == 413
    assert response.json() == {"detail": "Request body too large"}


def test_body_at_the_limit_is_accepted(rw_client, make_client):
    import json

    client = make_client(MAX_REQUEST_BODY_BYTES=300, ALLOW_WRITES=True)
    payload = json.dumps({"value": "v" * 200}).encode()
    assert len(payload) <= 300
    response = client.post(
        "/api/v1/credentials/at-limit", content=payload, headers={**auth(), "Content-Type": "application/json"}
    )
    assert response.status_code == 201


def test_invalid_content_length_is_400(make_client):
    client = make_client()
    response = client.post("/api/v1/credentials/x", content=b"{}", headers={"Content-Length": "abc"})
    assert response.status_code in (400, 422)  # rejected either by us or by the HTTP stack, never a 500


# ---------------------------------------------------------------------------
# security headers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "method, path, expected",
    [
        ("GET", "/health", 200),
        ("GET", "/api/v1/credentials", 401),
        ("GET", "/api/v1/credentials/x", 401),
        ("GET", "/no/such/path", 404),
        ("POST", "/api/v1/credentials/x", 401),
    ],
)
def test_security_headers_on_every_response(client, method, path, expected):
    response = client.request(method, path, json={"value": "v"} if method == "POST" else None)
    assert response.status_code == expected
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["cache-control"] == "no-store"


def test_docs_can_be_disabled(make_client):
    assert make_client().get("/api/v1/openapi.json").status_code == 200
    hidden = make_client(DISABLE_DOCS=True)
    for path in ("/api/v1/docs", "/api/v1/redoc", "/api/v1/openapi.json"):
        assert hidden.get(path).status_code == 404


def test_cors_is_closed_by_default(client):
    response = client.options(
        "/api/v1/credentials",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
    )
    assert "access-control-allow-origin" not in response.headers
