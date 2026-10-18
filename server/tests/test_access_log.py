"""The structured access log: one line per request, never a secret, rotated, mode 0600, and fail closed."""

import errno
import json
import logging
import os
import stat
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.responses import Response

from app import accesslog
from app.main import create_app

from .conftest import FULL_KEY, auth

BASE = "/api/v1/admin"


def bearer(token: str) -> dict[str, str]:
    return auth(token)


@pytest.fixture
def log_path(tmp_path) -> str:
    return str(tmp_path / "access.jsonl")


@pytest.fixture
def lc(make_client, policy_path, log_path, data):
    """Client for the policy file with a file sink."""
    return make_client(API_KEY=None, POLICY_FILE=policy_path, ACCESS_LOG_FILE=log_path, ALLOW_WRITES=True)


def file_records(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle]


def last(path: str) -> dict:
    return file_records(path)[-1]


# ---------------------------------------------------------------------------
# what is logged
# ---------------------------------------------------------------------------


def test_an_allowed_read_is_one_line_with_every_field(lc, log_path, policy_tokens, policy_path):
    from mattstash.authz import load_policy

    grant = next(g for g in load_policy(policy_path).grants if g.principal == "hermes" and g.key == "firefly.*")
    lc.get("/api/v1/credentials/firefly.token?show_password=true", headers=bearer(policy_tokens["hermes"]))
    (record,) = file_records(log_path)
    assert set(record) == {
        "ts", "principal", "kind", "token", "action", "route", "key", "decision", "grant", "client", "status"
    }  # fmt: skip
    assert record["principal"] == "hermes" and record["kind"] == "agent"
    assert record["token"] == policy_tokens["hermes"].split("_")[1]
    assert (record["action"], record["route"], record["key"]) == ("read", "get", "firefly.token")
    assert record["decision"] == "allowed" and record["grant"] == grant.id and record["status"] == 200
    assert record["ts"].endswith("Z") and record["client"]
    assert list(record)[:3] == ["ts", "principal", "kind"]  # stable field order


def test_denied_reads_and_writes_carry_a_reason_and_the_real_status(lc, log_path, policy_tokens):
    hermes, scribe = bearer(policy_tokens["hermes"]), bearer(policy_tokens["scribe"])
    lc.get("/api/v1/credentials/other", headers=hermes)
    lc.get("/api/v1/credentials/other/versions", headers=hermes)
    lc.get("/api/v1/db-url/other", headers=hermes)
    lc.post("/api/v1/credentials/other", json={"value": "x"}, headers=scribe)
    lc.delete("/api/v1/credentials/other", headers=scribe)
    lc.post("/api/v1/credentials/app-y", json={"value": "x"}, headers=hermes)  # holds no write grant at all
    lc.delete("/api/v1/credentials/app-y", headers=hermes)
    records = file_records(log_path)
    assert [(r["action"], r["route"], r["status"]) for r in records] == [
        ("read", "get", 404),
        ("read", "versions", 404),
        ("read", "db-url", 404),
        ("write", "put", 403),
        ("delete", "delete", 403),
        ("write", "put", 403),
        ("delete", "delete", 403),
    ]
    assert all(r["decision"] == "denied" and r["reason"] == "no-grant" and "grant" not in r for r in records)
    assert [r["key"] for r in records] == ["other"] * 5 + ["app-y"] * 2


def test_writes_and_deletes_are_logged_with_their_grant(lc, log_path, policy_tokens):
    scribe = bearer(policy_tokens["scribe"])
    lc.post("/api/v1/credentials/app-new", json={"value": "write-secret-xyz"}, headers=scribe)
    lc.delete("/api/v1/credentials/app-new", headers=scribe)
    put, delete = file_records(log_path)
    assert (put["action"], put["route"], put["decision"], put["status"]) == ("write", "put", "allowed", 201)
    assert (delete["action"], delete["route"], delete["decision"], delete["status"]) == (
        "delete",
        "delete",
        "allowed",
        200,
    )
    assert put["grant"] == delete["grant"] and put["grant"].startswith("g_")


def test_list_and_search_log_the_filter_and_the_count_not_the_names(lc, log_path, policy_tokens):
    h = bearer(policy_tokens["fireflyer"])
    lc.get("/api/v1/credentials", headers=h)
    lc.get("/api/v1/credentials", params={"prefix": "firefly."}, headers=h)
    lc.get("/api/v1/search", params={"q": "fire", "tag": "shared"}, headers=bearer(policy_tokens["runner"]))
    lc.get("/api/v1/search", params={"tag": "shared"}, headers=bearer(policy_tokens["runner"]))
    plain, prefixed, both, tag_only = file_records(log_path)
    assert (plain["action"], plain["route"], plain["count"], "key" not in plain) == ("list", "list", 2, True)
    assert (prefixed["key"], prefixed["count"]) == ("firefly.", 2)
    assert (both["action"], both["route"], both["key"], both["tag"], both["count"]) == (
        "list",
        "search",
        "fire",
        "shared",
        0,
    )
    assert (tag_only["tag"], tag_only["count"]) == ("shared", 3) and "key" not in tag_only
    assert all(r["decision"] == "allowed" and r["status"] == 200 for r in (plain, prefixed, both, tag_only))
    assert "firefly.token" not in Path(log_path).read_text()  # counts, never the names that were returned


def test_authentication_failures_are_logged_with_the_reason_and_no_principal(lc, log_path, policy_tokens):
    from mattstash.authz import generate_token

    unknown = generate_token()[1]
    attempts = [
        ({}, "no-token"),
        ({"X-API-Key": "plain-wrong-key-" + "z" * 30}, "bad-token"),
        (bearer(unknown), "unknown-token"),
        (bearer(policy_tokens["hermes"][:-2] + "xx"), "bad-token"),
        (bearer(policy_tokens["expired"]), "expired-token"),
        (bearer(policy_tokens["off"]), "disabled"),
        ({"X-API-Key": "mst_nope"}, "bad-token"),
    ]
    for headers, _ in attempts:
        assert lc.get("/api/v1/credentials", headers=headers).status_code == 401
    records = file_records(log_path)
    assert [r["reason"] for r in records] == [reason for _, reason in attempts]
    for record in records:
        assert (record["principal"], record["decision"], record["status"]) == ("-", "denied", 401)
        assert "kind" not in record and "action" not in record
    # a token id is logged only when the token parsed: never part of a malformed or non-token key
    assert records[2]["token"] == unknown.split("_")[1]
    assert records[3]["token"] == policy_tokens["hermes"].split("_")[1]
    assert records[4]["token"] and records[5]["token"]
    assert all("token" not in records[i] for i in (0, 1, 6))


def test_throttled_requests_are_logged(make_client, policy_path, policy_tokens, log_path, data):
    client = make_client(API_KEY=None, POLICY_FILE=policy_path, ACCESS_LOG_FILE=log_path, AUTH_FAIL_LIMIT=2)
    for _ in range(2):
        client.get("/api/v1/credentials", headers={"X-API-Key": "wrong"})
    blocked = client.get("/api/v1/credentials", headers=bearer(policy_tokens["hermes"]))  # even a valid token
    assert blocked.status_code == 429
    last_record = last(log_path)
    assert (last_record["principal"], last_record["decision"], last_record["reason"], last_record["status"]) == (
        "-", "denied", "throttled", 429
    )  # fmt: skip


def test_the_rate_limiter_429_is_logged_with_the_principal(make_client, policy_path, policy_tokens, log_path, data):
    client = make_client(API_KEY=None, POLICY_FILE=policy_path, ACCESS_LOG_FILE=log_path, RATE_LIMIT="2/minute")
    h = bearer(policy_tokens["runner"])
    codes = [client.get("/api/v1/credentials", headers=h).status_code for _ in range(3)]
    assert codes == [200, 200, 429]
    record = last(log_path)
    assert (record["principal"], record["status"]) == ("runner", 429)


def test_an_unusable_key_store_is_logged_and_answered_503(lc, log_path, monkeypatch, policy_tokens):
    import app.middleware.security as security

    def broken(value):
        raise OSError("/etc/secret-keys.json: disk error")

    monkeypatch.setattr(security, "authenticate", broken)
    response = lc.get("/api/v1/credentials", headers=bearer(policy_tokens["hermes"]))
    assert response.status_code == 503
    record = last(log_path)
    assert (record["principal"], record["reason"], record["status"]) == ("-", "auth-unavailable", 503)


def test_admin_requests_are_logged_with_the_thing_they_change(lc, log_path, policy_tokens):
    matt = bearer(policy_tokens["matt"])
    lc.post(f"{BASE}/principals", json={"name": "fresh", "kind": "agent"}, headers=matt)
    grant_id = lc.post(f"{BASE}/grants", json={"principal": "fresh", "key": "x"}, headers=matt).json()["id"]
    lc.delete(f"{BASE}/grants/{grant_id}", headers=matt)
    lc.get(f"{BASE}/principals/hermes", headers=matt)
    lc.patch(f"{BASE}/principals/fresh", json={"disabled": True}, headers=matt)
    lc.post(f"{BASE}/principals/fresh/tokens", json={}, headers=matt)
    lc.post(f"{BASE}/check", json={"principal": "hermes", "action": "read", "name": "x"}, headers=matt)
    lc.post(f"{BASE}/reload", headers=matt)
    records = file_records(log_path)
    assert [(r["action"], r["route"], r.get("key")) for r in records] == [
        ("admin", "admin.principal.add", "fresh"),
        ("admin", "admin.grant.add", "fresh"),
        ("admin", "admin.grant.remove", grant_id),
        ("admin", "admin.principal.show", "hermes"),
        ("admin", "admin.principal.update", "fresh"),
        ("admin", "admin.token.issue", "fresh"),
        ("admin", "admin.check", "hermes"),
        ("admin", "admin.reload", None),
    ]
    assert all(r["principal"] == "matt" and r["kind"] == "human-device" and r["decision"] == "allowed" for r in records)
    assert [r["status"] for r in records] == [201, 201, 200, 200, 200, 201, 200, 200]


def test_a_non_admin_calling_admin_is_logged_as_not_admin(lc, log_path, policy_tokens):
    lc.post(f"{BASE}/principals", json={"name": "fresh", "kind": "agent"}, headers=bearer(policy_tokens["hermes"]))
    lc.delete(f"{BASE}/grants/g_00000000", headers=bearer(policy_tokens["runner"]))
    first, second = file_records(log_path)
    assert (first["principal"], first["action"], first["route"]) == ("hermes", "admin", "admin.principal.add")
    assert (first["decision"], first["reason"], first["status"]) == ("denied", "not-admin", 403)
    assert (second["key"], second["status"]) == ("g_00000000", 403)


def test_probes_and_docs_are_not_logged(lc, log_path):
    assert lc.get("/health").status_code == 200 and lc.get("/ready").status_code == 200
    assert lc.get("/api/v1/openapi.json").status_code == 200
    assert not os.path.getsize(log_path)


def test_every_request_is_exactly_one_line_even_when_it_fails_early(lc, log_path, policy_tokens):
    h = bearer(policy_tokens["scribe"])
    requests = [
        lc.get("/api/v1/credentials/bad%0Aname", headers=h),  # 400 before authorization
        lc.get("/api/v1/nope", headers=h),  # 404 route
        lc.post("/api/v1/credentials/app-x", json={}, headers=h),  # 422
        lc.post("/api/v1/credentials/app-x", content=b"x" * 2_000_000, headers=h),  # 413
        lc.get("/api/v1/credentials?show_password=true", headers=h),
        lc.get("/api/v1/credentials", headers={"X-API-Key": "nope"}),
    ]
    records = file_records(log_path)
    assert len(records) == len(requests)
    assert [r["status"] for r in records] == [r.status_code for r in requests]
    assert records[0]["principal"] == "scribe" and "decision" not in records[0]  # nothing was decided
    assert all(r["principal"] in ("scribe", "-") for r in records)


def test_untrusted_names_cannot_forge_lines(lc, log_path, policy_tokens):
    forged = '/api/v1/credentials/x%0A{"principal":"matt"}%0Dend'
    lc.post(forged, json={"value": "v"}, headers=bearer(policy_tokens["hermes"]))  # denied before validation
    lc.get(f"{BASE}/principals/a%0Ab", headers=bearer(policy_tokens["matt"]))
    with open(log_path, encoding="utf-8") as handle:
        lines = handle.read().splitlines()
    assert len(lines) == 2
    first, second = (json.loads(line) for line in lines)
    assert first["principal"] == "hermes" and "\\x0a" in first["key"] and "\\x0d" in first["key"]
    assert second["key"] == "a\\x0ab"
    assert all(ord(c) < 128 for line in lines for c in line)


def test_a_crash_is_logged_from_finally_with_status_500(make_client, log_path, db_path, caplog):
    make_client(ACCESS_LOG_FILE=log_path)
    application = create_app()

    @application.get("/api/v1/boom")
    def boom() -> Response:
        raise RuntimeError("internal-secret-detail")

    with TestClient(application, raise_server_exceptions=False) as client:
        response = client.get("/api/v1/boom", headers=auth(FULL_KEY))
    assert response.status_code == 500
    record = last(log_path)
    assert (record["principal"], record["status"]) == ("legacy-env", 500)
    assert "internal-secret-detail" not in Path(log_path).read_text()


# ---------------------------------------------------------------------------
# nothing secret is ever written
# ---------------------------------------------------------------------------


def test_neither_tokens_nor_values_nor_passwords_reach_any_log(lc, log_path, policy_tokens, caplog, capsys):
    caplog.set_level(logging.DEBUG)
    matt, hermes, scribe = (bearer(policy_tokens[n]) for n in ("matt", "hermes", "scribe"))
    lc.get("/api/v1/credentials?show_password=true", headers=hermes)
    lc.get("/api/v1/credentials/firefly.token?show_password=true", headers=hermes)
    lc.get("/api/v1/credentials/shared-db/versions", headers=hermes)
    lc.get("/api/v1/db-url/shared-db?database=d&mask_password=false", headers=hermes)
    lc.get("/api/v1/search?q=firefly", headers=hermes)
    lc.post("/api/v1/credentials/app-new", json={"password": "write-secret-xyz", "username": "u"}, headers=scribe)
    lc.get("/api/v1/credentials/other", headers={"X-API-Key": policy_tokens["hermes"] + "x"})
    issued = lc.post(f"{BASE}/principals/lister/tokens", json={"description": "d"}, headers=matt).json()
    rotated = lc.post(
        f"{BASE}/principals/hermes/tokens/{policy_tokens['hermes'].split('_')[1]}/rotate", json={}, headers=matt
    ).json()
    lc.get(f"{BASE}/access-log", headers=matt)
    everything = Path(log_path).read_text() + caplog.text + capsys.readouterr().out + capsys.readouterr().err
    plaintexts = [*policy_tokens.values(), issued["token"], rotated["token"]]
    for token in plaintexts:
        assert token not in everything
        assert token.split("_", 2)[2] not in everything  # nor the secret half
    for secret in ("ff-secret", "db-secret", "mcp-secret", "tagged-secret", "write-secret-xyz", "private", "dbuser"):
        assert secret not in everything, secret
    assert "hmac-sha256" not in everything
    # ... while the token ids (public handles) are what identifies the callers
    assert policy_tokens["hermes"].split("_")[1] in Path(log_path).read_text()


def test_the_error_logged_when_the_sink_fails_has_no_secrets(lc, monkeypatch, caplog, policy_tokens, log_path):
    def disk_full(self, line):
        raise OSError(errno.ENOSPC, "No space left on device: " + log_path)

    monkeypatch.setattr(accesslog.FileSink, "write", disk_full)
    caplog.set_level(logging.DEBUG)
    lc.get("/api/v1/credentials/firefly.token?show_password=true", headers=bearer(policy_tokens["hermes"]))
    assert "Access log write failed: OSError" in caplog.text
    assert log_path not in caplog.text and policy_tokens["hermes"] not in caplog.text and "ff-secret" not in caplog.text


# ---------------------------------------------------------------------------
# legacy keys are marked
# ---------------------------------------------------------------------------


def test_legacy_requests_carry_a_deprecation_header_and_kind_legacy(make_client, log_path, data):
    client = make_client(ACCESS_LOG_FILE=log_path, ALLOW_WRITES=True)
    ok = client.get("/api/v1/credentials/other", headers=auth(FULL_KEY))
    missing = client.get("/api/v1/credentials/zzz", headers=auth(FULL_KEY))
    created = client.post("/api/v1/credentials/legacy-new", json={"value": "v"}, headers=auth(FULL_KEY))
    for response in (ok, missing, created):
        assert response.headers["deprecation"] == "true"
    unauthenticated = client.get("/api/v1/credentials/other", headers=auth("wrong-key"))
    assert "deprecation" not in unauthenticated.headers
    records = file_records(log_path)
    assert [r["kind"] for r in records[:3]] == ["legacy"] * 3
    assert all(r["principal"] == "legacy-env" and "token" not in r for r in records[:3])
    assert records[0]["grant"] == "legacy:legacy-env"


def test_token_requests_have_no_deprecation_header(lc, policy_tokens):
    assert "deprecation" not in lc.get("/api/v1/credentials", headers=bearer(policy_tokens["hermes"])).headers


def test_migrated_v1_keys_are_not_legacy_kind_but_report_their_token(
    make_client, tmp_path, key_policy_file, log_path, data
):
    from mattstash.authz import edit_policy

    from .conftest import APP_KEY

    with edit_policy(tmp_path / "migrated.json", create=True) as ed:
        ed.import_v1(key_policy_file.read_text(), 32)
    client = make_client(API_KEY=None, POLICY_FILE=str(tmp_path / "migrated.json"), ACCESS_LOG_FILE=log_path)
    response = client.get("/api/v1/credentials/app-db", headers=auth(APP_KEY))
    record = last(log_path)
    assert (record["principal"], record["kind"], record["decision"]) == ("app", "agent", "allowed")
    assert record["token"] and "deprecation" not in response.headers


# ---------------------------------------------------------------------------
# the file: mode 0600, rotation, stdout
# ---------------------------------------------------------------------------


def mode(path: str) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def test_the_log_file_is_created_0600_whatever_the_umask(make_client, log_path, db_path):
    old = os.umask(0)
    try:
        make_client(ACCESS_LOG_FILE=log_path).get("/api/v1/credentials", headers=auth(FULL_KEY))
    finally:
        os.umask(old)
    assert mode(log_path) == 0o600 and len(file_records(log_path)) == 1


def test_an_existing_world_readable_file_is_tightened_and_appended_to(make_client, log_path, db_path):
    with open(log_path, "w") as handle:
        handle.write('{"ts":"old"}\n')
    os.chmod(log_path, 0o644)
    make_client(ACCESS_LOG_FILE=log_path).get("/api/v1/credentials", headers=auth(FULL_KEY))
    assert mode(log_path) == 0o600
    assert file_records(log_path)[0]["ts"] == "old" and len(file_records(log_path)) == 2


def test_rotation_keeps_the_newest_backups_and_everything_stays_0600(make_client, log_path, db_path):
    client = make_client(ACCESS_LOG_FILE=log_path, ACCESS_LOG_MAX_BYTES=600, ACCESS_LOG_BACKUPS=2)
    old = os.umask(0)
    try:
        for _ in range(12):
            client.get("/api/v1/credentials", headers=auth(FULL_KEY))
    finally:
        os.umask(old)
    names = sorted(n for n in os.listdir(os.path.dirname(log_path)) if n.startswith("access.jsonl"))
    assert names == ["access.jsonl", "access.jsonl.1", "access.jsonl.2"]  # never a .3: the backup count is a cap
    for name in names:
        path = os.path.join(os.path.dirname(log_path), name)
        assert mode(path) == 0o600
        assert os.path.getsize(path) <= 600 + 300
        file_records(path)  # every file holds whole lines
    total = sum(len(file_records(os.path.join(os.path.dirname(log_path), n))) for n in names)
    assert 3 <= total < 12  # the oldest lines were dropped, and none was torn


def test_the_admin_endpoint_reads_across_rotated_files(make_client, policy_path, policy_tokens, log_path, data):
    client = make_client(
        API_KEY=None,
        POLICY_FILE=policy_path,
        ACCESS_LOG_FILE=log_path,
        ACCESS_LOG_MAX_BYTES=1024,
        ACCESS_LOG_BACKUPS=20,
    )
    for _ in range(15):
        client.get("/api/v1/credentials", headers=bearer(policy_tokens["runner"]))
    assert os.path.exists(log_path + ".1")
    response = client.get(
        f"{BASE}/access-log", params={"principal": "runner", "limit": 1000}, headers=bearer(policy_tokens["matt"])
    )
    assert response.json()["count"] == 15


def test_lines_also_go_to_stdout_in_every_mode(make_client, db_path, caplog):
    caplog.set_level(logging.INFO, logger="mattstash.access")
    client = make_client()  # no file configured
    client.get("/api/v1/credentials", headers=auth(FULL_KEY))
    client.get("/api/v1/credentials", headers=auth("wrong"))
    lines = [json.loads(r.getMessage()) for r in caplog.records if r.name == "mattstash.access"]
    assert [(line["principal"], line["status"]) for line in lines] == [("legacy-env", 200), ("-", 401)]


def test_a_log_file_that_cannot_be_opened_stops_startup(configure, tmp_path):
    configure(ACCESS_LOG_FILE=str(tmp_path / "missing-dir" / "access.jsonl"))
    with pytest.raises(FileNotFoundError):
        with TestClient(create_app()):
            pass  # pragma: no cover


def test_the_file_is_closed_at_shutdown(make_client, log_path, db_path):
    make_client(ACCESS_LOG_FILE=log_path)
    assert accesslog._sink is not None
    accesslog.close_file_sink()
    assert accesslog._sink is None
    accesslog.close_file_sink()  # idempotent


def test_note_refuses_unknown_fields():
    from starlette.requests import Request

    request = Request({"type": "http", "state": {}})
    accesslog.note(request, action="read")
    with pytest.raises(ValueError, match="unknown access-log fields"):
        accesslog.note(request, principal="forged")  # the middleware owns who the caller is


# ---------------------------------------------------------------------------
# fail closed
# ---------------------------------------------------------------------------

UNAVAILABLE = {"detail": "Service temporarily unavailable"}


def test_a_failing_file_sink_replaces_the_response_with_503(lc, monkeypatch, policy_tokens, caplog, capsys):
    def disk_full(self, line):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(accesslog.FileSink, "write", disk_full)
    caplog.set_level(logging.INFO)
    response = lc.get("/api/v1/credentials/firefly.token?show_password=true", headers=bearer(policy_tokens["hermes"]))
    assert response.status_code == 503 and response.json() == UNAVAILABLE
    assert "ff-secret" not in response.text  # the secret was read but never sent
    assert response.headers["cache-control"] == "no-store" and response.headers["content-type"] == "application/json"
    assert int(response.headers["content-length"]) == len(response.content)
    assert "Access log write failed: OSError" in caplog.text
    stdout_line = json.loads(next(r.getMessage() for r in caplog.records if r.name == "mattstash.access"))
    assert stdout_line["status"] == 503 and stdout_line["error"] == "access-log-write-failed"
    assert stdout_line["principal"] == "hermes" and stdout_line["key"] == "firefly.token"


def test_a_closed_log_file_fails_closed_for_every_kind_of_request_and_nothing_is_sent(lc, log_path, policy_tokens):
    accesslog._sink._handler.stream.close()  # the descriptor is gone
    for response in (
        lc.get("/api/v1/credentials", headers=bearer(policy_tokens["hermes"])),
        lc.get("/api/v1/credentials", headers={"X-API-Key": "wrong"}),  # even a failed login must be logged
        lc.get(f"{BASE}/principals", headers=bearer(policy_tokens["matt"])),
        lc.post("/api/v1/credentials/app-q", json={"value": "v"}, headers=bearer(policy_tokens["scribe"])),
    ):
        assert response.status_code == 503 and response.json() == UNAVAILABLE
    assert lc.get("/health").status_code == 200  # probes are not logged, so they do not depend on the log


def test_the_sink_recovers_when_the_disk_does(lc, monkeypatch, policy_tokens):
    real = accesslog.FileSink.write
    state = {"full": True}

    def sometimes(self, line):
        if state["full"]:
            raise OSError(errno.ENOSPC, "full")
        real(self, line)

    monkeypatch.setattr(accesslog.FileSink, "write", sometimes)
    h = bearer(policy_tokens["hermes"])
    assert lc.get("/api/v1/credentials", headers=h).status_code == 503
    state["full"] = False
    assert lc.get("/api/v1/credentials", headers=h).status_code == 200


def test_a_crash_while_the_sink_is_failing_does_not_hide_the_crash(make_client, log_path, db_path, monkeypatch):
    make_client(ACCESS_LOG_FILE=log_path)
    application = create_app()

    @application.get("/api/v1/boom")
    def boom() -> Response:
        raise RuntimeError("x")

    def broken(self, line):
        raise OSError("full")

    monkeypatch.setattr(accesslog.FileSink, "write", broken)
    with TestClient(application, raise_server_exceptions=False) as client:
        assert client.get("/api/v1/boom", headers=auth(FULL_KEY)).status_code == 500
