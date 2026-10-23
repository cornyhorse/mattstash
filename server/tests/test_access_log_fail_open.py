"""MATTSTASH_ACCESS_LOG_FAIL_OPEN, and /ready reporting an unhealthy access-log file (both modes)."""

import errno
import json
import logging

import pytest

from app import accesslog

from .test_access_log import BASE, UNAVAILABLE, bearer, file_records, lc  # noqa: F401  (fixtures)

NOT_READY = {"detail": "Not ready"}


@pytest.fixture
def fail_open_client(make_client, policy_path, log_path, data):
    return make_client(POLICY_FILE=policy_path, ACCESS_LOG_FILE=log_path, ALLOW_WRITES=True, ACCESS_LOG_FAIL_OPEN=True)


@pytest.fixture
def disk(monkeypatch):
    """A switch for the disk being full."""
    real = accesslog.FileSink.write
    state = {"full": True}

    def write(self, line):
        if state["full"]:
            raise OSError(errno.ENOSPC, "No space left on device")
        real(self, line)

    monkeypatch.setattr(accesslog.FileSink, "write", write)
    return state


def stdout_lines(caplog):
    return [json.loads(r.getMessage()) for r in caplog.records if r.name == "mattstash.access"]


def test_default_is_fail_closed():
    from app.config import Config

    assert Config.ACCESS_LOG_FAIL_OPEN is False


def test_fail_open_lets_a_read_through_and_marks_the_stdout_line(fail_open_client, disk, policy_tokens, caplog):
    caplog.set_level(logging.INFO)
    response = fail_open_client.get(
        "/api/v1/credentials/firefly.token?show_password=true", headers=bearer(policy_tokens["hermes"])
    )
    assert response.status_code == 200 and response.json()["password"] == "ff-secret"
    assert "Access log write failed: OSError" in caplog.text
    assert "ff-secret" not in caplog.text and policy_tokens["hermes"] not in caplog.text
    (line,) = stdout_lines(caplog)
    assert line["error"] == "access-log-write-failed" and line["status"] == 200 and line["key"] == "firefly.token"


def test_fail_open_lets_decision_time_writes_through(fail_open_client, disk, policy_tokens, caplog):
    caplog.set_level(logging.INFO)
    created = fail_open_client.post(
        "/api/v1/credentials/app-new", json={"value": "v"}, headers=bearer(policy_tokens["scribe"])
    )
    assert created.status_code == 201
    deleted = fail_open_client.delete("/api/v1/credentials/app-new", headers=bearer(policy_tokens["scribe"]))
    assert deleted.status_code == 200
    admin = fail_open_client.post(
        f"{BASE}/principals/hermes/tokens", json={"description": "x"}, headers=bearer(policy_tokens["matt"])
    )
    assert admin.status_code == 201
    lines = stdout_lines(caplog)
    assert len(lines) == 3 and all(line["error"] == "access-log-write-failed" for line in lines)
    assert all(line.get("status") != 503 for line in lines)
    assert admin.json()["token"] not in caplog.text


def test_fail_closed_refuses_both_write_paths(lc, disk, policy_tokens):  # noqa: F811
    assert lc.get("/api/v1/credentials", headers=bearer(policy_tokens["hermes"])).json() == UNAVAILABLE
    post = lc.post("/api/v1/credentials/app-x", json={"value": "v"}, headers=bearer(policy_tokens["scribe"]))
    assert post.status_code == 503 and post.json() == UNAVAILABLE
    disk["full"] = False
    assert lc.get("/api/v1/credentials/app-x", headers=bearer(policy_tokens["scribe"])).status_code == 404


@pytest.mark.parametrize("fail_open", [False, True])
@pytest.mark.parametrize("prefix", ["", "/api"])
def test_ready_follows_the_file_sink(
    make_client, policy_path, log_path, data, disk, clock, policy_tokens, fail_open, prefix
):
    client = make_client(POLICY_FILE=policy_path, ACCESS_LOG_FILE=log_path, ACCESS_LOG_FAIL_OPEN=fail_open)
    assert client.get(f"{prefix}/ready").status_code == 200  # nothing has failed yet
    client.get("/api/v1/credentials", headers=bearer(policy_tokens["hermes"]))  # the write fails
    assert accesslog.sink_healthy() is False
    for _ in range(2):  # still failing: the probe fails too
        response = client.get(f"{prefix}/ready")
        assert response.status_code == 503 and response.json() == NOT_READY
        assert log_path not in response.text
    assert client.get(f"{prefix}/health").status_code == 200  # liveness is unaffected
    disk["full"] = False
    assert client.get(f"{prefix}/ready").status_code == 503  # the disk is back, but the probe was tried a moment ago
    clock.advance(accesslog.READY_PROBE_INTERVAL)
    assert client.get(f"{prefix}/ready").status_code == 200  # the probe write succeeded
    assert accesslog.sink_healthy() is True
    events = [r["event"] for r in file_records(log_path) if "event" in r]
    assert events == ["access-log-gap", "access-log-probe"]  # one gap marker, then the probe line


def test_a_successful_request_write_makes_the_sink_healthy_again(lc, disk, clock, policy_tokens):  # noqa: F811
    h = bearer(policy_tokens["hermes"])
    assert lc.get("/api/v1/credentials", headers=h).status_code == 503
    assert lc.get("/ready").status_code == 503
    disk["full"] = False
    # no time has passed, so /ready still answers from the cached flag: a REQUEST is what notices the recovery
    assert lc.get("/ready").status_code == 503
    assert lc.get("/api/v1/credentials", headers=h).status_code == 200
    assert accesslog.sink_healthy() is True and lc.get("/ready").status_code == 200


def test_ready_without_a_file_sink_is_unaffected(make_client):
    assert make_client().get("/ready").status_code == 200
    assert accesslog.probe_sink() is True


def test_a_sink_that_cannot_open_is_unhealthy(configure, tmp_path):
    configure(ACCESS_LOG_FILE=str(tmp_path / "missing-dir" / "access.jsonl"))
    with pytest.raises(OSError):
        accesslog.open_file_sink()
    assert accesslog.sink_healthy() is False
    configure(ACCESS_LOG_FILE=str(tmp_path / "ok.jsonl"))
    accesslog.open_file_sink()
    assert accesslog.sink_healthy() is True
