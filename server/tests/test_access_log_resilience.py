"""The access-log file under a REAL failing file: fail closed and open, ``/ready`` pacing, rate-limited error lines,
no line for a refused request, and the gap marker once writes work again.

The failure is real, not a mock: ``MATTSTASH_ACCESS_LOG_FILE`` is a named pipe whose reader has gone away, so the
server opens it fine at startup and every later write fails (EPIPE), for any user (``/dev/full`` is not writable
by everyone in every sandbox). Replacing the pipe with an ordinary file is the disk coming back.
"""

import contextlib
import json
import logging
import os
from pathlib import Path

import pytest
from mattstash import MattStash

from app import accesslog

from .conftest import DB_PASSWORD
from .test_access_log import UNAVAILABLE, bearer
from .test_access_log_fail_open import stdout_lines


@pytest.fixture
def link(tmp_path) -> Path:
    """The log path: a named pipe with a reader, so the sink can open it (the reader is closed by ``broken``)."""
    path = tmp_path / "access.jsonl"
    os.mkfifo(path)
    return path


@pytest.fixture
def reader(link):
    descriptor = os.open(link, os.O_RDONLY | os.O_NONBLOCK)
    yield descriptor
    with contextlib.suppress(OSError):  # the fixtures that break the pipe close it first
        os.close(descriptor)


def repair(link: Path) -> None:
    """The disk has room again: the path is an ordinary file."""
    link.unlink()  # the pipe
    link.touch()


def records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


@pytest.fixture
def broken(make_client, policy_path, link, reader, data):
    client = make_client(POLICY_FILE=policy_path, ACCESS_LOG_FILE=str(link), ALLOW_WRITES=True)
    os.close(reader)  # the sink has the pipe open; with no reader left every write fails
    return client


@pytest.fixture
def broken_open(make_client, policy_path, link, reader, data):
    client = make_client(
        POLICY_FILE=policy_path, ACCESS_LOG_FILE=str(link), ALLOW_WRITES=True, ACCESS_LOG_FAIL_OPEN=True
    )
    os.close(reader)
    return client


def test_fail_closed_on_an_unwritable_file_refuses_reads_and_writes_and_changes_nothing(
    broken,
    policy_tokens,
    clock,
    db_path,
    link,
):
    read = broken.get("/api/v1/credentials/firefly.token?show_password=true", headers=bearer(policy_tokens["hermes"]))
    assert read.status_code == 503 and read.json() == UNAVAILABLE and "ff-secret" not in read.text
    write = broken.post("/api/v1/credentials/app-new", json={"value": "v"}, headers=bearer(policy_tokens["scribe"]))
    assert write.status_code == 503 and write.json() == UNAVAILABLE
    assert MattStash(path=str(db_path), password=DB_PASSWORD).get("app-new") is None
    assert accesslog.sink_healthy() is False
    ready = broken.get("/ready")
    assert ready.status_code == 503 and ready.json() == {"detail": "Not ready"} and str(link) not in ready.text
    assert broken.get("/health").status_code == 200


def test_no_line_is_ever_written_for_a_request_that_was_answered_503(broken, policy_tokens, clock, link):
    for _ in range(3):
        assert (
            broken.get("/api/v1/credentials/firefly.token", headers=bearer(policy_tokens["hermes"])).status_code == 503
        )
    assert (
        broken.post(
            "/api/v1/credentials/app-new", json={"value": "v"}, headers=bearer(policy_tokens["scribe"])
        ).status_code
        == 503
    )
    repair(link)  # the disk comes back; the next request is the first the file sees
    clock.advance(10)
    assert broken.get("/api/v1/credentials/other/versions", headers=bearer(policy_tokens["hermes"])).status_code == 404
    lines = records(link)
    assert [r.get("event") for r in lines] == ["access-log-gap", None]
    assert lines[0]["lost"] == 4  # three reads and one write: the requests answered 503
    assert lines[1]["key"] == "other" and "firefly.token" not in link.read_text() and "app-new" not in link.read_text()


def test_fail_open_serves_requests_marks_stdout_and_reports_the_loss_when_the_file_recovers(
    broken_open,
    policy_tokens,
    clock,
    link,
    caplog,
):
    caplog.set_level(logging.INFO)
    h = bearer(policy_tokens["hermes"])
    for _ in range(2):
        assert broken_open.get("/api/v1/credentials/firefly.token?show_password=true", headers=h).status_code == 200
    created = broken_open.post(
        "/api/v1/credentials/app-new", json={"value": "v"}, headers=bearer(policy_tokens["scribe"])
    )
    assert created.status_code == 201
    assert [line["error"] for line in stdout_lines(caplog)] == ["access-log-write-failed"] * 3
    assert broken_open.get("/ready").status_code == 503  # fail open still tells monitoring
    repair(link)
    clock.advance(accesslog.READY_PROBE_INTERVAL)
    assert broken_open.get("/ready").status_code == 200
    assert broken_open.get("/api/v1/credentials", headers=h).status_code == 200
    lines = records(link)
    assert [r.get("event") for r in lines] == ["access-log-gap", "access-log-probe", None]
    assert lines[0]["lost"] == 3 and set(lines[0]) == {"ts", "event", "lost"}


def test_ready_retries_a_failing_sink_at_most_every_five_seconds(broken, policy_tokens, clock, monkeypatch):
    attempts = []
    real = accesslog.FileSink.write

    def counting(self, line):
        attempts.append(json.loads(line).get("event"))
        real(self, line)

    monkeypatch.setattr(accesslog.FileSink, "write", counting)
    assert broken.get("/api/v1/credentials", headers=bearer(policy_tokens["hermes"])).status_code == 503
    assert attempts == [None]  # the request's own line
    for _ in range(20):
        assert broken.get("/ready").status_code == 503
    assert attempts == [None, "access-log-probe"]  # one probe for twenty polls
    clock.advance(accesslog.READY_PROBE_INTERVAL - 0.1)
    assert broken.get("/ready").status_code == 503 and len(attempts) == 2
    clock.advance(0.2)
    assert broken.get("/ready").status_code == 503 and attempts[2:] == ["access-log-probe"]


def test_the_write_failed_error_is_logged_once_a_minute_with_a_count(broken, policy_tokens, clock, caplog):
    caplog.set_level(logging.ERROR, logger="mattstash.api")
    h = bearer(policy_tokens["hermes"])

    def messages() -> list[str]:
        return [r.getMessage() for r in caplog.records if "Access log write failed" in r.getMessage()]

    for _ in range(5):
        broken.get("/api/v1/credentials", headers=h)
    assert messages() == ["Access log write failed: OSError (1 failure(s) since the last report)"]
    clock.advance(accesslog.FAILURE_REPORT_INTERVAL - 1)
    broken.get("/api/v1/credentials", headers=h)
    assert len(messages()) == 1
    clock.advance(2)
    broken.get("/api/v1/credentials", headers=h)
    assert messages()[1] == "Access log write failed: OSError (6 failure(s) since the last report)"
    assert "access.jsonl" not in caplog.text


def test_a_failed_write_closes_the_file_and_the_next_write_reopens_it(tmp_path):
    """Whatever a failed write left behind is dropped with the stream; a half-written fragment cannot swallow the
    line after it."""
    path = tmp_path / "log.jsonl"
    sink = accesslog.FileSink(str(path), 10_000, 2)
    sink.write('{"n":1}')
    stream = sink._handler.stream

    class Failing:
        """Accepts part of the first write, then fails like a full disk."""

        def __init__(self) -> None:
            self.calls = 0

        def write(self, data):
            self.calls += 1
            if self.calls == 1:
                stream.write(bytes(data[:4]))
                return 4
            raise OSError(28, "No space left on device")

        def __getattr__(self, name):  # tell, seek, close ...: the real file's
            return getattr(stream, name)

    sink._handler.stream = Failing()
    with pytest.raises(OSError):
        sink.write('{"n":2}')
    assert sink._handler.stream is None and sink.healthy is False
    sink.record_failure()
    sink.write('{"n":3}')
    lines = path.read_text().splitlines()
    assert lines[0] == '{"n":1}' and lines[1] == '{"n"'  # the fragment is its own (invalid) line
    parsed = [json.loads(line) for line in lines if line.endswith("}")]
    assert [r.get("n") for r in parsed] == [1, None, 3] and parsed[1]["event"] == "access-log-gap"
    assert parsed[1]["lost"] == 1
    sink.close()


def test_a_file_that_accepts_no_bytes_is_a_failure_not_an_endless_loop(tmp_path):
    sink = accesslog.FileSink(str(tmp_path / "log.jsonl"), 10_000, 2)

    class Stuck:
        def write(self, data):
            return 0

        def __getattr__(self, name):
            return getattr(real, name)

    real = sink._handler.stream
    sink._handler.stream = Stuck()
    with pytest.raises(OSError, match="accepted no bytes"):
        sink.write('{"n":1}')
    assert sink.healthy is False
    sink.close()
