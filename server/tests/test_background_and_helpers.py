"""DB change poller, reload helpers, admin reload and log-masking helper."""

import asyncio
import logging

import pytest

import app.dependencies as deps
from app.middleware.logging import mask_sensitive_data

from .conftest import auth

H = auth()


# ---------------------------------------------------------------------------
# poller
# ---------------------------------------------------------------------------


def test_poller_checks_for_external_changes_periodically(make_client, monkeypatch):
    import app.main as main_module

    calls: list[int] = []
    monkeypatch.setattr(main_module, "reload_mattstash_if_changed", lambda: calls.append(1) or True)
    client = make_client(DB_POLL_INTERVAL=1)
    import time

    deadline = time.monotonic() + 5
    while not calls and time.monotonic() < deadline:
        time.sleep(0.1)
    assert calls, "the poller never ran"
    assert client.get("/health").status_code == 200


def test_poller_survives_errors_and_keeps_polling(make_client, monkeypatch, caplog):
    import time

    import app.main as main_module

    attempts: list[int] = []

    def flaky():
        attempts.append(1)
        raise RuntimeError("transient")

    monkeypatch.setattr(main_module, "reload_mattstash_if_changed", flaky)
    caplog.set_level(logging.ERROR, logger="mattstash.api")
    make_client(DB_POLL_INTERVAL=1)
    deadline = time.monotonic() + 6
    while len(attempts) < 2 and time.monotonic() < deadline:
        time.sleep(0.1)
    assert len(attempts) >= 2  # an exception does not stop the loop
    assert "Error during database change poll" in caplog.text


def test_poller_is_disabled_with_interval_zero(client, caplog):
    import app.main as main_module

    caplog.set_level(logging.INFO, logger="mattstash.api")
    asyncio.run(main_module._poll_database_changes())  # returns immediately instead of looping forever
    assert "polling disabled" in caplog.text


# ---------------------------------------------------------------------------
# reload helpers + admin endpoint
# ---------------------------------------------------------------------------


def test_reload_helpers_without_an_instance():
    assert deps.reload_mattstash() is False
    assert deps.reload_mattstash_if_changed() is False


def test_reload_helpers_with_an_instance(client, db_path):
    from mattstash import MattStash

    assert deps.reload_mattstash() is True
    assert deps.reload_mattstash_if_changed() is False  # nothing changed
    MattStash(path=str(db_path), password="test-db-password-123").put("x", value="1")
    assert deps.reload_mattstash_if_changed() is True


def test_admin_reload_reports_success_and_failure(client, monkeypatch):
    assert client.post("/api/v1/admin/reload", headers=H).json() == {"status": "reloaded"}
    monkeypatch.setattr("app.routers.admin.reload_mattstash", lambda: False)
    failed = client.post("/api/v1/admin/reload", headers=H)
    assert failed.status_code == 503 and "still serving the previous state" in failed.json()["detail"]


def test_get_mattstash_lazy_failure_is_503_and_recovers(configure, monkeypatch, tmp_path):
    """If startup did not open the DB (e.g. app used without lifespan) the first request opens it lazily."""
    from fastapi import HTTPException

    configure(DB_PATH=str(tmp_path / "missing.kdbx"))
    with pytest.raises(HTTPException) as excinfo:
        deps.get_mattstash()
    assert excinfo.value.status_code == 503 and excinfo.value.headers["Retry-After"] == "5"


# ---------------------------------------------------------------------------
# masking helper
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text, expected",
    [
        ('{"password": "hunter2"}', '{"password": "*****"}'),
        ('{"value":"s3cr3t"}', '{"value": "*****"}'),
        ("x-api-key: abc123def", "X-API-Key: *****"),
        ("X-API-Key:   abc123def", "X-API-Key: *****"),
        ("nothing sensitive here", "nothing sensitive here"),
    ],
)
def test_mask_sensitive_data(text, expected):
    assert mask_sensitive_data(text) == expected
