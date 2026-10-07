"""Application startup validation (fail fast, with safe messages)."""

import logging

import pytest
from fastapi.testclient import TestClient

from app.config import Config
from app.main import create_app

from .conftest import DB_PASSWORD, FULL_KEY


def _start(application):
    with TestClient(application):
        pass  # pragma: no cover


def test_startup_fails_no_kdbx_password(monkeypatch):
    monkeypatch.setattr(Config, "KDBX_PASSWORD", None)
    monkeypatch.setattr(Config, "KDBX_PASSWORD_FILE", None)
    monkeypatch.setattr(Config, "API_KEY", FULL_KEY)
    monkeypatch.setattr(Config, "API_KEYS_FILE", None)
    with pytest.raises(ValueError, match="KDBX password must be provided"):
        _start(create_app())


def test_startup_fails_kdbx_password_file_not_found(monkeypatch):
    monkeypatch.setattr(Config, "KDBX_PASSWORD", None)
    monkeypatch.setattr(Config, "KDBX_PASSWORD_FILE", "/nonexistent/path.txt")
    monkeypatch.setattr(Config, "API_KEY", FULL_KEY)
    monkeypatch.setattr(Config, "API_KEYS_FILE", None)
    with pytest.raises(FileNotFoundError, match="Password file not found"):
        _start(create_app())


def test_startup_fails_no_api_keys(monkeypatch):
    monkeypatch.setattr(Config, "KDBX_PASSWORD", DB_PASSWORD)
    monkeypatch.setattr(Config, "API_KEY", None)
    monkeypatch.setattr(Config, "API_KEYS_FILE", None)
    with pytest.raises(ValueError, match="At least one API key must be provided"):
        _start(create_app())


def test_startup_fails_on_weak_api_key(configure):
    configure(API_KEY="short-key")
    with pytest.raises(ValueError, match="shorter than 32 characters"):
        _start(create_app())


def test_startup_fails_if_database_is_missing(configure, tmp_path):
    configure(DB_PATH=str(tmp_path / "typo" / "mattstash.kdbx"))
    from mattstash.utils.exceptions import DatabaseNotFoundError

    with pytest.raises(DatabaseNotFoundError):
        _start(create_app())
    assert not (tmp_path / "typo").exists()  # the server never creates a database


def test_startup_fails_on_wrong_database_password(configure):
    configure(KDBX_PASSWORD="not-the-password")
    from mattstash.utils.exceptions import DatabaseAccessError

    with pytest.raises(DatabaseAccessError):
        _start(create_app())


def test_startup_requires_tls_files_together(configure):
    configure(TLS_CERT_FILE="/some/cert.pem", TLS_KEY_FILE=None)
    with pytest.raises(ValueError, match="must be set together"):
        _start(create_app())


def test_startup_warns_about_legacy_keys(client, caplog):
    # `client` fixture already started the app with a legacy key; restart to capture the log
    caplog.set_level(logging.WARNING, logger="mattstash.api")
    from app.main import create_app

    with TestClient(create_app()):
        pass
    assert "legacy API key" in caplog.text
    assert FULL_KEY not in caplog.text


def test_startup_refuses_legacy_keys_when_scoped_keys_are_required(configure):
    configure(REQUIRE_SCOPED_KEYS=True)
    with pytest.raises(ValueError, match="MATTSTASH_REQUIRE_SCOPED_KEYS"):
        _start(create_app())


def test_sidecar_next_to_database_warns(configure, db_path, caplog):
    (db_path.parent / ".mattstash.txt").write_text(DB_PASSWORD)
    configure()
    caplog.set_level(logging.WARNING, logger="mattstash.api")
    _start(create_app())
    assert "sidecar password file exists next to the database" in caplog.text


def test_sidecar_next_to_database_can_be_refused(configure, db_path):
    (db_path.parent / ".mattstash.txt").write_text(DB_PASSWORD)
    configure(REFUSE_SIDECAR=True)
    with pytest.raises(RuntimeError, match="refusing to start"):
        _start(create_app())


def test_read_only_mode_is_announced(configure, caplog):
    configure()
    caplog.set_level(logging.INFO, logger="mattstash.api")
    _start(create_app())
    assert "Read-only mode" in caplog.text


def test_write_mode_is_announced(configure, caplog):
    configure(ALLOW_WRITES=True)
    caplog.set_level(logging.WARNING, logger="mattstash.api")
    _start(create_app())
    assert "Writes are ENABLED" in caplog.text
