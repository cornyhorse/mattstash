"""Tests for application lifespan startup validation."""
import pytest
from fastapi.testclient import TestClient

from app.config import Config
from app.main import create_app


def test_startup_fails_no_kdbx_password(monkeypatch):
    """Lifespan raises ValueError when no KDBX password is configured."""
    monkeypatch.setattr(Config, "KDBX_PASSWORD", None)
    monkeypatch.setattr(Config, "KDBX_PASSWORD_FILE", None)
    monkeypatch.setattr(Config, "API_KEY", "test-key")
    monkeypatch.setattr(Config, "API_KEYS_FILE", None)

    application = create_app()
    with pytest.raises(ValueError, match="KDBX password must be provided"):
        with TestClient(application):
            pass  # pragma: no cover


def test_startup_fails_kdbx_password_file_not_found(monkeypatch):
    """Lifespan raises FileNotFoundError when KDBX_PASSWORD_FILE path does not exist."""
    monkeypatch.setattr(Config, "KDBX_PASSWORD", None)
    monkeypatch.setattr(Config, "KDBX_PASSWORD_FILE", "/nonexistent/path.txt")
    monkeypatch.setattr(Config, "API_KEY", "test-key")
    monkeypatch.setattr(Config, "API_KEYS_FILE", None)

    application = create_app()
    with pytest.raises(FileNotFoundError, match="Password file not found"):
        with TestClient(application):
            pass  # pragma: no cover


def test_startup_fails_no_api_keys(monkeypatch):
    """Lifespan raises ValueError when no API keys are configured."""
    monkeypatch.setattr(Config, "KDBX_PASSWORD", "testpass")
    monkeypatch.setattr(Config, "KDBX_PASSWORD_FILE", None)
    monkeypatch.setattr(Config, "API_KEY", None)
    monkeypatch.setattr(Config, "API_KEYS_FILE", None)

    application = create_app()
    with pytest.raises(ValueError, match="At least one API key must be provided"):
        with TestClient(application):
            pass  # pragma: no cover
