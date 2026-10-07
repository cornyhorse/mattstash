"""Shared fixtures for MattStash server tests.

The server tests run the real application (real middleware, real key policy, real KeePass
database in a temp dir) through ``TestClient``. Nothing in the data or auth layer is mocked, so
authorization, throttling, locking and error mapping are exercised end to end.
"""

import json
import tempfile
from collections.abc import Callable, Generator
from pathlib import Path
from unittest.mock import MagicMock, Mock

import pytest
from fastapi.testclient import TestClient
from mattstash import MattStash

DB_PASSWORD = "test-db-password-123"
# Keys are >= 32 chars (the enforced minimum); each has a distinct role in the policy below.
FULL_KEY = "full-access-legacy-key-" + "a" * 20
READ_KEY = "read-only-scoped-key--" + "b" * 20
APP_KEY = "app-prefix-scoped-key--" + "c" * 20
WRITE_KEY = "writer-scoped-key------" + "d" * 20
ADMIN_KEY = "admin-scoped-key-------" + "e" * 20


def fresh_config_module():
    """Load a private copy of ``app.config`` evaluated against the current environment.

    ``importlib.reload(app.config)`` would replace the ``Config``/``config`` objects that every other
    ``app.*`` module has already imported, silently desynchronising later tests; an isolated copy cannot.
    """
    import importlib.util

    import app.config as real

    spec = importlib.util.spec_from_file_location("app_config_isolated", real.__file__)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CONFIG_ENV_VARS = [
    "MATTSTASH_DB_PATH",
    "KDBX_PASSWORD",
    "KDBX_PASSWORD_FILE",
    "MATTSTASH_HOST",
    "MATTSTASH_PORT",
    "MATTSTASH_LOG_LEVEL",
    "MATTSTASH_API_KEY",
    "MATTSTASH_API_KEYS_FILE",
    "MATTSTASH_RATE_LIMIT",
    "MATTSTASH_ALLOW_WRITES",
    "MATTSTASH_MIN_KEY_LENGTH",
    "MATTSTASH_REQUIRE_SCOPED_KEYS",
    "MATTSTASH_AUTH_FAIL_LIMIT",
    "MATTSTASH_AUTH_FAIL_WINDOW_SECONDS",
    "MATTSTASH_TRUSTED_PROXY_HOPS",
    "MATTSTASH_TLS_CERT_FILE",
    "MATTSTASH_TLS_KEY_FILE",
    "MATTSTASH_DISABLE_DOCS",
    "MATTSTASH_REFUSE_SIDECAR",
    "MATTSTASH_MAX_REQUEST_BODY_BYTES",
    "MATTSTASH_DB_POLL_INTERVAL",
]


@pytest.fixture
def temp_password_file() -> Generator[Path, None, None]:
    """Create a temporary password file."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
        f.write("test_password_123")
        temp_path = Path(f.name)
    yield temp_path
    temp_path.unlink(missing_ok=True)


@pytest.fixture
def temp_api_keys_file() -> Generator[Path, None, None]:
    """Create a temporary legacy API keys file."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
        f.write("# API Keys\n")
        f.write("test-key-1\n")
        f.write("test-key-2\n")
        f.write("# Another comment\n")
        f.write("test-key-3\n")
        temp_path = Path(f.name)
    yield temp_path
    temp_path.unlink(missing_ok=True)


@pytest.fixture
def clean_env(monkeypatch) -> None:
    """Remove every MattStash-related environment variable."""
    for var in CONFIG_ENV_VARS:
        monkeypatch.delenv(var, raising=False)


@pytest.fixture(autouse=True)
def reset_state(clean_env):
    """Reset all module-level state (instance, key cache, throttle, rate limiter) around each test."""
    import app.dependencies as deps
    import app.security.api_keys as api_keys_module
    from app.middleware.security import auth_failures
    from app.rate_limit import limiter

    def reset() -> None:
        deps._mattstash_instance = None
        api_keys_module._policy = None
        api_keys_module._policy_loaded_at = 0.0
        auth_failures.reset()
        limiter.reset()

    reset()
    yield
    reset()


@pytest.fixture
def mock_mattstash() -> Mock:
    """A MattStash mock for tests that only care about HTTP-level behaviour."""
    from mattstash.models.credential import Credential

    mock = MagicMock(spec=MattStash)
    mock.get.return_value = Credential(
        credential_name="test_cred",
        username="testuser",
        password="testpass",
        url="https://example.com",
        notes="Test notes",
        tags=[],
        show_password=False,
    )
    mock.list_versions.return_value = ["0000000001"]
    mock.delete.return_value = True
    return mock


# ---------------------------------------------------------------------------
# Real application + real database
# ---------------------------------------------------------------------------


@pytest.fixture
def db_path(tmp_path) -> Path:
    """A freshly created, empty KeePass database (explicit creation; the server never creates one)."""
    data = tmp_path / "data"
    data.mkdir()
    path = data / "mattstash.kdbx"
    MattStash.create(str(path), password=DB_PASSWORD)
    return path


@pytest.fixture
def seed(db_path) -> Callable[..., MattStash]:
    """Return a function that seeds credentials directly through the library (bypassing the API)."""

    def _seed(**credentials) -> MattStash:
        stash = MattStash(path=str(db_path), password=DB_PASSWORD)
        for name, spec in credentials.items():
            stash.put(name.replace("__", "-"), **spec)
        return stash

    return _seed


@pytest.fixture
def key_policy_file(tmp_path) -> Path:
    """A JSON key policy exercising every role."""
    import hashlib

    def sha(key: str) -> str:
        return hashlib.sha256(key.encode()).hexdigest()

    policy = {
        "keys": [
            {"id": "reader", "key_sha256": sha(READ_KEY), "ops": ["read"]},
            {"id": "app", "key": APP_KEY, "ops": ["read", "write", "delete"], "prefixes": ["app-"]},
            {"id": "writer", "key_sha256": sha(WRITE_KEY), "ops": ["read", "write"]},
            {"id": "ops", "key_sha256": sha(ADMIN_KEY), "ops": ["admin"]},
        ]
    }
    path = tmp_path / "keys.json"
    path.write_text(json.dumps(policy))
    return path


@pytest.fixture
def configure(monkeypatch, db_path):
    """Set server configuration for a test (class attributes are read at request time)."""
    from app.config import Config

    def _configure(**overrides) -> None:
        defaults = {
            "DB_PATH": str(db_path),
            "KDBX_PASSWORD": DB_PASSWORD,
            "KDBX_PASSWORD_FILE": None,
            "API_KEY": FULL_KEY,
            "API_KEYS_FILE": None,
            "DB_POLL_INTERVAL": 0,
        }
        defaults.update(overrides)
        for name, value in defaults.items():
            monkeypatch.setattr(Config, name, value)

    return _configure


@pytest.fixture
def make_client(configure) -> Generator[Callable[..., TestClient], None, None]:
    """Factory: ``make_client(ALLOW_WRITES=True, ...)`` -> TestClient with lifespan (DB opened at startup)."""
    clients: list[TestClient] = []

    def _make(**overrides) -> TestClient:
        configure(**overrides)
        from app.main import create_app

        client = TestClient(create_app())
        client.__enter__()
        clients.append(client)
        return client

    yield _make
    for client in clients:
        client.__exit__(None, None, None)


@pytest.fixture
def client(make_client) -> TestClient:
    """Default: one legacy full-access key, read-only mode."""
    return make_client()


@pytest.fixture
def rw_client(make_client) -> TestClient:
    """Default key, writes enabled."""
    return make_client(ALLOW_WRITES=True)


def auth(key: str = FULL_KEY) -> dict[str, str]:
    return {"X-API-Key": key}
