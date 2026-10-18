"""Shared fixtures for MattStash server tests.

The server tests run the real application (real middleware, real key policy, real KeePass
database in a temp dir) through ``TestClient``. Nothing in the data or auth layer is mocked, so
authorization, throttling, locking and error mapping are exercised end to end.
"""

import json
import os
import tempfile
from collections.abc import Callable, Generator
from pathlib import Path
from unittest.mock import MagicMock, Mock

# ``app.config.Config`` reads the environment when ``app.config`` is first imported (class attributes), so every
# configuration variable must be gone BEFORE any test module imports ``app``: a developer's exported
# MATTSTASH_ALLOW_SLASH_NAMES, MATTSTASH_ACCESS_LOG_FAIL_OPEN or MATTSTASH_API_KEY would otherwise change results.
# (This runs when pytest loads this conftest, which precedes the collection of every test module.)
for _name in [name for name in os.environ if name.startswith(("MATTSTASH_", "KDBX_"))]:
    os.environ.pop(_name, None)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from mattstash import MattStash  # noqa: E402


@pytest.fixture(scope="session")
def _cheap_blank_database(tmp_path_factory: pytest.TempPathFactory) -> str:
    """pykeepass's blank-database template with a nearly free Argon2 setting (same trick as the root tests).

    Databases are created from that template and keep its KDF parameters in their header, so the real server
    subprocesses some tests start read them from the file. The shipped template costs ~0.5 s per open/save.
    Production code is untouched; the library's own test suite proves new databases still get the strong default.
    """
    import pykeepass.pykeepass as kp_module

    path = str(tmp_path_factory.mktemp("kdf") / "blank-cheap.kdbx")
    blank = kp_module.PyKeePass(kp_module.BLANK_DATABASE_LOCATION, kp_module.BLANK_DATABASE_PASSWORD)
    params = blank.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
    params["I"].value = 1
    params["M"].value = 1024 * 1024
    blank.filename = path
    blank.save()
    return path


@pytest.fixture(scope="session", autouse=True)
def _cheap_kdf(_cheap_blank_database: str) -> Generator[None, None, None]:
    """Session-wide, so module-scoped database fixtures (they run before function-scoped ones) are cheap too."""
    import pykeepass.pykeepass as kp_module

    original = kp_module.BLANK_DATABASE_LOCATION
    kp_module.BLANK_DATABASE_LOCATION = _cheap_blank_database
    yield
    kp_module.BLANK_DATABASE_LOCATION = original


DB_PASSWORD = "test-db-password-123"
# Keys are >= 32 chars (the enforced minimum); each has a distinct role in the policy below.
FULL_KEY = "full-access-test-key---" + "a" * 20
READ_KEY = "read-only-scoped-key--" + "b" * 20
APP_KEY = "app-prefix-scoped-key--" + "c" * 20
WRITE_KEY = "writer-scoped-key------" + "d" * 20
ADMIN_KEY = "admin-scoped-key-------" + "e" * 20
RUNNER_PREFIXES = "adfnors"  # the first letters of every entry in the ``data`` fixture
DB = {"username": "dbuser", "password": "db-secret", "url": "db.internal:5432"}


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
    "MATTSTASH_MAX_CONCURRENT_WRITES",
    "MATTSTASH_DB_POLL_INTERVAL",
    "MATTSTASH_POLICY_FILE",
    "MATTSTASH_ACCESS_LOG_FILE",
    "MATTSTASH_ACCESS_LOG_MAX_BYTES",
    "MATTSTASH_ACCESS_LOG_BACKUPS",
    "MATTSTASH_ACCESS_LOG_FAIL_OPEN",
    "MATTSTASH_ALLOW_SLASH_NAMES",
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
        api_keys_module._state = None
        api_keys_module._state_loaded_at = 0.0
        api_keys_module._failed_signature = None
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


def import_plain_key(editor, name: str, key: str, **kwargs):
    """``editor.import_token`` for a principal that is ALSO an admin. The editor refuses that combination (admins use
    issued tokens only), but a hand-edited policy file can hold it and the server must keep working with one, so
    the fixtures build it by flipping the flag around the import."""
    from dataclasses import replace

    principal = editor.policy.principal(name)
    if principal is None or not principal.admin:
        return editor.import_token(name, key, **kwargs)
    editor._update(principal, replace(principal, admin=False))
    try:
        return editor.import_token(name, key, **kwargs)
    finally:
        editor._update(editor.policy.principal(name), replace(editor.policy.principal(name), admin=True))


def write_policy_with_agent_star(path) -> str:
    """A policy file as a 0.2-era one could hold it: agent ``bot`` with a ``*`` grant (``g_aaaaaaaa``), which the
    strict rules now refuse. Written by hand (``dump_policy``), since the editor would refuse to build it. Returns
    the path; the admin ``matt`` has a token, so the file is otherwise usable."""
    from datetime import UTC, datetime
    from pathlib import Path

    from mattstash.authz import Grant, Policy, Principal, Token, dump_policy, generate_token, hash_token

    when = datetime(2026, 1, 1, tzinfo=UTC)
    token_id, plaintext = generate_token()
    policy = Policy(
        principals=(
            Principal(
                "matt", "human-device", admin=True, created=when, tokens=(Token(token_id, hash_token(plaintext), when),)
            ),
            Principal("bot", "agent", created=when),
        ),
        grants=(
            Grant("g_aaaaaaaa", "bot", "*", None, frozenset({"list", "read"}), created=when),
            Grant("g_bbbbbbbb", "bot", "app.*", None, frozenset({"list", "read"}), created=when),
        ),
    )
    Path(path).write_text(dump_policy(policy))
    return str(path)


def write_default_policy(path: Path) -> str:
    """The policy the ``client`` fixtures run on: principal ``full`` (human-device admin, ``*`` on every action) whose
    token is ``FULL_KEY``, imported as a plain key (the ``sha256:`` scheme), so ``auth()`` works as it always did."""
    from mattstash.authz import edit_policy

    with edit_policy(path, create=True) as ed:
        ed.add_principal("full", "human-device", "default test principal", admin=True)
        ed.add_grant("full", key="*", actions=["list", "read", "write", "delete"])
        import_plain_key(ed, "full", FULL_KEY)
    return str(path)


@pytest.fixture
def default_policy(tmp_path) -> str:
    return write_default_policy(tmp_path / "default-policy.json")


@pytest.fixture
def configure(monkeypatch, db_path, default_policy):
    """Set server configuration for a test (class attributes are read at request time)."""
    from app.config import Config

    def _configure(**overrides) -> None:
        defaults = {
            "DB_PATH": str(db_path),
            "KDBX_PASSWORD": DB_PASSWORD,
            "KDBX_PASSWORD_FILE": None,
            "POLICY_FILE": default_policy,
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
    """Default: the ``full`` principal (``FULL_KEY``), read-only mode."""
    return make_client()


@pytest.fixture
def rw_client(make_client) -> TestClient:
    """Default principal, writes enabled."""
    return make_client(ALLOW_WRITES=True)


@pytest.fixture
def policy_tokens(tmp_path) -> dict[str, str]:
    """A v2 policy file (``tmp_path/policy.json``) exercising every role; returns each principal's plaintext token.

    matt: admin human-device without any data grant. hermes: ``firefly.*`` list+read, exact ``firefly-mcp`` read,
    tag ``shared`` list+read. lister: ``firefly.*`` list only. fireflyer: ``firefly.*`` list+read.
    scribe: ``app-*`` all four. runner: every name of the ``data`` fixture
    (one ``<letter>*`` grant per first letter), list+read.
    expired / off: valid tokens that must not work (past expiry, disabled principal).
    """
    from datetime import timedelta

    from mattstash.authz import edit_policy
    from mattstash.authz.models import utcnow

    tokens: dict[str, str] = {}
    with edit_policy(tmp_path / "policy.json", create=True) as ed:
        ed.add_principal("matt", "human-device", "laptop", admin=True)
        ed.add_principal("hermes", "agent")
        ed.add_principal("lister", "agent")
        ed.add_principal("fireflyer", "agent")
        ed.add_principal("scribe", "agent")
        ed.add_principal("runner", "runner")
        ed.add_principal("expired", "agent")
        ed.add_principal("off", "agent")
        ed.add_grant("hermes", key="firefly.*", actions=["list", "read"])
        ed.add_grant("hermes", key="firefly-mcp", actions=["read"])
        ed.add_grant("hermes", tag="shared", actions=["list", "read"])
        ed.add_grant("lister", key="firefly.*", actions=["list"])
        ed.add_grant("fireflyer", key="firefly.*", actions=["list", "read"])
        ed.add_grant("scribe", key="app-*", actions=["list", "read", "write", "delete"])
        for prefix in RUNNER_PREFIXES:  # '*' alone is only for human-device principals
            ed.add_grant("runner", key=f"{prefix}*", actions=["list", "read"])
        ed.add_grant("off", key="a*", actions=["list", "read"])
        for name in ("matt", "hermes", "lister", "fireflyer", "scribe", "runner", "off"):
            tokens[name] = ed.issue_token(name)[1]
        ed.set_disabled("off", True)
    # The library refuses an already-expired NEW token, so issue it as of two hours ago, expiring an hour ago.
    with edit_policy(tmp_path / "policy.json", now=utcnow() - timedelta(hours=2)) as ed:
        tokens["expired"] = ed.issue_token("expired", utcnow() - timedelta(hours=1))[1]
    return tokens


@pytest.fixture
def policy_path(tmp_path, policy_tokens) -> str:
    return str(tmp_path / "policy.json")


@pytest.fixture
def data(seed):
    """Entries on both sides of every grant boundary. ``shared-note`` is a password-only entry that is TAGGED: the
    library reads it back as a bare dict without tags, which the server must not mistake for 'no tags'."""
    stash = seed(
        **{
            "firefly.token": {"value": "ff-secret"},
            "firefly.db": DB,
            "firefly-mcp": {"value": "mcp-secret"},
            "firefly": {"value": "bare-secret"},
            "app-db": DB,
            "app-token": {"value": "tok"},
            "other": {"value": "private"},
            "shared-note": {"password": "tagged-secret", "tags": ["shared"]},
            "shared-db": {**DB, "tags": ["shared"]},
        }
    )
    stash.put("retag", value="v1-untagged")  # latest version carries the tag: it decides for every version
    stash.put("retag", password="v2-tagged", tags=["shared"])
    stash.put("demoted", password="v1-tagged", tags=["shared"])
    stash.put("demoted", password="v2-untagged", tags=["other"])
    return stash


class Clock:
    """The access log's monotonic clock, set by the test."""

    def __init__(self) -> None:
        self.now = 1000.0

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock(monkeypatch):
    from app import accesslog

    fake = Clock()
    monkeypatch.setattr(accesslog, "_now", lambda: fake.now)
    return fake


@pytest.fixture
def log_path(tmp_path) -> str:
    """Where tests that use an access-log file put it."""
    return str(tmp_path / "access.jsonl")


def auth(key: str = FULL_KEY) -> dict[str, str]:
    return {"X-API-Key": key}
