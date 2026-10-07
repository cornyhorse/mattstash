"""Shared fixtures.

MattStash never creates a database implicitly, so the common ``temp_db`` fixture creates one
explicitly (with a sidecar password file, the layout most tests exercise) and returns its path.
"""

from pathlib import Path

import pytest

from mattstash import MattStash

_SCRUBBED_ENV = (
    "KDBX_PASSWORD",
    "KDBX_PASSWORD_FILE",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "MATTSTASH_DB_PATH",
    "MATTSTASH_SERVER_URL",
    "MATTSTASH_API_KEY",
    "MATTSTASH_API_KEY_FILE",
    "MATTSTASH_ALLOW_INSECURE_HTTP",
)


@pytest.fixture(autouse=True)
def _hermetic_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep ambient credentials/config of the developer or CI machine out of the tests."""
    for name in _SCRUBBED_ENV:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def _fresh_default_instance() -> None:
    """The module-level helpers share one lazily created MattStash; don't let it leak between tests."""
    import mattstash.module_functions as module_functions

    module_functions._default_instance = None


@pytest.fixture()
def temp_db(tmp_path: Path) -> Path:
    """An existing, empty database (+ sidecar password file) in an isolated directory."""
    d = tmp_path / "mattstash"
    d.mkdir()
    db = d / "test.kdbx"
    MattStash.create(str(db), sidecar=True)
    return db


@pytest.fixture()
def missing_db(tmp_path: Path) -> Path:
    """A database path in an existing directory where nothing has been created."""
    d = tmp_path / "mattstash"
    d.mkdir()
    return d / "test.kdbx"
