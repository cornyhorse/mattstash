"""Shared fixtures.

MattStash never creates a database implicitly, so the common ``temp_db`` fixture creates one
explicitly (with a sidecar password file, the layout most tests exercise) and returns its path.
"""

import os
from collections.abc import Generator
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
    # a developer's or CI machine's proxy settings change what the HTTP client does (and warns about)
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
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


@pytest.fixture(scope="session")
def _cheap_blank_database(tmp_path_factory: pytest.TempPathFactory) -> str:
    """A copy of pykeepass's blank-database template whose Argon2 key derivation is nearly free.

    ``create_database`` starts from that template and keeps its KDF parameters, so every database the tests create
    inherits them (and any process that later opens the file, e.g. a real server subprocess, reads them from the
    file header). The shipped template costs ~0.5 s per open and per save (Argon2, 64 MiB, 14 passes), which made
    the suite spend almost all of its time hashing. Tests that are *about* the KDF opt out with
    ``@pytest.mark.real_kdf``. Production code is untouched: users still get the strong default.
    """
    import pykeepass.pykeepass as kp_module

    path = str(tmp_path_factory.mktemp("kdf") / "blank-cheap.kdbx")
    blank = kp_module.PyKeePass(kp_module.BLANK_DATABASE_LOCATION, kp_module.BLANK_DATABASE_PASSWORD)
    params = blank.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
    params["I"].value = 1  # iterations
    params["M"].value = 1024 * 1024  # memory in bytes (1 MiB)
    blank.filename = path
    blank.save()
    return path


@pytest.fixture(scope="session", autouse=True)
def _cheap_kdf(_cheap_blank_database: str) -> Generator[None, None, None]:
    """Session-wide, so module-scoped database fixtures (they run before function-scoped ones) are cheap too."""
    import pykeepass.pykeepass as kp_module

    original = kp_module.BLANK_DATABASE_LOCATION
    kp_module.BLANK_DATABASE_LOCATION = _cheap_blank_database
    os.environ["MATTSTASH_TEST_BLANK_DB"] = (
        _cheap_blank_database  # for test scripts that create databases in a subprocess
    )
    _REAL_BLANK.append(original)
    yield
    os.environ.pop("MATTSTASH_TEST_BLANK_DB", None)
    kp_module.BLANK_DATABASE_LOCATION = original


_REAL_BLANK: list[str] = []


@pytest.fixture(autouse=True)
def _real_kdf_when_marked(request: pytest.FixtureRequest, _cheap_blank_database: str) -> Generator[None, None, None]:
    if not request.node.get_closest_marker("real_kdf"):
        yield
        return
    import pykeepass.pykeepass as kp_module

    kp_module.BLANK_DATABASE_LOCATION = _REAL_BLANK[0]
    try:
        yield
    finally:
        kp_module.BLANK_DATABASE_LOCATION = _cheap_blank_database


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
