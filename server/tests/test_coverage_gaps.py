"""Behaviour that no other server test reaches: the process entry point, key-tool script mode, the
header-authentication dependency without the middleware, unreadable password files, and several error branches.

Everything here runs in-process (``uvicorn.run`` is mocked; no sockets are opened, nothing is slept on).
"""

import inspect
import io
import json
import logging
import os
import runpy
import sys
from types import SimpleNamespace
from typing import Annotated
from unittest.mock import MagicMock

import pytest
import uvicorn
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient
from starlette.responses import Response
from uvicorn.importer import import_from_string

from app.config import Config
from app.dependencies import authenticate_request
from app.main import create_app
from app.rate_limit import rate_limit_exceeded_handler
from app.security.api_keys import Principal

from .conftest import FULL_KEY, auth

H = auth()


# ---------------------------------------------------------------------------
# python -m app  (app/__main__.py)
# ---------------------------------------------------------------------------


@pytest.fixture
def uvicorn_run(monkeypatch) -> MagicMock:
    """Replace ``uvicorn.run`` so the entry point can be exercised without starting a server."""
    run = MagicMock(name="uvicorn.run")
    monkeypatch.setattr(uvicorn, "run", run)
    return run


@pytest.fixture
def server_settings(monkeypatch):
    """Set the server options ``main()`` reads (``Config`` captures its environment at import time)."""

    def _set(**overrides) -> None:
        settings = {"HOST": "0.0.0.0", "PORT": 8000, "LOG_LEVEL": "info", "TLS_CERT_FILE": None, "TLS_KEY_FILE": None}
        settings.update(overrides)
        for name, value in settings.items():
            monkeypatch.setattr(Config, name, value)

    return _set


def test_entry_point_starts_uvicorn_with_the_plain_http_defaults(uvicorn_run, server_settings):
    from app.__main__ import main

    server_settings()
    main()

    uvicorn_run.assert_called_once_with(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        log_level="info",
        ssl_certfile=None,
        ssl_keyfile=None,
        access_log=False,  # the app has its own access log with the key id
        server_header=False,
        proxy_headers=False,  # client addresses come from MATTSTASH_TRUSTED_PROXY_HOPS
    )


def test_entry_point_passes_host_port_and_lowercased_log_level(uvicorn_run, server_settings):
    from app.__main__ import main

    server_settings(HOST="127.0.0.1", PORT=9001, LOG_LEVEL="DEBUG")
    main()

    options = uvicorn_run.call_args.kwargs
    assert (options["host"], options["port"], options["log_level"]) == ("127.0.0.1", 9001, "debug")
    assert options["ssl_certfile"] is None and options["ssl_keyfile"] is None


@pytest.mark.parametrize(
    ("configured", "expected"),
    [
        ("WARN", "warning"),
        ("fatal", "critical"),
        ("Critical", "critical"),
        ("error", "error"),
        ("notset", "debug"),
        ("trace", "info"),  # the application has no trace level, so it logs at info
        ("verbose", "info"),  # unknown names fall back to info, for the application and for uvicorn alike
    ],
)
def test_entry_point_never_hands_uvicorn_a_log_level_it_rejects(uvicorn_run, server_settings, configured, expected):
    from uvicorn.config import LOG_LEVELS

    from app.__main__ import main

    server_settings(LOG_LEVEL=configured)
    main()

    level = uvicorn_run.call_args.kwargs["log_level"]
    assert level == expected and level in LOG_LEVELS, "uvicorn raises KeyError at startup for names it does not know"


def test_entry_point_enables_tls_when_certificate_and_key_are_both_set(uvicorn_run, server_settings, tmp_path):
    from app.__main__ import main

    cert, key = str(tmp_path / "server.crt"), str(tmp_path / "server.key")
    server_settings(TLS_CERT_FILE=cert, TLS_KEY_FILE=key)
    main()

    options = uvicorn_run.call_args.kwargs
    assert options["ssl_certfile"] == cert and options["ssl_keyfile"] == key


@pytest.mark.parametrize("missing", ["TLS_CERT_FILE", "TLS_KEY_FILE"])
def test_entry_point_refuses_half_a_tls_configuration_without_starting(uvicorn_run, server_settings, tmp_path, missing):
    from app.__main__ import main

    server_settings(**{"TLS_CERT_FILE": str(tmp_path / "c"), "TLS_KEY_FILE": str(tmp_path / "k"), missing: None})
    with pytest.raises(ValueError, match="must be set together"):
        main()
    uvicorn_run.assert_not_called()


def test_entry_point_arguments_are_valid_for_uvicorn(uvicorn_run, server_settings, tmp_path):
    """A typo'd option name or a dangling app path would only show up when the container starts."""
    from app.__main__ import main

    server_settings(TLS_CERT_FILE=str(tmp_path / "c"), TLS_KEY_FILE=str(tmp_path / "k"))
    main()

    args, kwargs = uvicorn_run.call_args
    inspect.signature(uvicorn.Config).bind(*args, **kwargs)  # TypeError on an unknown or duplicated option
    assert isinstance(import_from_string(args[0]), FastAPI)


def test_python_dash_m_app_runs_main(uvicorn_run, server_settings, monkeypatch):
    server_settings(HOST="::1", PORT=8443)
    # Executing a module that is already imported would otherwise emit runpy's "unpredictable behaviour" warning.
    monkeypatch.delitem(sys.modules, "app.__main__", raising=False)

    runpy.run_module("app", run_name="__main__")

    uvicorn_run.assert_called_once()
    assert uvicorn_run.call_args.kwargs["host"] == "::1" and uvicorn_run.call_args.kwargs["port"] == 8443


# ---------------------------------------------------------------------------
# python -m app.keytool
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "stdin",
    [pytest.param("", id="empty"), pytest.param("\n", id="lf"), pytest.param("\r\n", id="crlf")],
)
def test_keytool_stdin_without_a_key_is_a_usage_error(monkeypatch, capsys, stdin):
    from app.keytool import main

    monkeypatch.setattr(sys, "stdin", io.StringIO(stdin))
    with pytest.raises(SystemExit) as exit_info:
        main(["--id", "ci", "--stdin"])

    assert exit_info.value.code == 2  # argparse usage error
    captured = capsys.readouterr()
    assert "no key received on stdin" in captured.err
    assert captured.out == ""  # no policy entry is printed for an empty key


def test_python_dash_m_keytool_prints_the_policy_entry_and_exits_zero(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["keytool", "--id", "ci", "--ops", "read,write", "--prefix", "ci-"])
    monkeypatch.delitem(sys.modules, "app.keytool", raising=False)  # see test_python_dash_m_app_runs_main

    with pytest.raises(SystemExit) as exit_info:
        runpy.run_module("app.keytool", run_name="__main__")

    assert exit_info.value.code == 0
    captured = capsys.readouterr()
    entry = json.loads(captured.out)
    assert entry["id"] == "ci" and entry["ops"] == ["read", "write"] and entry["prefixes"] == ["ci-"]
    assert "API key (shown once" in captured.err


# ---------------------------------------------------------------------------
# authenticate_request without SecurityMiddleware (app/dependencies.py)
# ---------------------------------------------------------------------------


@pytest.fixture
def bare_client(configure) -> TestClient:
    """An app that uses the ``authenticate_request`` dependency but has no SecurityMiddleware in front of it."""
    configure()
    bare = FastAPI()

    @bare.get("/whoami")
    async def whoami(
        request: Request, principal: Annotated[Principal, Depends(authenticate_request)]
    ) -> dict[str, str]:
        return {"id": principal.id, "on_request_state": request.state.principal.id}

    return TestClient(bare)


def test_header_is_verified_by_the_dependency_when_no_middleware_ran(bare_client):
    response = bare_client.get("/whoami", headers=H)

    assert response.status_code == 200
    assert response.json() == {"id": "legacy-env", "on_request_state": "legacy-env"}


@pytest.mark.parametrize("headers", [{}, {"X-API-Key": ""}, {"X-API-Key": "x" * 40}, {"X-API-Key": FULL_KEY + "x"}])
def test_missing_empty_or_wrong_key_is_401_without_the_middleware(bare_client, headers):
    response = bare_client.get("/whoami", headers=headers)

    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication failed"}


def test_unusable_key_store_is_503_not_401_without_the_middleware(bare_client, monkeypatch, caplog):
    import app.dependencies as dependencies

    def broken_store(key: str):
        raise OSError("/etc/secret-keys.json: disk error")

    monkeypatch.setattr(dependencies, "authenticate", broken_store)
    caplog.set_level(logging.ERROR, logger="mattstash.api")

    response = bare_client.get("/whoami", headers=H)

    assert response.status_code == 503
    assert response.json() == {"detail": "Service temporarily unavailable"}
    assert "API key store unavailable: OSError" in caplog.text
    assert "secret-keys.json" not in response.text + caplog.text


# ---------------------------------------------------------------------------
# Config.get_kdbx_password: a password file that exists but cannot be used
# ---------------------------------------------------------------------------


@pytest.fixture
def password_file(monkeypatch):
    """Point the (real) Config at ``path`` as the password file and no password variable."""

    def _use(path) -> None:
        monkeypatch.setattr(Config, "KDBX_PASSWORD", None)
        monkeypatch.setattr(Config, "KDBX_PASSWORD_FILE", str(path))

    return _use


def _write(path, data: bytes):
    path.write_bytes(data)
    return path


@pytest.mark.parametrize(
    ("make_path", "error_name"),
    [
        pytest.param(lambda tmp: tmp, "IsADirectoryError", id="directory"),
        pytest.param(lambda tmp: _write(tmp / "pw", b"\xff\xfe not utf-8 \x80"), "UnicodeDecodeError", id="not-utf8"),
    ],
)
def test_unreadable_password_file_is_a_value_error_naming_only_the_error_type(
    password_file, tmp_path, make_path, error_name
):
    path = make_path(tmp_path)
    password_file(path)

    with pytest.raises(ValueError, match=f"^KDBX password file cannot be read: {error_name}$") as raised:
        Config.get_kdbx_password()

    assert str(path) not in str(raised.value)  # the path and any file content stay out of the message
    assert raised.value.__suppress_context__ and raised.value.__cause__ is None


# ---------------------------------------------------------------------------
# main.py: warning when writes are enabled but the data directory is read-only
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("writable", [True, False])
def test_write_mode_warns_only_when_the_data_directory_is_not_writable(
    configure, db_path, monkeypatch, caplog, writable
):
    """``os.access`` is faked for the data directory: root can write anywhere, so chmod cannot set this up."""
    configure(ALLOW_WRITES=True)
    real_access = os.access

    def access(path, mode, *args, **kwargs) -> bool:
        if mode == os.W_OK and os.fspath(path) == str(db_path.parent):
            return writable
        return real_access(path, mode, *args, **kwargs)

    monkeypatch.setattr(os, "access", access)
    caplog.set_level(logging.WARNING, logger="mattstash.api")

    with TestClient(create_app()):
        pass

    assert "Writes are ENABLED" in caplog.text
    assert ("data directory is not writable" in caplog.text) is (not writable)


# ---------------------------------------------------------------------------
# SecurityMiddleware: an exception escaping the application
# ---------------------------------------------------------------------------


def test_unhandled_application_error_is_logged_by_type_and_still_reaches_the_server_error_handler(configure, caplog):
    configure()
    application = create_app()

    @application.get("/api/v1/boom")
    def boom() -> Response:
        raise RuntimeError("internal-secret-detail")

    caplog.set_level(logging.INFO, logger="mattstash.api")
    with TestClient(application, raise_server_exceptions=False) as client:
        response = client.get("/api/v1/boom", headers=H)

    assert response.status_code == 500
    assert "internal-secret-detail" not in response.text + caplog.text  # only the exception type is logged
    assert "Unhandled error: GET /api/v1/boom - RuntimeError" in caplog.text
    assert "GET /api/v1/boom -> 500" in caplog.text  # the access-log line is still written (``finally``)


# ---------------------------------------------------------------------------
# rate limiter: Retry-After fallback
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "exc",
    [
        pytest.param(SimpleNamespace(limit=None, detail="5 per 1 minute"), id="no-limit-object"),
        pytest.param(SimpleNamespace(limit=SimpleNamespace(limit=object()), detail="5 per 1 minute"), id="no-expiry"),
    ],
)
def test_rate_limit_response_falls_back_to_one_minute_for_an_unknown_limit_shape(exc):
    response = rate_limit_exceeded_handler(Request({"type": "http"}), exc)

    assert response.status_code == 429
    assert response.headers["retry-after"] == "60"
    assert json.loads(response.body) == {"error": "Rate limit exceeded: 5 per 1 minute"}


# ---------------------------------------------------------------------------
# routers
# ---------------------------------------------------------------------------


def test_versions_of_a_name_that_was_never_stored_is_404(client):
    response = client.get("/api/v1/credentials/never-stored/versions", headers=H)

    assert response.status_code == 404
    assert response.json() == {"detail": "Credential not found: never-stored"}


def test_db_url_value_error_from_the_builder_is_a_generic_400(rw_client, monkeypatch, caplog):
    import app.routers.db_url as db_url_router

    def refuse(**kwargs) -> str:
        raise ValueError("password hunter2 contains a forbidden character")

    monkeypatch.setattr(db_url_router, "build_db_url", refuse)
    caplog.set_level(logging.ERROR, logger="mattstash.api")

    response = rw_client.get("/api/v1/db-url/pg", params={"database": "orders"}, headers=H)

    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid credential for database URL construction"}
    assert "hunter2" not in response.text + caplog.text  # only the exception type is logged
    assert "Error building database URL for pg: ValueError" in caplog.text


# ---------------------------------------------------------------------------
# titles with "/" (allowed by the library since PR #16) are not addressable through the API
# ---------------------------------------------------------------------------


def test_a_title_with_a_forward_slash_is_not_addressable_through_the_server(rw_client):
    """The library accepts ``cloud/hetzner/s3-key``; the server's single-segment URLs cannot name it (documented:
    use ``.`` for secrets that must be reachable through the API). Neither form of the URL reaches a handler."""
    for name in ("cloud/hetzner/s3-key", "cloud%2Fhetzner%2Fs3-key"):
        assert rw_client.post(f"/api/v1/credentials/{name}", json={"value": "v"}, headers=H).status_code == 404
        assert rw_client.get(f"/api/v1/credentials/{name}", headers=H).status_code == 404
    listed = rw_client.get("/api/v1/credentials", headers=H).json()
    assert listed["credentials"] == [] and listed["count"] == 0
