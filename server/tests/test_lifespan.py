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
    with pytest.raises(ValueError, match="KDBX password must be provided"):
        _start(create_app())


def test_startup_fails_kdbx_password_file_not_found(monkeypatch):
    monkeypatch.setattr(Config, "KDBX_PASSWORD", None)
    monkeypatch.setattr(Config, "KDBX_PASSWORD_FILE", "/nonexistent/path.txt")
    with pytest.raises(FileNotFoundError, match="Password file not found"):
        _start(create_app())


def test_startup_fails_without_a_policy_file(configure):
    configure(POLICY_FILE=None)
    with pytest.raises(ValueError, match="MATTSTASH_POLICY_FILE is not set") as info:
        _start(create_app())
    assert "docs/upgrading-to-0.3.md" in str(info.value)


def test_startup_fails_when_the_policy_file_is_missing(configure, tmp_path):
    configure(POLICY_FILE=str(tmp_path / "nope.json"))
    with pytest.raises(FileNotFoundError, match="Policy file not found"):
        _start(create_app())


def _policy_with(tmp_path, *, token=True, disabled=False, expired=False) -> str:
    from datetime import timedelta

    from mattstash.authz import edit_policy
    from mattstash.authz.models import utcnow

    path = tmp_path / "p.json"
    with edit_policy(path, now=utcnow() - timedelta(hours=2), create=True) as ed:
        ed.add_principal("bot", "agent")
        if token:
            ed.issue_token("bot", utcnow() - timedelta(hours=1) if expired else None)
        ed.set_disabled("bot", disabled)
    return str(path)


@pytest.mark.parametrize(
    "kwargs",
    [
        pytest.param({"token": False}, id="no-token"),
        pytest.param({"disabled": True}, id="disabled-principal"),
    ],
)
def test_startup_fails_when_the_policy_has_no_usable_credential(configure, tmp_path, kwargs):
    configure(POLICY_FILE=_policy_with(tmp_path, **kwargs))
    with pytest.raises(ValueError, match="no usable credential"):
        _start(create_app())


def test_startup_fails_when_every_token_has_expired(configure, tmp_path):
    from datetime import timedelta

    from mattstash.authz import edit_policy
    from mattstash.authz.models import utcnow

    path = tmp_path / "p.json"
    with edit_policy(path, now=utcnow() - timedelta(hours=2), create=True) as ed:
        ed.add_principal("bot", "agent")
        ed.issue_token("bot", utcnow() - timedelta(hours=1))
    configure(POLICY_FILE=str(path))
    with pytest.raises(ValueError, match="no usable credential"):
        _start(create_app())


REMOVED = ["MATTSTASH_API_KEY", "MATTSTASH_API_KEYS_FILE", "MATTSTASH_REQUIRE_SCOPED_KEYS"]


@pytest.mark.parametrize("name", REMOVED)
def test_startup_refuses_a_removed_setting_and_says_where_to_go(configure, monkeypatch, name):
    configure()
    monkeypatch.setenv(name, "some-value-" + "k" * 30)
    with pytest.raises(ValueError, match=name) as info:
        _start(create_app())
    message = str(info.value)
    assert "docs/upgrading-to-0.3.md" in message and "MATTSTASH_POLICY_FILE" in message
    assert "some-value" not in message  # the names only, never a value


def test_startup_names_every_removed_setting_that_is_set(configure, monkeypatch):
    configure()
    for name in REMOVED:
        monkeypatch.setenv(name, "false")  # even 'false' counts: the variable no longer exists
    with pytest.raises(ValueError) as info:
        _start(create_app())
    assert all(name in str(info.value) for name in REMOVED) and " are set" in str(info.value)


def test_an_empty_removed_setting_is_not_an_error(configure, monkeypatch):
    configure()
    for name in REMOVED:
        monkeypatch.setenv(name, "  ")  # an empty compose variable (`KEY=${KEY:-}`) is not a configuration
    _start(create_app())


def test_python_dash_m_app_refuses_a_removed_setting_without_a_traceback(monkeypatch, capsys):
    import app.__main__ as entry

    ran = []
    monkeypatch.setattr(entry.uvicorn, "run", lambda *a, **k: ran.append(1))
    monkeypatch.setenv("MATTSTASH_API_KEY", "some-value-" + "k" * 30)
    with pytest.raises(SystemExit) as info:
        entry.main()
    assert "MATTSTASH_API_KEY" in str(info.value.code) and "some-value" not in str(info.value.code)
    assert not ran


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


def test_startup_warns_once_per_sha256_token_and_names_it(client, caplog, default_policy):
    # `client` already started the app on the default policy (FULL_KEY was imported: a sha256: token); restart to log
    from mattstash.authz import load_policy

    caplog.set_level(logging.WARNING, logger="mattstash.api")
    with TestClient(create_app()):
        pass
    token_id = load_policy(default_policy).principal("full").tokens[0].id
    lines = [r.getMessage() for r in caplog.records if "unsalted 'sha256:'" in r.getMessage()]
    assert len(lines) == 1 and token_id in lines[0] and "principal full" in lines[0]
    assert f"mattstash admin token rotate full {token_id}" in lines[0]
    assert FULL_KEY not in caplog.text


def test_startup_does_not_warn_about_salted_tokens(configure, policy_path, policy_tokens, caplog):
    configure(POLICY_FILE=policy_path)
    caplog.set_level(logging.WARNING, logger="mattstash.api")
    _start(create_app())
    assert "sha256" not in caplog.text


def _admin_policy(tmp_path, days: int | None) -> str:
    from datetime import timedelta

    from mattstash.authz import edit_policy
    from mattstash.authz.models import utcnow

    path = tmp_path / "admin.json"
    with edit_policy(path, create=True) as ed:
        ed.add_principal("matt", "human-device", admin=True)
        ed.issue_token("matt", None if days is None else utcnow() + timedelta(days=days))
    return str(path)


def test_startup_logs_the_early_warning_when_every_admin_token_expires_within_14_days(configure, tmp_path, caplog):
    configure(POLICY_FILE=_admin_policy(tmp_path, 5))
    caplog.set_level(logging.WARNING, logger="mattstash.api")
    _start(create_app())
    lines = [r.getMessage() for r in caplog.records if "every admin token expires within 14 days" in r.getMessage()]
    assert len(lines) == 1 and "mattstash admin token issue" in lines[0]


def test_no_early_warning_when_an_admin_token_lasts(configure, tmp_path, caplog):
    for days in (None, 30):
        caplog.clear()
        configure(POLICY_FILE=_admin_policy(tmp_path / str(days), days))
        caplog.set_level(logging.WARNING, logger="mattstash.api")
        _start(create_app())
        assert "admin token" not in caplog.text


def test_sidecar_next_to_database_warns(configure, db_path, caplog):
    (db_path.parent / ".mattstash.txt").write_text(DB_PASSWORD)
    configure()
    caplog.set_level(logging.WARNING, logger="mattstash.api")
    _start(create_app())
    assert "Plaintext password file(s)" in caplog.text and ".mattstash.txt" in caplog.text


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
