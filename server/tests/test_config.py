"""Tests for app.config module."""

import pytest

from .conftest import fresh_config_module


class TestConfig:
    """Test configuration management."""

    def test_default_values(self, clean_env, monkeypatch):
        """Verify default configuration values."""
        # Reload config to get defaults

        config_module = fresh_config_module()

        config = config_module.Config()
        assert config.DB_PATH == "/data/mattstash.kdbx"
        assert config.KDBX_PASSWORD is None
        assert config.KDBX_PASSWORD_FILE is None
        assert config.HOST == "0.0.0.0"
        assert config.PORT == 8000
        assert config.LOG_LEVEL == "info"
        assert config.API_KEY is None
        assert config.API_KEYS_FILE is None
        assert config.RATE_LIMIT == "100/minute"
        assert config.API_VERSION == "v1"
        assert config.API_TITLE == "MattStash API"

    def test_env_override_db_path(self, clean_env, monkeypatch):
        """Environment variable overrides DB_PATH."""
        monkeypatch.setenv("MATTSTASH_DB_PATH", "/custom/path/db.kdbx")

        config_module = fresh_config_module()

        config = config_module.Config()
        assert config.DB_PATH == "/custom/path/db.kdbx"

    def test_env_override_host_port(self, clean_env, monkeypatch):
        """Environment variable overrides HOST/PORT."""
        monkeypatch.setenv("MATTSTASH_HOST", "127.0.0.1")
        monkeypatch.setenv("MATTSTASH_PORT", "9000")

        config_module = fresh_config_module()

        config = config_module.Config()
        assert config.HOST == "127.0.0.1"
        assert config.PORT == 9000

    def test_invalid_port_fails_fast(self, clean_env, monkeypatch):
        """Invalid port values fail with a clear error."""
        monkeypatch.setenv("MATTSTASH_PORT", "not-a-port")

        with pytest.raises(ValueError, match="MATTSTASH_PORT must be an integer"):
            fresh_config_module()

    def test_invalid_poll_interval_fails_fast(self, clean_env, monkeypatch):
        """Invalid polling intervals fail with a clear error."""
        monkeypatch.setenv("MATTSTASH_DB_POLL_INTERVAL", "-1")

        with pytest.raises(ValueError, match="MATTSTASH_DB_POLL_INTERVAL must be between"):
            fresh_config_module()

    def test_get_kdbx_password_from_env(self, clean_env, monkeypatch):
        """Password from KDBX_PASSWORD env var."""
        monkeypatch.setenv("KDBX_PASSWORD", "env_password_123")

        config_module = fresh_config_module()

        config = config_module.Config()
        password = config.get_kdbx_password()
        assert password == "env_password_123"

    def test_get_kdbx_password_from_file(self, clean_env, monkeypatch, temp_password_file):
        """Password from KDBX_PASSWORD_FILE."""
        monkeypatch.setenv("KDBX_PASSWORD_FILE", str(temp_password_file))

        config_module = fresh_config_module()

        config = config_module.Config()
        password = config.get_kdbx_password()
        assert password == "test_password_123"

    def test_get_kdbx_password_file_not_found(self, clean_env, monkeypatch):
        """FileNotFoundError when file missing."""
        monkeypatch.setenv("KDBX_PASSWORD_FILE", "/nonexistent/password.txt")

        config_module = fresh_config_module()

        config = config_module.Config()
        with pytest.raises(FileNotFoundError, match="Password file not found"):
            config.get_kdbx_password()

    def test_get_kdbx_password_no_source(self, clean_env, monkeypatch):
        """ValueError when no password configured."""

        config_module = fresh_config_module()

        config = config_module.Config()
        with pytest.raises(ValueError, match="KDBX password must be provided"):
            config.get_kdbx_password()

    def test_get_kdbx_password_file_strips_whitespace(self, tmp_path, monkeypatch, clean_env):
        """KDBX_PASSWORD_FILE content is stripped of surrounding whitespace."""
        password_file = tmp_path / "password.txt"
        password_file.write_text("  mypassword  \n")

        config_module = fresh_config_module()

        monkeypatch.setattr(config_module.Config, "KDBX_PASSWORD", None)
        monkeypatch.setattr(config_module.Config, "KDBX_PASSWORD_FILE", str(password_file))

        config = config_module.Config()
        assert config.get_kdbx_password() == "mypassword"


class TestNewSettings:
    """Settings added by the hardening work: defaults are the safe ones."""

    def test_safe_defaults(self, clean_env):
        config = fresh_config_module().Config()
        assert config.ALLOW_WRITES is False  # read-only unless explicitly enabled
        assert config.MIN_KEY_LENGTH == 32
        assert config.REQUIRE_SCOPED_KEYS is False  # legacy keys keep working on upgrade
        assert config.DISABLE_DOCS is False
        assert config.REFUSE_SIDECAR is False
        assert (config.AUTH_FAIL_LIMIT, config.AUTH_FAIL_WINDOW) == (10, 60)
        assert config.TRUSTED_PROXY_HOPS == 0  # client IP is the TCP peer unless proxies are declared
        assert config.TLS_CERT_FILE is None and config.TLS_KEY_FILE is None

    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("true", True),
            ("1", True),
            ("YES", True),
            ("on", True),
            ("false", False),
            ("0", False),
            ("", False),
            ("maybe", False),
        ],
    )
    def test_boolean_parsing(self, clean_env, monkeypatch, raw, expected):
        monkeypatch.setenv("MATTSTASH_ALLOW_WRITES", raw)
        assert fresh_config_module().Config().ALLOW_WRITES is expected

    @pytest.mark.parametrize(
        "var, value",
        [
            ("MATTSTASH_MIN_KEY_LENGTH", "4"),
            ("MATTSTASH_AUTH_FAIL_LIMIT", "0"),
            ("MATTSTASH_AUTH_FAIL_WINDOW_SECONDS", "x"),
            ("MATTSTASH_TRUSTED_PROXY_HOPS", "11"),
            ("MATTSTASH_TRUSTED_PROXY_HOPS", "-1"),
        ],
    )
    def test_bounds_fail_fast(self, clean_env, monkeypatch, var, value):
        monkeypatch.setenv(var, value)
        with pytest.raises(ValueError, match=var):
            fresh_config_module()

    def test_tls_files_must_be_set_together(self, clean_env, monkeypatch):
        monkeypatch.setenv("MATTSTASH_TLS_CERT_FILE", "/c.pem")
        config = fresh_config_module().Config
        with pytest.raises(ValueError, match="set together"):
            config.validate_tls()
        monkeypatch.setenv("MATTSTASH_TLS_KEY_FILE", "/k.pem")
        assert fresh_config_module().Config.validate_tls() is True
        monkeypatch.delenv("MATTSTASH_TLS_CERT_FILE")
        monkeypatch.delenv("MATTSTASH_TLS_KEY_FILE")
        assert fresh_config_module().Config.validate_tls() is False

    def test_empty_password_file_is_rejected(self, clean_env, monkeypatch, tmp_path):
        empty = tmp_path / "pw"
        empty.write_text("\n")
        monkeypatch.setenv("KDBX_PASSWORD_FILE", str(empty))
        with pytest.raises(ValueError, match="empty"):
            fresh_config_module().Config.get_kdbx_password()
