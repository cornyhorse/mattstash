"""Tests for app.config module."""
import os
from pathlib import Path

import pytest

from app.config import Config


class TestConfig:
    """Test configuration management."""
    
    def test_default_values(self, clean_env, monkeypatch):
        """Verify default configuration values."""
        # Reload config to get defaults
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
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
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        config = config_module.Config()
        assert config.DB_PATH == "/custom/path/db.kdbx"
    
    def test_env_override_host_port(self, clean_env, monkeypatch):
        """Environment variable overrides HOST/PORT."""
        monkeypatch.setenv("MATTSTASH_HOST", "127.0.0.1")
        monkeypatch.setenv("MATTSTASH_PORT", "9000")
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        config = config_module.Config()
        assert config.HOST == "127.0.0.1"
        assert config.PORT == 9000
    
    def test_get_kdbx_password_from_env(self, clean_env, monkeypatch):
        """Password from KDBX_PASSWORD env var."""
        monkeypatch.setenv("KDBX_PASSWORD", "env_password_123")
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        config = config_module.Config()
        password = config.get_kdbx_password()
        assert password == "env_password_123"
    
    def test_get_kdbx_password_from_file(self, clean_env, monkeypatch, temp_password_file):
        """Password from KDBX_PASSWORD_FILE."""
        monkeypatch.setenv("KDBX_PASSWORD_FILE", str(temp_password_file))
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        config = config_module.Config()
        password = config.get_kdbx_password()
        assert password == "test_password_123"
    
    def test_get_kdbx_password_file_not_found(self, clean_env, monkeypatch):
        """FileNotFoundError when file missing."""
        monkeypatch.setenv("KDBX_PASSWORD_FILE", "/nonexistent/password.txt")
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        config = config_module.Config()
        with pytest.raises(FileNotFoundError, match="Password file not found"):
            config.get_kdbx_password()
    
    def test_get_kdbx_password_no_source(self, clean_env, monkeypatch):
        """ValueError when no password configured."""
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        config = config_module.Config()
        with pytest.raises(ValueError, match="KDBX password must be provided"):
            config.get_kdbx_password()
    
    def test_get_api_keys_from_env(self, clean_env, monkeypatch):
        """Single API key from MATTSTASH_API_KEY."""
        monkeypatch.setenv("MATTSTASH_API_KEY", "single-key-123")
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        config = config_module.Config()
        keys = config.get_api_keys()
        assert keys == {"single-key-123"}
    
    def test_get_api_keys_from_file(self, clean_env, monkeypatch, temp_api_keys_file):
        """Multiple keys from file."""
        monkeypatch.setenv("MATTSTASH_API_KEYS_FILE", str(temp_api_keys_file))
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        config = config_module.Config()
        keys = config.get_api_keys()
        assert keys == {"test-key-1", "test-key-2", "test-key-3"}
    
    def test_get_api_keys_combined(self, clean_env, monkeypatch, temp_api_keys_file):
        """Keys from both env and file."""
        monkeypatch.setenv("MATTSTASH_API_KEY", "env-key")
        monkeypatch.setenv("MATTSTASH_API_KEYS_FILE", str(temp_api_keys_file))
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        config = config_module.Config()
        keys = config.get_api_keys()
        assert keys == {"env-key", "test-key-1", "test-key-2", "test-key-3"}
    
    def test_get_api_keys_ignores_comments(self, clean_env, monkeypatch, temp_api_keys_file):
        """Comment lines ignored in key file."""
        # This is tested implicitly in test_get_api_keys_from_file
        # but we verify explicitly that comments don't appear in the set
        monkeypatch.setenv("MATTSTASH_API_KEYS_FILE", str(temp_api_keys_file))
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        config = config_module.Config()
        keys = config.get_api_keys()
        
        # Ensure no comment lines are included
        for key in keys:
            assert not key.startswith("#")
    
    def test_get_api_keys_no_keys(self, clean_env, monkeypatch):
        """ValueError when no keys configured."""
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        config = config_module.Config()
        with pytest.raises(ValueError, match="At least one API key must be provided"):
            config.get_api_keys()
