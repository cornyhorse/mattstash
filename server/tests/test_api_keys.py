"""Tests for app.security.api_keys module."""
import pytest

from app.security.api_keys import get_valid_api_keys, verify_api_key


class TestAPIKeys:
    """Test API key management and verification."""
    
    def test_get_valid_api_keys_caching(self, clean_env, monkeypatch):
        """Keys are cached after first call."""
        monkeypatch.setenv("MATTSTASH_API_KEY", "cached-key")
        
        # Reset cache
        import app.security.api_keys as api_keys_module
        api_keys_module._api_keys = None
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        # First call - should populate cache
        keys1 = get_valid_api_keys()
        
        # Second call - should return cached value
        keys2 = get_valid_api_keys()
        
        assert keys1 is keys2  # Same object reference (cached)
        assert keys1 == {"cached-key"}
    
    def test_verify_api_key_valid(self, clean_env, monkeypatch):
        """Valid key returns True."""
        monkeypatch.setenv("MATTSTASH_API_KEY", "valid-key-123")
        
        # Reset cache
        import app.security.api_keys as api_keys_module
        api_keys_module._api_keys = None
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        result = verify_api_key("valid-key-123")
        assert result is True
    
    def test_verify_api_key_invalid(self, clean_env, monkeypatch):
        """Invalid key returns False."""
        monkeypatch.setenv("MATTSTASH_API_KEY", "correct-key")
        
        # Reset cache
        import app.security.api_keys as api_keys_module
        api_keys_module._api_keys = None
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        result = verify_api_key("wrong-key")
        assert result is False
    
    def test_verify_api_key_empty(self, clean_env, monkeypatch):
        """Empty string returns False."""
        monkeypatch.setenv("MATTSTASH_API_KEY", "valid-key")
        
        # Reset cache
        import app.security.api_keys as api_keys_module
        api_keys_module._api_keys = None
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        result = verify_api_key("")
        assert result is False
