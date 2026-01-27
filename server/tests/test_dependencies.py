"""Tests for app.dependencies module."""
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from app.dependencies import get_mattstash, verify_api_key_header


class TestDependencies:
    """Test dependency injection."""
    
    def test_get_mattstash_creates_instance(self, clean_env, monkeypatch):
        """Creates MattStash on first call."""
        monkeypatch.setenv("KDBX_PASSWORD", "test_pass")
        monkeypatch.setenv("MATTSTASH_DB_PATH", "/test/db.kdbx")
        
        # Reset cache
        import app.dependencies as deps
        deps._mattstash_instance = None
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        with patch('app.dependencies.MattStash') as MockMattStash:
            mock_instance = MagicMock()
            MockMattStash.return_value = mock_instance
            
            result = get_mattstash()
            
            MockMattStash.assert_called_once_with(
                db_path="/test/db.kdbx",
                password="test_pass"
            )
            assert result is mock_instance
    
    def test_get_mattstash_returns_singleton(self, clean_env, monkeypatch):
        """Returns same instance on subsequent calls."""
        monkeypatch.setenv("KDBX_PASSWORD", "test_pass")
        
        # Reset cache
        import app.dependencies as deps
        deps._mattstash_instance = None
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        with patch('app.dependencies.MattStash') as MockMattStash:
            mock_instance = MagicMock()
            MockMattStash.return_value = mock_instance
            
            result1 = get_mattstash()
            result2 = get_mattstash()
            
            # Should only be called once (singleton)
            MockMattStash.assert_called_once()
            assert result1 is result2
    
    def test_get_mattstash_handles_error(self, clean_env, monkeypatch):
        """Returns 503 if MattStash fails to init."""
        monkeypatch.setenv("KDBX_PASSWORD", "test_pass")
        
        # Reset cache
        import app.dependencies as deps
        deps._mattstash_instance = None
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        with patch('app.dependencies.MattStash') as MockMattStash:
            MockMattStash.side_effect = Exception("Database connection failed")
            
            with pytest.raises(HTTPException) as exc_info:
                get_mattstash()
            
            assert exc_info.value.status_code == 503
            assert "Failed to initialize MattStash" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_verify_api_key_header_missing(self):
        """Returns 401 if header missing."""
        with pytest.raises(HTTPException) as exc_info:
            await verify_api_key_header(x_api_key=None)
        
        assert exc_info.value.status_code == 401
        assert "Missing API key" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_verify_api_key_header_invalid(self, clean_env, monkeypatch):
        """Returns 401 if key invalid."""
        monkeypatch.setenv("MATTSTASH_API_KEY", "correct-key")
        
        # Reset cache
        import app.security.api_keys as api_keys_module
        api_keys_module._api_keys = None
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        with pytest.raises(HTTPException) as exc_info:
            await verify_api_key_header(x_api_key="wrong-key")
        
        assert exc_info.value.status_code == 401
        assert "Invalid API key" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_verify_api_key_header_valid(self, clean_env, monkeypatch):
        """Returns key if valid."""
        monkeypatch.setenv("MATTSTASH_API_KEY", "valid-key-123")
        
        # Reset cache
        import app.security.api_keys as api_keys_module
        api_keys_module._api_keys = None
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        result = await verify_api_key_header(x_api_key="valid-key-123")
        assert result == "valid-key-123"
