"""Shared test fixtures for MattStash Server tests."""
import os
import tempfile
from pathlib import Path
from typing import Generator
from unittest.mock import MagicMock, Mock

import pytest
from fastapi.testclient import TestClient

from mattstash import MattStash


@pytest.fixture
def temp_password_file() -> Generator[Path, None, None]:
    """Create a temporary password file."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write("test_password_123")
        temp_path = Path(f.name)
    
    yield temp_path
    
    # Cleanup
    if temp_path.exists():
        temp_path.unlink()


@pytest.fixture
def temp_api_keys_file() -> Generator[Path, None, None]:
    """Create a temporary API keys file."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write("# API Keys\n")
        f.write("test-key-1\n")
        f.write("test-key-2\n")
        f.write("# Another comment\n")
        f.write("test-key-3\n")
        temp_path = Path(f.name)
    
    yield temp_path
    
    # Cleanup
    if temp_path.exists():
        temp_path.unlink()


@pytest.fixture
def mock_mattstash() -> Mock:
    """Create a mock MattStash instance."""
    mock = MagicMock(spec=MattStash)
    
    # Default behavior for common methods
    mock.get_credential.return_value = {
        'name': 'test_cred',
        'username': 'testuser',
        'password': 'testpass',
        'url': 'https://example.com',
        'notes': 'Test notes'
    }
    
    mock.list_credentials.return_value = [
        {
            'name': 'cred1',
            'username': 'user1',
            'password': 'pass1',
            'url': 'https://example1.com',
            'notes': ''
        },
        {
            'name': 'cred2',
            'username': 'user2',
            'password': 'pass2',
            'url': 'https://example2.com',
            'notes': 'Notes'
        }
    ]
    
    mock.list_versions.return_value = [
        {
            'version': 3,
            'username': 'user_v3',
            'password': 'pass_v3',
            'url': 'https://v3.example.com',
            'notes': 'Version 3'
        },
        {
            'version': 2,
            'username': 'user_v2',
            'password': 'pass_v2',
            'url': 'https://v2.example.com',
            'notes': 'Version 2'
        }
    ]
    
    return mock


@pytest.fixture
def valid_api_key() -> str:
    """Return a valid test API key."""
    return "test-api-key-valid"


@pytest.fixture
def test_credential() -> dict:
    """Return a test credential dictionary."""
    return {
        'name': 'test_app',
        'username': 'admin',
        'password': 'secure_password_123',
        'url': 'https://test.example.com',
        'notes': 'Test application credentials'
    }


@pytest.fixture(autouse=True)
def reset_caches():
    """Auto-reset all module caches before each test."""
    import app.dependencies as deps
    import app.security.api_keys as api_keys_module
    
    # Reset before test
    deps._mattstash_instance = None
    api_keys_module._api_keys = None
    
    yield
    
    # Reset after test
    deps._mattstash_instance = None
    api_keys_module._api_keys = None


@pytest.fixture
def clean_env(monkeypatch) -> None:
    """Clean environment variables before each test."""
    env_vars = [
        'MATTSTASH_DB_PATH',
        'KDBX_PASSWORD',
        'KDBX_PASSWORD_FILE',
        'MATTSTASH_HOST',
        'MATTSTASH_PORT',
        'MATTSTASH_LOG_LEVEL',
        'MATTSTASH_API_KEY',
        'MATTSTASH_API_KEYS_FILE',
        'MATTSTASH_RATE_LIMIT'
    ]
    
    for var in env_vars:
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def test_app(clean_env, monkeypatch):
    """Create a test app with minimal config."""
    monkeypatch.setenv("KDBX_PASSWORD", "test_password")
    monkeypatch.setenv("MATTSTASH_API_KEY", "test-api-key")
    
    # Force config reload
    from importlib import reload
    import app.config as config_module
    reload(config_module)
    
    from app.main import create_app
    return create_app()


@pytest.fixture
def test_client(test_app):
    """Create a TestClient from the test app."""
    from fastapi.testclient import TestClient
    return TestClient(test_app)


@pytest.fixture
def reset_config_cache():
    """Reset config singleton state between tests."""
    # Import here to avoid circular imports
    from app.config import Config
    from app.security.api_keys import _api_keys
    from app.dependencies import _mattstash_instance
    
    # Reset cached values
    yield
    
    # Cleanup is handled by test isolation


@pytest.fixture
def test_client_factory(monkeypatch):
    """Factory to create TestClient with custom config."""
    def _create_client(mock_mattstash_instance=None, api_keys=None):
        # Reset the dependency cache
        import app.dependencies as deps
        deps._mattstash_instance = mock_mattstash_instance
        
        # Reset API keys cache
        import app.security.api_keys as api_keys_module
        api_keys_module._api_keys = api_keys
        
        # Set required environment variables
        monkeypatch.setenv("KDBX_PASSWORD", "test_password")
        monkeypatch.setenv("MATTSTASH_API_KEY", "test-api-key-valid")
        
        # Import app after setting env vars
        from app.main import create_app
        app = create_app()
        
        return TestClient(app)
    
    return _create_client
