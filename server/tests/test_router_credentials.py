"""Tests for app.routers.credentials module."""
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from mattstash.utils.exceptions import CredentialNotFoundError

from app.main import create_app
from app.routers.credentials import credential_to_response, mask_password


class TestCredentialsRouter:
    """Test credentials CRUD endpoints."""
    
    # Helper function tests
    
    def test_mask_password(self):
        """Masks any password to *****."""
        assert mask_password("secret123") == "*****"
        assert mask_password("") == "*****"
        assert mask_password("very_long_password_123") == "*****"
    
    def test_credential_to_response_masked(self):
        """Converts dict with masked password."""
        cred_dict = {
            "username": "admin",
            "password": "secret123",
            "url": "https://example.com",
            "notes": "Test notes",
            "version": 2
        }
        
        result = credential_to_response("test_cred", cred_dict, show_password=False)
        
        assert result.name == "test_cred"
        assert result.username == "admin"
        assert result.password == "*****"
        assert result.url == "https://example.com"
        assert result.notes == "Test notes"
        assert result.version == 2
    
    def test_credential_to_response_shown(self):
        """Converts dict with actual password."""
        cred_dict = {
            "username": "user1",
            "password": "actual_password",
            "url": None,
            "notes": None
        }
        
        result = credential_to_response("cred1", cred_dict, show_password=True)
        
        assert result.name == "cred1"
        assert result.password == "actual_password"
    
    def test_credential_to_response_optional_fields(self):
        """Handles missing optional fields."""
        cred_dict = {
            "password": "pass123"
        }
        
        result = credential_to_response("minimal", cred_dict)
        
        assert result.name == "minimal"
        assert result.username is None
        assert result.url is None
        assert result.notes is None
    
    # GET /credentials/{name} tests
    
    def test_get_credential_success(self, clean_env, monkeypatch):
        """Returns credential with masked password."""
        monkeypatch.setenv("KDBX_PASSWORD", "test_pass")
        monkeypatch.setenv("MATTSTASH_API_KEY", "test-key")
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        # Reset dependency cache
        import app.dependencies as deps
        deps._mattstash_instance = None
        
        with patch('app.dependencies.MattStash') as MockMattStash:
            mock_ms = MagicMock()
            mock_ms.get.return_value = {
                "username": "admin",
                "password": "secret123",
                "url": "https://example.com",
                "notes": "Test"
            }
            MockMattStash.return_value = mock_ms
            
            app = create_app()
            client = TestClient(app)
            
            response = client.get(
                "/api/v1/credentials/test_cred",
                headers={"X-API-Key": "test-key"}
            )
            
            assert response.status_code == 200
            data = response.json()
            assert data["name"] == "test_cred"
            assert data["username"] == "admin"
            assert data["password"] == "*****"
            assert data["url"] == "https://example.com"
    
    def test_get_credential_show_password(self, clean_env, monkeypatch):
        """Returns credential with actual password."""
        monkeypatch.setenv("KDBX_PASSWORD", "test_pass")
        monkeypatch.setenv("MATTSTASH_API_KEY", "test-key")
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        import app.dependencies as deps
        deps._mattstash_instance = None
        
        with patch('app.dependencies.MattStash') as MockMattStash:
            mock_ms = MagicMock()
            mock_ms.get.return_value = {
                "username": "user1",
                "password": "actual_password",
                "url": None,
                "notes": None
            }
            MockMattStash.return_value = mock_ms
            
            app = create_app()
            client = TestClient(app)
            
            response = client.get(
                "/api/v1/credentials/test_cred?show_password=true",
                headers={"X-API-Key": "test-key"}
            )
            
            assert response.status_code == 200
            data = response.json()
            assert data["password"] == "actual_password"
    
    def test_get_credential_with_version(self, clean_env, monkeypatch):
        """Returns specific version."""
        monkeypatch.setenv("KDBX_PASSWORD", "test_pass")
        monkeypatch.setenv("MATTSTASH_API_KEY", "test-key")
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        import app.dependencies as deps
        deps._mattstash_instance = None
        
        with patch('app.dependencies.MattStash') as MockMattStash:
            mock_ms = MagicMock()
            mock_ms.get_version.return_value = {
                "username": "old_user",
                "password": "old_pass",
                "url": None,
                "notes": None,
                "version": 2
            }
            MockMattStash.return_value = mock_ms
            
            app = create_app()
            client = TestClient(app)
            
            response = client.get(
                "/api/v1/credentials/test_cred?version=2",
                headers={"X-API-Key": "test-key"}
            )
            
            assert response.status_code == 200
            mock_ms.get_version.assert_called_once_with("test_cred", 2)
    
    def test_get_credential_not_found(self, clean_env, monkeypatch):
        """Returns 404 for missing credential."""
        monkeypatch.setenv("KDBX_PASSWORD", "test_pass")
        monkeypatch.setenv("MATTSTASH_API_KEY", "test-key")
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        import app.dependencies as deps
        deps._mattstash_instance = None
        
        with patch('app.dependencies.MattStash') as MockMattStash:
            mock_ms = MagicMock()
            mock_ms.get.side_effect = CredentialNotFoundError("Not found")
            MockMattStash.return_value = mock_ms
            
            app = create_app()
            client = TestClient(app)
            
            response = client.get(
                "/api/v1/credentials/missing_cred",
                headers={"X-API-Key": "test-key"}
            )
            
            assert response.status_code == 404
            assert "Credential not found" in response.json()["detail"]
    
    def test_get_credential_no_api_key(self, clean_env, monkeypatch):
        """Returns 401 without API key."""
        monkeypatch.setenv("KDBX_PASSWORD", "test_pass")
        monkeypatch.setenv("MATTSTASH_API_KEY", "test-key")
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        app = create_app()
        client = TestClient(app)
        
        response = client.get("/api/v1/credentials/test_cred")
        
        assert response.status_code == 401
        assert "Missing API key" in response.json()["detail"]
    
    def test_get_credential_invalid_api_key(self, clean_env, monkeypatch):
        """Returns 401 with wrong key."""
        monkeypatch.setenv("KDBX_PASSWORD", "test_pass")
        monkeypatch.setenv("MATTSTASH_API_KEY", "correct-key")
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        # Reset API keys cache
        import app.security.api_keys as api_keys_module
        api_keys_module._api_keys = None
        
        app = create_app()
        client = TestClient(app)
        
        response = client.get(
            "/api/v1/credentials/test_cred",
            headers={"X-API-Key": "wrong-key"}
        )
        
        assert response.status_code == 401
        assert "Invalid API key" in response.json()["detail"]
    
    def test_get_credential_internal_error(self, clean_env, monkeypatch):
        """Returns 500 on unexpected error."""
        monkeypatch.setenv("KDBX_PASSWORD", "test_pass")
        monkeypatch.setenv("MATTSTASH_API_KEY", "test-key")
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        import app.dependencies as deps
        deps._mattstash_instance = None
        
        with patch('app.dependencies.MattStash') as MockMattStash:
            mock_ms = MagicMock()
            mock_ms.get.side_effect = Exception("Database error")
            MockMattStash.return_value = mock_ms
            
            app = create_app()
            client = TestClient(app)
            
            response = client.get(
                "/api/v1/credentials/test_cred",
                headers={"X-API-Key": "test-key"}
            )
            
            assert response.status_code == 500
            assert "Error retrieving credential" in response.json()["detail"]
    
    # GET /credentials tests
    
    def test_list_credentials_success(self, clean_env, monkeypatch):
        """Lists all credentials."""
        monkeypatch.setenv("KDBX_PASSWORD", "test_pass")
        monkeypatch.setenv("MATTSTASH_API_KEY", "test-key")
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        import app.dependencies as deps
        deps._mattstash_instance = None
        
        with patch('app.dependencies.MattStash') as MockMattStash:
            mock_ms = MagicMock()
            mock_ms.list.return_value = ["cred1", "cred2"]
            mock_ms.get.side_effect = [
                {"username": "user1", "password": "pass1", "url": None, "notes": None},
                {"username": "user2", "password": "pass2", "url": None, "notes": None}
            ]
            MockMattStash.return_value = mock_ms
            
            app = create_app()
            client = TestClient(app)
            
            response = client.get(
                "/api/v1/credentials",
                headers={"X-API-Key": "test-key"}
            )
            
            assert response.status_code == 200
            data = response.json()
            assert data["count"] == 2
            assert len(data["credentials"]) == 2
            assert data["credentials"][0]["name"] == "cred1"
            assert data["credentials"][1]["name"] == "cred2"
    
    def test_list_credentials_with_prefix(self, clean_env, monkeypatch):
        """Filters by prefix."""
        monkeypatch.setenv("KDBX_PASSWORD", "test_pass")
        monkeypatch.setenv("MATTSTASH_API_KEY", "test-key")
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        import app.dependencies as deps
        deps._mattstash_instance = None
        
        with patch('app.dependencies.MattStash') as MockMattStash:
            mock_ms = MagicMock()
            mock_ms.list.return_value = ["prod_db", "prod_api", "dev_db"]
            mock_ms.get.side_effect = [
                {"username": "user1", "password": "pass1", "url": None, "notes": None},
                {"username": "user2", "password": "pass2", "url": None, "notes": None}
            ]
            MockMattStash.return_value = mock_ms
            
            app = create_app()
            client = TestClient(app)
            
            response = client.get(
                "/api/v1/credentials?prefix=prod",
                headers={"X-API-Key": "test-key"}
            )
            
            assert response.status_code == 200
            data = response.json()
            assert data["count"] == 2
            # Only prod_db and prod_api should be fetched
            assert mock_ms.get.call_count == 2
    
    def test_list_credentials_empty(self, clean_env, monkeypatch):
        """Returns empty list."""
        monkeypatch.setenv("KDBX_PASSWORD", "test_pass")
        monkeypatch.setenv("MATTSTASH_API_KEY", "test-key")
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        import app.dependencies as deps
        deps._mattstash_instance = None
        
        with patch('app.dependencies.MattStash') as MockMattStash:
            mock_ms = MagicMock()
            mock_ms.list.return_value = []
            MockMattStash.return_value = mock_ms
            
            app = create_app()
            client = TestClient(app)
            
            response = client.get(
                "/api/v1/credentials",
                headers={"X-API-Key": "test-key"}
            )
            
            assert response.status_code == 200
            data = response.json()
            assert data["count"] == 0
            assert data["credentials"] == []
    
    def test_list_credentials_show_password(self, clean_env, monkeypatch):
        """Shows actual passwords."""
        monkeypatch.setenv("KDBX_PASSWORD", "test_pass")
        monkeypatch.setenv("MATTSTASH_API_KEY", "test-key")
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        import app.dependencies as deps
        deps._mattstash_instance = None
        
        with patch('app.dependencies.MattStash') as MockMattStash:
            mock_ms = MagicMock()
            mock_ms.list.return_value = ["cred1"]
            mock_ms.get.return_value = {"username": "user1", "password": "actual_pass", "url": None, "notes": None}
            MockMattStash.return_value = mock_ms
            
            app = create_app()
            client = TestClient(app)
            
            response = client.get(
                "/api/v1/credentials?show_password=true",
                headers={"X-API-Key": "test-key"}
            )
            
            assert response.status_code == 200
            data = response.json()
            assert data["credentials"][0]["password"] == "actual_pass"
    
    def test_list_credentials_no_api_key(self, clean_env, monkeypatch):
        """Returns 401 without API key."""
        monkeypatch.setenv("KDBX_PASSWORD", "test_pass")
        monkeypatch.setenv("MATTSTASH_API_KEY", "test-key")
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        app = create_app()
        client = TestClient(app)
        
        response = client.get("/api/v1/credentials")
        
        assert response.status_code == 401
    
    def test_list_credentials_internal_error(self, clean_env, monkeypatch):
        """Returns 500 on unexpected error."""
        monkeypatch.setenv("KDBX_PASSWORD", "test_pass")
        monkeypatch.setenv("MATTSTASH_API_KEY", "test-key")
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        import app.dependencies as deps
        deps._mattstash_instance = None
        
        with patch('app.dependencies.MattStash') as MockMattStash:
            mock_ms = MagicMock()
            mock_ms.list.side_effect = Exception("Database error")
            MockMattStash.return_value = mock_ms
            
            app = create_app()
            client = TestClient(app)
            
            response = client.get(
                "/api/v1/credentials",
                headers={"X-API-Key": "test-key"}
            )
            
            assert response.status_code == 500
            assert "Error listing credentials" in response.json()["detail"]
    
    def test_list_credentials_skips_deleted(self, clean_env, monkeypatch):
        """Handles race condition gracefully."""
        monkeypatch.setenv("KDBX_PASSWORD", "test_pass")
        monkeypatch.setenv("MATTSTASH_API_KEY", "test-key")
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        import app.dependencies as deps
        deps._mattstash_instance = None
        
        with patch('app.dependencies.MattStash') as MockMattStash:
            mock_ms = MagicMock()
            mock_ms.list.return_value = ["cred1", "cred2", "cred3"]
            # cred2 was deleted between list and get
            mock_ms.get.side_effect = [
                {"username": "user1", "password": "pass1", "url": None, "notes": None},
                CredentialNotFoundError("Not found"),
                {"username": "user3", "password": "pass3", "url": None, "notes": None}
            ]
            MockMattStash.return_value = mock_ms
            
            app = create_app()
            client = TestClient(app)
            
            response = client.get(
                "/api/v1/credentials",
                headers={"X-API-Key": "test-key"}
            )
            
            assert response.status_code == 200
            data = response.json()
            assert data["count"] == 2  # Only cred1 and cred3
            assert len(data["credentials"]) == 2
    
    # GET /credentials/{name}/versions tests
    
    def test_list_versions_success(self, clean_env, monkeypatch):
        """Lists all versions."""
        monkeypatch.setenv("KDBX_PASSWORD", "test_pass")
        monkeypatch.setenv("MATTSTASH_API_KEY", "test-key")
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        import app.dependencies as deps
        deps._mattstash_instance = None
        
        with patch('app.dependencies.MattStash') as MockMattStash:
            mock_ms = MagicMock()
            mock_ms.list_versions.return_value = [
                {"version": 1, "username": "user1", "password": "pass1"},
                {"version": 2, "username": "user2", "password": "pass2"}
            ]
            MockMattStash.return_value = mock_ms
            
            app = create_app()
            client = TestClient(app)
            
            response = client.get(
                "/api/v1/credentials/test_cred/versions",
                headers={"X-API-Key": "test-key"}
            )
            
            assert response.status_code == 200
            data = response.json()
            assert data["name"] == "test_cred"
            assert len(data["versions"]) == 2
            assert data["latest"]["version"] == 2
    
    def test_list_versions_not_found(self, clean_env, monkeypatch):
        """Returns 404 for missing credential."""
        monkeypatch.setenv("KDBX_PASSWORD", "test_pass")
        monkeypatch.setenv("MATTSTASH_API_KEY", "test-key")
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        import app.dependencies as deps
        deps._mattstash_instance = None
        
        with patch('app.dependencies.MattStash') as MockMattStash:
            mock_ms = MagicMock()
            mock_ms.list_versions.side_effect = CredentialNotFoundError("Not found")
            MockMattStash.return_value = mock_ms
            
            app = create_app()
            client = TestClient(app)
            
            response = client.get(
                "/api/v1/credentials/missing/versions",
                headers={"X-API-Key": "test-key"}
            )
            
            assert response.status_code == 404
    
    def test_list_versions_empty_versions(self, clean_env, monkeypatch):
        """Returns 404 if no versions."""
        monkeypatch.setenv("KDBX_PASSWORD", "test_pass")
        monkeypatch.setenv("MATTSTASH_API_KEY", "test-key")
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        import app.dependencies as deps
        deps._mattstash_instance = None
        
        with patch('app.dependencies.MattStash') as MockMattStash:
            mock_ms = MagicMock()
            mock_ms.list_versions.return_value = []
            MockMattStash.return_value = mock_ms
            
            app = create_app()
            client = TestClient(app)
            
            response = client.get(
                "/api/v1/credentials/test_cred/versions",
                headers={"X-API-Key": "test-key"}
            )
            
            assert response.status_code == 404
    
    def test_list_versions_internal_error(self, clean_env, monkeypatch):
        """Returns 500 on unexpected error."""
        monkeypatch.setenv("KDBX_PASSWORD", "test_pass")
        monkeypatch.setenv("MATTSTASH_API_KEY", "test-key")
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        import app.dependencies as deps
        deps._mattstash_instance = None
        
        with patch('app.dependencies.MattStash') as MockMattStash:
            mock_ms = MagicMock()
            mock_ms.list_versions.side_effect = Exception("Database error")
            MockMattStash.return_value = mock_ms
            
            app = create_app()
            client = TestClient(app)
            
            response = client.get(
                "/api/v1/credentials/test_cred/versions",
                headers={"X-API-Key": "test-key"}
            )
            
            assert response.status_code == 500
            assert "Error listing versions" in response.json()["detail"]
