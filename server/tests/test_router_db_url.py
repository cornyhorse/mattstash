"""Tests for app.routers.db_url module."""
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from mattstash.utils.exceptions import CredentialNotFoundError

from app.main import create_app


class TestDatabaseUrlRouter:
    """Test database URL builder endpoint."""
    
    def test_get_db_url_success(self, clean_env, monkeypatch):
        """Returns masked database URL."""
        monkeypatch.setenv("KDBX_PASSWORD", "test_pass")
        monkeypatch.setenv("MATTSTASH_API_KEY", "test-key")
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        import app.dependencies as deps
        deps._mattstash_instance = None
        
        with patch('app.dependencies.MattStash') as MockMattStash:
            mock_ms = MagicMock()
            MockMattStash.return_value = mock_ms
            
            with patch('app.routers.db_url.build_db_url') as mock_build:
                mock_build.return_value = "postgresql+psycopg://admin:secret123@localhost:5432/mydb"
                
                app = create_app()
                client = TestClient(app)
                
                response = client.get(
                    "/api/v1/db-url/postgres_cred",
                    headers={"X-API-Key": "test-key"}
                )
                
                assert response.status_code == 200
                data = response.json()
                assert data["url"] == "postgresql+psycopg://admin:*****@localhost:5432/mydb"
    
    def test_get_db_url_unmasked(self, clean_env, monkeypatch):
        """Returns unmasked URL when requested."""
        monkeypatch.setenv("KDBX_PASSWORD", "test_pass")
        monkeypatch.setenv("MATTSTASH_API_KEY", "test-key")
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        import app.dependencies as deps
        deps._mattstash_instance = None
        
        with patch('app.dependencies.MattStash') as MockMattStash:
            mock_ms = MagicMock()
            MockMattStash.return_value = mock_ms
            
            with patch('app.routers.db_url.build_db_url') as mock_build:
                mock_build.return_value = "postgresql+psycopg://admin:secret123@localhost:5432/mydb"
                
                app = create_app()
                client = TestClient(app)
                
                response = client.get(
                    "/api/v1/db-url/postgres_cred?mask_password=false",
                    headers={"X-API-Key": "test-key"}
                )
                
                assert response.status_code == 200
                data = response.json()
                assert data["url"] == "postgresql+psycopg://admin:secret123@localhost:5432/mydb"
    
    def test_get_db_url_with_database(self, clean_env, monkeypatch):
        """Includes database name in URL."""
        monkeypatch.setenv("KDBX_PASSWORD", "test_pass")
        monkeypatch.setenv("MATTSTASH_API_KEY", "test-key")
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        import app.dependencies as deps
        deps._mattstash_instance = None
        
        with patch('app.dependencies.MattStash') as MockMattStash:
            mock_ms = MagicMock()
            MockMattStash.return_value = mock_ms
            
            with patch('app.routers.db_url.build_db_url') as mock_build:
                mock_build.return_value = "postgresql+psycopg://admin:secret@localhost:5432/custom_db"
                
                app = create_app()
                client = TestClient(app)
                
                response = client.get(
                    "/api/v1/db-url/postgres_cred?database=custom_db",
                    headers={"X-API-Key": "test-key"}
                )
                
                assert response.status_code == 200
                # Verify build_db_url was called with database parameter
                mock_build.assert_called_once()
                call_kwargs = mock_build.call_args[1]
                assert call_kwargs.get('database') == 'custom_db'
    
    def test_get_db_url_custom_driver(self, clean_env, monkeypatch):
        """Uses custom driver."""
        monkeypatch.setenv("KDBX_PASSWORD", "test_pass")
        monkeypatch.setenv("MATTSTASH_API_KEY", "test-key")
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        import app.dependencies as deps
        deps._mattstash_instance = None
        
        with patch('app.dependencies.MattStash') as MockMattStash:
            mock_ms = MagicMock()
            MockMattStash.return_value = mock_ms
            
            with patch('app.routers.db_url.build_db_url') as mock_build:
                mock_build.return_value = "mysql+mysqldb://user:pass@host/db"
                
                app = create_app()
                client = TestClient(app)
                
                response = client.get(
                    "/api/v1/db-url/mysql_cred?driver=mysqldb",
                    headers={"X-API-Key": "test-key"}
                )
                
                assert response.status_code == 200
                # Verify build_db_url was called with custom driver
                call_kwargs = mock_build.call_args[1]
                assert call_kwargs.get('driver') == 'mysqldb'
    
    def test_get_db_url_not_found(self, clean_env, monkeypatch):
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
            MockMattStash.return_value = mock_ms
            
            with patch('app.routers.db_url.build_db_url') as mock_build:
                mock_build.side_effect = CredentialNotFoundError("Not found")
                
                app = create_app()
                client = TestClient(app)
                
                response = client.get(
                    "/api/v1/db-url/missing_cred",
                    headers={"X-API-Key": "test-key"}
                )
                
                assert response.status_code == 404
                assert "Credential not found" in response.json()["detail"]
    
    def test_get_db_url_no_api_key(self, clean_env, monkeypatch):
        """Returns 401 without API key."""
        monkeypatch.setenv("KDBX_PASSWORD", "test_pass")
        monkeypatch.setenv("MATTSTASH_API_KEY", "test-key")
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        app = create_app()
        client = TestClient(app)
        
        response = client.get("/api/v1/db-url/test_cred")
        
        assert response.status_code == 401
    
    def test_get_db_url_internal_error(self, clean_env, monkeypatch):
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
            MockMattStash.return_value = mock_ms
            
            with patch('app.routers.db_url.build_db_url') as mock_build:
                mock_build.side_effect = Exception("Builder error")
                
                app = create_app()
                client = TestClient(app)
                
                response = client.get(
                    "/api/v1/db-url/test_cred",
                    headers={"X-API-Key": "test-key"}
                )
                
                assert response.status_code == 500
                assert "Error building database URL" in response.json()["detail"]
    
    def test_get_db_url_mask_no_at_symbol(self, clean_env, monkeypatch):
        """Handles URL without @ symbol."""
        monkeypatch.setenv("KDBX_PASSWORD", "test_pass")
        monkeypatch.setenv("MATTSTASH_API_KEY", "test-key")
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        import app.dependencies as deps
        deps._mattstash_instance = None
        
        with patch('app.dependencies.MattStash') as MockMattStash:
            mock_ms = MagicMock()
            MockMattStash.return_value = mock_ms
            
            with patch('app.routers.db_url.build_db_url') as mock_build:
                # URL without credentials
                mock_build.return_value = "postgresql://localhost:5432/mydb"
                
                app = create_app()
                client = TestClient(app)
                
                response = client.get(
                    "/api/v1/db-url/test_cred",
                    headers={"X-API-Key": "test-key"}
                )
                
                assert response.status_code == 200
                # URL should remain unchanged (no masking needed)
                data = response.json()
                assert data["url"] == "postgresql://localhost:5432/mydb"
    
    def test_get_db_url_mask_no_colon_in_creds(self, clean_env, monkeypatch):
        """Handles creds without password."""
        monkeypatch.setenv("KDBX_PASSWORD", "test_pass")
        monkeypatch.setenv("MATTSTASH_API_KEY", "test-key")
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        import app.dependencies as deps
        deps._mattstash_instance = None
        
        with patch('app.dependencies.MattStash') as MockMattStash:
            mock_ms = MagicMock()
            MockMattStash.return_value = mock_ms
            
            with patch('app.routers.db_url.build_db_url') as mock_build:
                # URL with username but no password
                mock_build.return_value = "postgresql://admin@localhost:5432/mydb"
                
                app = create_app()
                client = TestClient(app)
                
                response = client.get(
                    "/api/v1/db-url/test_cred",
                    headers={"X-API-Key": "test-key"}
                )
                
                assert response.status_code == 200
                # URL should remain unchanged (no : to split on)
                data = response.json()
                assert data["url"] == "postgresql://admin@localhost:5432/mydb"
