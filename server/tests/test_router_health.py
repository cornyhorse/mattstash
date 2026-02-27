"""Tests for app.routers.health module."""
from fastapi.testclient import TestClient

from app.main import create_app


class TestHealthRouter:
    """Test health check endpoint."""
    
    def test_health_check_success(self, clean_env, monkeypatch):
        """Returns 200 with healthy status."""
        # Set required env vars
        monkeypatch.setenv("KDBX_PASSWORD", "test_pass")
        monkeypatch.setenv("MATTSTASH_API_KEY", "test-key")
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        app = create_app()
        client = TestClient(app)
        
        response = client.get("/api/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["version"] == "v1"
    
    def test_health_check_no_auth_required(self, clean_env, monkeypatch):
        """No API key required."""
        monkeypatch.setenv("KDBX_PASSWORD", "test_pass")
        monkeypatch.setenv("MATTSTASH_API_KEY", "test-key")
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        app = create_app()
        client = TestClient(app)
        
        # Request without X-API-Key header should succeed
        response = client.get("/api/health")
        
        assert response.status_code == 200
    
    def test_health_check_response_schema(self, clean_env, monkeypatch):
        """Response matches HealthResponse model."""
        monkeypatch.setenv("KDBX_PASSWORD", "test_pass")
        monkeypatch.setenv("MATTSTASH_API_KEY", "test-key")
        
        from importlib import reload
        import app.config as config_module
        reload(config_module)
        
        app = create_app()
        client = TestClient(app)
        
        response = client.get("/api/health")
        data = response.json()
        
        # Verify schema
        assert "status" in data
        assert "version" in data
        assert isinstance(data["status"], str)
        assert isinstance(data["version"], str)
