"""Tests for the admin reload endpoint."""
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient


class TestAdminReloadEndpoint:
    """Tests for POST /api/v1/admin/reload."""

    def test_reload_success(self, test_app, mock_mattstash):
        """Reload returns 200 with status 'reloaded' when successful."""
        from app.dependencies import get_mattstash, verify_api_key_header

        mock_mattstash.reload.return_value = True
        test_app.dependency_overrides[get_mattstash] = lambda: mock_mattstash
        test_app.dependency_overrides[verify_api_key_header] = lambda: "test-api-key"

        with patch("app.routers.admin.reload_mattstash", return_value=True):
            client = TestClient(test_app)
            response = client.post(
                "/api/v1/admin/reload",
                headers={"X-API-Key": "test-api-key"},
            )

        assert response.status_code == 200
        assert response.json()["status"] == "reloaded"
        test_app.dependency_overrides.clear()

    def test_reload_no_instance(self, test_app):
        """Reload returns 200 with status 'no_change' when no instance exists."""
        from app.dependencies import verify_api_key_header

        test_app.dependency_overrides[verify_api_key_header] = lambda: "test-api-key"

        with patch("app.routers.admin.reload_mattstash", return_value=False):
            client = TestClient(test_app)
            response = client.post(
                "/api/v1/admin/reload",
                headers={"X-API-Key": "test-api-key"},
            )

        assert response.status_code == 200
        assert response.json()["status"] == "no_change"
        test_app.dependency_overrides.clear()

    def test_reload_requires_api_key(self, test_app):
        """Reload endpoint requires authentication."""
        client = TestClient(test_app)
        response = client.post("/api/v1/admin/reload")

        assert response.status_code == 401


class TestReloadDependencyFunctions:
    """Tests for reload_mattstash and reload_mattstash_if_changed in dependencies."""

    def test_reload_mattstash_calls_instance_reload(self):
        """reload_mattstash delegates to the singleton instance."""
        import app.dependencies as deps

        mock_instance = MagicMock()
        mock_instance.reload.return_value = True
        deps._mattstash_instance = mock_instance

        result = deps.reload_mattstash()
        assert result is True
        mock_instance.reload.assert_called_once()

    def test_reload_mattstash_no_instance(self):
        """reload_mattstash returns False when no instance exists."""
        import app.dependencies as deps

        deps._mattstash_instance = None
        result = deps.reload_mattstash()
        assert result is False

    def test_reload_if_changed_calls_instance(self):
        """reload_mattstash_if_changed delegates to the singleton."""
        import app.dependencies as deps

        mock_instance = MagicMock()
        mock_instance.reload_if_changed.return_value = True
        deps._mattstash_instance = mock_instance

        result = deps.reload_mattstash_if_changed()
        assert result is True
        mock_instance.reload_if_changed.assert_called_once()

    def test_reload_if_changed_no_instance(self):
        """reload_mattstash_if_changed returns False when no instance exists."""
        import app.dependencies as deps

        deps._mattstash_instance = None
        result = deps.reload_mattstash_if_changed()
        assert result is False
