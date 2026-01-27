"""Tests for credentials router helper functions."""
import pytest

from app.routers.credentials import mask_password, credential_to_response


class TestCredentialsHelpers:
    """Test credential router helper functions."""
    
    def test_mask_password(self):
        """Test password masking."""
        assert mask_password("secret123") == "*****"
        assert mask_password("") == "*****"
    
    def test_credential_to_response_masked(self):
        """Test credential to response conversion with masked password."""
        cred = {
            "username": "admin",
            "password": "secret123",
            "url": "https://example.com",
            "notes": "Test notes",
            "version": "2"
        }
        
        response = credential_to_response("test_cred", cred, show_password=False)
        
        assert response.name == "test_cred"
        assert response.username == "admin"
        assert response.password == "*****"
        assert response.url == "https://example.com"
        assert response.notes == "Test notes"
        assert response.version == "2"
    
    def test_credential_to_response_unmasked(self):
        """Test credential to response conversion with unmasked password."""
        cred = {
            "username": "admin",
            "password": "secret123",
            "url": "https://example.com",
            "notes": "Test notes",
            "version": None
        }
        
        response = credential_to_response("test_cred", cred, show_password=True)
        
        assert response.name == "test_cred"
        assert response.username == "admin"
        assert response.password == "secret123"  # Not masked
        assert response.url == "https://example.com"
        assert response.notes == "Test notes"
        assert response.version is None
