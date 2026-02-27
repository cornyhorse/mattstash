"""Tests for app.models.* modules."""
import pytest
from pydantic import ValidationError

from app.models.requests import CreateCredentialRequest
from app.models.responses import (
    CredentialListResponse,
    CredentialResponse,
    DatabaseUrlResponse,
    ErrorResponse,
    HealthResponse,
    VersionListResponse,
)


class TestResponseModels:
    """Test Pydantic response models."""
    
    def test_health_response_schema(self):
        """HealthResponse validates correctly."""
        data = {"status": "healthy", "version": "v1"}
        response = HealthResponse(**data)
        
        assert response.status == "healthy"
        assert response.version == "v1"
    
    def test_credential_response_schema(self):
        """CredentialResponse with all fields."""
        data = {
            "name": "test_cred",
            "username": "admin",
            "password": "*****",
            "url": "https://example.com",
            "notes": "Test notes",
            "version": "1"
        }
        response = CredentialResponse(**data)
        
        assert response.name == "test_cred"
        assert response.username == "admin"
        assert response.password == "*****"
        assert response.url == "https://example.com"
        assert response.notes == "Test notes"
        assert response.version == "1"
    
    def test_credential_response_optional_fields(self):
        """Optional fields can be None."""
        data = {
            "name": "minimal",
            "password": "secret"
        }
        response = CredentialResponse(**data)
        
        assert response.name == "minimal"
        assert response.password == "secret"
        assert response.username is None
        assert response.url is None
        assert response.notes is None
        assert response.version is None
    
    def test_credential_list_response_schema(self):
        """CredentialListResponse validates."""
        data = {
            "credentials": [
                {
                    "name": "cred1",
                    "password": "pass1",
                    "username": "user1",
                    "url": None,
                    "notes": None,
                    "version": None
                }
            ],
            "count": 1
        }
        response = CredentialListResponse(**data)
        
        assert response.count == 1
        assert len(response.credentials) == 1
        assert response.credentials[0].name == "cred1"
    
    def test_version_list_response_schema(self):
        """VersionListResponse validates."""
        data = {
            "name": "test_cred",
            "versions": ["1", "2", "3"],
            "latest": "3"
        }
        response = VersionListResponse(**data)
        
        assert response.name == "test_cred"
        assert len(response.versions) == 3
        assert response.latest == "3"
    
    def test_database_url_response_schema(self):
        """DatabaseUrlResponse validates."""
        data = {
            "url": "postgresql://user:pass@host:5432/db"
        }
        response = DatabaseUrlResponse(**data)
        
        assert response.url == "postgresql://user:pass@host:5432/db"
    
    def test_error_response_schema(self):
        """ErrorResponse validates."""
        data = {
            "detail": "An error occurred"
        }
        response = ErrorResponse(**data)
        
        assert response.detail == "An error occurred"


class TestRequestModels:
    """Test Pydantic request models."""
    
    def test_create_credential_request_simple(self):
        """Simple mode (value only)."""
        data = {
            "value": "my-secret-value"
        }
        request = CreateCredentialRequest(**data)
        
        assert request.value == "my-secret-value"
        assert request.username is None
        assert request.password is None
        assert request.url is None
        assert request.notes is None
    
    def test_create_credential_request_full(self):
        """Full mode (all fields)."""
        data = {
            "username": "admin",
            "password": "secret123",
            "url": "postgres.example.com:5432",
            "notes": "Production database"
        }
        request = CreateCredentialRequest(**data)
        
        assert request.value is None
        assert request.username == "admin"
        assert request.password == "secret123"
        assert request.url == "postgres.example.com:5432"
        assert request.notes == "Production database"
