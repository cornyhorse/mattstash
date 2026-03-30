"""Tests for credentials router helper functions."""
import pytest

from mattstash.models.credential import Credential

from app.routers.credentials import _normalize_credential, _validate_credential_name


class TestCredentialsHelpers:
    """Test credential router helper functions."""

    def test_normalize_credential_object_masked(self):
        """Test _normalize_credential with a Credential object, masked."""
        cred = Credential(
            credential_name="test_cred",
            username="admin",
            password="secret123",
            url="https://example.com",
            notes="Test notes",
            tags=[],
        )

        response = _normalize_credential("test_cred", cred, show_password=False)

        assert response.name == "test_cred"
        assert response.username == "admin"
        assert response.password == "*****"
        assert response.url == "https://example.com"
        assert response.notes == "Test notes"
        assert response.version is None

    def test_normalize_credential_object_unmasked(self):
        """Test _normalize_credential with a Credential object, unmasked."""
        cred = Credential(
            credential_name="test_cred",
            username="admin",
            password="secret123",
            url="https://example.com",
            notes="Test notes",
            tags=[],
        )

        response = _normalize_credential("test_cred", cred, show_password=True)

        assert response.name == "test_cred"
        assert response.username == "admin"
        assert response.password == "secret123"
        assert response.url == "https://example.com"
        assert response.notes == "Test notes"

    def test_normalize_credential_dict_masked(self):
        """Test _normalize_credential with a simple-secret dict, masked."""
        cred = {
            "name": "test_cred",
            "version": "0000000002",
            "value": "secret_value",
            "notes": "Some notes",
        }

        response = _normalize_credential("test_cred", cred, show_password=False)

        assert response.name == "test_cred"
        assert response.username is None
        assert response.password == "*****"
        assert response.url is None
        assert response.notes == "Some notes"
        assert response.version == "0000000002"

    def test_normalize_credential_dict_unmasked(self):
        """Test _normalize_credential with a simple-secret dict, unmasked."""
        cred = {
            "name": "test_cred",
            "version": "0000000001",
            "value": "secret_value",
            "notes": None,
        }

        response = _normalize_credential("test_cred", cred, show_password=True)

        assert response.name == "test_cred"
        assert response.password == "secret_value"
        assert response.version == "0000000001"

    def test_validate_credential_name_valid(self):
        """Valid names should not raise."""
        _validate_credential_name("my-cred_1.0")

    def test_validate_credential_name_empty(self):
        """Empty name should raise HTTPException."""
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            _validate_credential_name("")
        assert exc_info.value.status_code == 400

    def test_validate_credential_name_traversal(self):
        """Path-traversal characters should raise HTTPException."""
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            _validate_credential_name("../etc/passwd")
        assert exc_info.value.status_code == 400
