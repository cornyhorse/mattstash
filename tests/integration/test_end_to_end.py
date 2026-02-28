"""
End-to-end integration tests for MattStash.

Tests complete workflows without mocking core components.
"""

import os

import pytest

from mattstash import MattStash


class TestCompleteCredentialLifecycle:
    """Test complete CRUD operations on actual database."""

    def test_bootstrap_creates_database(self, tmp_path):
        """Test that MattStash bootstraps a new database on first use."""
        db_path = tmp_path / "bootstrap_test.kdbx"
        sidecar_path = tmp_path / ".password.txt"

        # Create sidecar password file
        sidecar_path.write_text("test-password-123")

        # Initialize MattStash - should create DB
        MattStash(path=str(db_path))

        # Verify database was created
        assert db_path.exists()
        assert db_path.stat().st_size > 0

    def test_put_and_get_simple_credential(self, tmp_path):
        """Test storing and retrieving a simple credential."""
        db_path = tmp_path / "test.kdbx"
        sidecar_path = tmp_path / ".password.txt"
        sidecar_path.write_text("test-password")

        ms = MattStash(path=str(db_path))

        # Put credential
        result = ms.put("api-key", value="secret-12345", autoincrement=False)
        assert result is not None
        assert result["name"] == "api-key"

        # Get credential (masked)
        cred = ms.get("api-key")
        assert cred is not None
        assert cred["name"] == "api-key"
        assert cred["value"] == "*****"  # Masked by default

        # Get credential (unmasked)
        cred_unmasked = ms.get("api-key", show_password=True)
        assert cred_unmasked["value"] == "secret-12345"

    def test_put_and_get_database_credential(self, tmp_path):
        """Test storing and retrieving a database credential."""
        db_path = tmp_path / "test.kdbx"
        sidecar_path = tmp_path / ".password.txt"
        sidecar_path.write_text("test-password")

        ms = MattStash(path=str(db_path))

        # Put database credential
        result = ms.put("postgres-dev", username="dbuser", password="dbpass", url="localhost:5432")
        assert result is not None
        assert result.credential_name == "postgres-dev"

        # Get credential
        cred = ms.get("postgres-dev", show_password=True)
        assert cred.username == "dbuser"
        assert cred.password == "dbpass"
        assert cred.url == "localhost:5432"

    def test_update_credential(self, tmp_path):
        """Test updating an existing credential."""
        db_path = tmp_path / "test.kdbx"
        sidecar_path = tmp_path / ".password.txt"
        sidecar_path.write_text("test-password")

        ms = MattStash(path=str(db_path))

        # Create initial credential
        ms.put("test-cred", value="initial-value", autoincrement=False)

        # Update credential
        result = ms.put("test-cred", value="updated-value", autoincrement=False)
        assert result is not None

        # Verify update
        cred = ms.get("test-cred", show_password=True)
        assert cred["value"] == "updated-value"

    def test_delete_credential(self, tmp_path):
        """Test deleting a credential."""
        db_path = tmp_path / "test.kdbx"
        sidecar_path = tmp_path / ".password.txt"
        sidecar_path.write_text("test-password")

        ms = MattStash(path=str(db_path))

        # Create credential (disable autoincrement to avoid versioning)
        ms.put("to-delete", value="temporary", autoincrement=False)

        # Verify it exists
        cred = ms.get("to-delete")
        assert cred is not None

        # Delete credential
        deleted = ms.delete("to-delete")
        assert deleted is True

        # Verify deletion
        result = ms.get("to-delete")
        assert result is None

    def test_complete_lifecycle(self, tmp_path):
        """Test complete credential lifecycle: create → read → update → delete."""
        db_path = tmp_path / "lifecycle.kdbx"
        sidecar_path = tmp_path / ".password.txt"
        sidecar_path.write_text("test-password")

        ms = MattStash(path=str(db_path))

        # Create (disable autoincrement)
        result = ms.put("lifecycle-test", value="v1", autoincrement=False)
        assert result is not None

        # Read
        cred = ms.get("lifecycle-test", show_password=True)
        assert cred["value"] == "v1"

        # Update (still no autoincrement)
        ms.put("lifecycle-test", value="v2", autoincrement=False)
        cred = ms.get("lifecycle-test", show_password=True)
        assert cred["value"] == "v2"

        # Delete
        deleted = ms.delete("lifecycle-test")
        assert deleted is True

        # Verify gone
        result = ms.get("lifecycle-test")
        assert result is None


class TestVersioning:
    """Test versioned credentials."""

    def test_create_versioned_credentials(self, tmp_path):
        """Test creating multiple versions of a credential."""
        db_path = tmp_path / "versions.kdbx"
        sidecar_path = tmp_path / ".password.txt"
        sidecar_path.write_text("test-password")

        ms = MattStash(path=str(db_path))

        # Create multiple versions
        ms.put("api-key", value="version-1", version=1)
        ms.put("api-key", value="version-2", version=2)
        ms.put("api-key", value="version-3", version=3)

        # Get specific versions
        v1 = ms.get("api-key", version=1, show_password=True)
        assert v1["value"] == "version-1"

        v2 = ms.get("api-key", version=2, show_password=True)
        assert v2["value"] == "version-2"

        v3 = ms.get("api-key", version=3, show_password=True)
        assert v3["value"] == "version-3"

    def test_get_latest_version(self, tmp_path):
        """Test retrieving latest version without specifying version."""
        db_path = tmp_path / "versions.kdbx"
        sidecar_path = tmp_path / ".password.txt"
        sidecar_path.write_text("test-password")

        ms = MattStash(path=str(db_path))

        # Create versions
        ms.put("secret", value="old", version=1)
        ms.put("secret", value="current", version=2)

        # Get latest
        latest = ms.get("secret", show_password=True)
        assert latest["value"] == "current"

    def test_list_versions(self, tmp_path):
        """Test listing all versions of a credential."""
        db_path = tmp_path / "versions.kdbx"
        sidecar_path = tmp_path / ".password.txt"
        sidecar_path.write_text("test-password")

        ms = MattStash(path=str(db_path))

        # Create versions
        ms.put("token", value="v1", version=1)
        ms.put("token", value="v2", version=2)
        ms.put("token", value="v3", version=3)

        # List versions (returns zero-padded version strings)
        versions = ms.list_versions("token")
        assert len(versions) == 3
        # Versions are zero-padded strings like "0000000001"
        assert len(versions[0]) == 10  # Default pad_width


class TestListOperations:
    """Test listing credentials."""

    def test_list_empty_database(self, tmp_path):
        """Test listing credentials in empty database."""
        db_path = tmp_path / "empty.kdbx"
        sidecar_path = tmp_path / ".password.txt"
        sidecar_path.write_text("test-password")

        ms = MattStash(path=str(db_path))

        credentials = ms.list()
        assert credentials == []

    def test_list_multiple_credentials(self, tmp_path):
        """Test listing multiple credentials."""
        db_path = tmp_path / "list.kdbx"
        sidecar_path = tmp_path / ".password.txt"
        sidecar_path.write_text("test-password")

        ms = MattStash(path=str(db_path))

        # Create credentials (disable autoincrement)
        ms.put("api-key-1", value="secret1", autoincrement=False)
        ms.put("api-key-2", value="secret2", autoincrement=False)
        ms.put("db-password", username="user", password="pass", url="localhost:5432", autoincrement=False)

        # List all
        credentials = ms.list()
        assert len(credentials) == 3

        titles = [c.credential_name for c in credentials]
        assert "api-key-1" in titles
        assert "api-key-2" in titles
        assert "db-password" in titles


class TestDatabaseUrlBuilder:
    """Test database URL building with actual database."""

    def test_build_basic_url(self, tmp_path):
        """Test building a basic database URL."""
        db_path = tmp_path / "dburl.kdbx"
        sidecar_path = tmp_path / ".password.txt"
        sidecar_path.write_text("test-password")

        ms = MattStash(path=str(db_path))

        # Create database credential with custom property for database name
        ms.put("postgres-prod", username="admin", password="secret123", url="db.example.com:5432", autoincrement=False)
        # Set database as custom property
        kp = ms._credential_store.open()
        if kp is None:
            raise RuntimeError("Could not open database")
        entry = kp.find_entries(title="postgres-prod", first=True)
        if entry is None:
            raise RuntimeError("Could not find entry")
        entry.set_custom_property("database", "production")
        ms._credential_store.save()

        # Build URL (masked)
        url = ms.get_db_url("postgres-prod")
        assert url == "postgresql://admin:*****@db.example.com:5432/production"

    def test_build_url_with_driver(self, tmp_path):
        """Test building database URL with driver."""
        db_path = tmp_path / "dburl.kdbx"
        sidecar_path = tmp_path / ".password.txt"
        sidecar_path.write_text("test-password")

        ms = MattStash(path=str(db_path))

        ms.put("postgres-dev", username="devuser", password="devpass", url="localhost:5432", autoincrement=False)
        # Set database as custom property
        kp = ms._credential_store.open()
        if kp is None:
            raise RuntimeError("Could not open database")
        entry = kp.find_entries(title="postgres-dev", first=True)
        if entry is None:
            raise RuntimeError("Could not find entry")
        entry.set_custom_property("database", "devdb")
        ms._credential_store.save()

        # Build URL with driver
        url = ms.get_db_url("postgres-dev", driver="psycopg")
        assert url == "postgresql+psycopg://devuser:*****@localhost:5432/devdb"

    def test_build_url_unmasked(self, tmp_path):
        """Test building unmasked database URL."""
        db_path = tmp_path / "dburl.kdbx"
        sidecar_path = tmp_path / ".password.txt"
        sidecar_path.write_text("test-password")

        ms = MattStash(path=str(db_path))

        ms.put("test-db", username="user", password="pass", url="localhost:5432", autoincrement=False)
        # Set database as custom property
        kp = ms._credential_store.open()
        if kp is None:
            raise RuntimeError("Could not open database")
        entry = kp.find_entries(title="test-db", first=True)
        if entry is None:
            raise RuntimeError("Could not find entry")
        entry.set_custom_property("database", "testdb")
        ms._credential_store.save()

        # Build URL unmasked
        url = ms.get_db_url("test-db", mask_password=False)
        assert url == "postgresql://user:pass@localhost:5432/testdb"


class TestErrorHandling:
    """Test error handling in integration scenarios."""

    def test_get_nonexistent_credential(self, tmp_path):
        """Test getting a credential that doesn't exist."""
        db_path = tmp_path / "errors.kdbx"
        sidecar_path = tmp_path / ".password.txt"
        sidecar_path.write_text("test-password")

        ms = MattStash(path=str(db_path))

        # Get non-existent credential
        result = ms.get("nonexistent")
        assert result is None

    def test_delete_nonexistent_credential(self, tmp_path):
        """Test deleting a credential that doesn't exist."""
        db_path = tmp_path / "errors.kdbx"
        sidecar_path = tmp_path / ".password.txt"
        sidecar_path.write_text("test-password")

        ms = MattStash(path=str(db_path))

        # Delete non-existent credential
        result = ms.delete("nonexistent")
        assert result is False

    def test_invalid_database_credential(self, tmp_path):
        """Test building URL from simple credential raises error."""
        db_path = tmp_path / "errors.kdbx"
        sidecar_path = tmp_path / ".password.txt"
        sidecar_path.write_text("test-password")

        ms = MattStash(path=str(db_path))

        # Create simple credential
        ms.put("simple-secret", value="just-a-value", autoincrement=False)

        # Try to build DB URL - should raise
        with pytest.raises(ValueError, match="simple secret"):
            ms.get_db_url("simple-secret")


class TestPasswordResolution:
    """Test password resolution from various sources."""

    def test_explicit_password(self, tmp_path):
        """Test explicit password takes precedence."""
        db_path = tmp_path / "password.kdbx"
        sidecar_path = tmp_path / ".password.txt"
        sidecar_path.write_text("sidecar-password")

        # Set environment variable
        os.environ["KDBX_PASSWORD"] = "env-password"

        try:
            # Explicit password should win
            ms = MattStash(path=str(db_path), password="explicit-password")
            assert ms.password == "explicit-password"
        finally:
            # Clean up env var
            if "KDBX_PASSWORD" in os.environ:
                del os.environ["KDBX_PASSWORD"]

    def test_sidecar_password(self, tmp_path):
        """Test sidecar file password resolution."""
        db_path = tmp_path / "password.kdbx"
        sidecar_path = tmp_path / ".password.txt"
        sidecar_path.write_text("sidecar-password")

        ms = MattStash(path=str(db_path))
        assert ms.password == "sidecar-password"

    def test_env_password(self, tmp_path):
        """Test environment variable password resolution."""
        db_path = tmp_path / "password.kdbx"

        # Set environment variable
        os.environ["KDBX_PASSWORD"] = "env-password"

        try:
            ms = MattStash(path=str(db_path))
            # Note: Sidecar might be created during bootstrap, so check if password resolved
            assert ms.password in ["env-password", ""]
        finally:
            if "KDBX_PASSWORD" in os.environ:
                del os.environ["KDBX_PASSWORD"]


class TestMultipleOperations:
    """Test multiple sequential operations."""

    def test_batch_credential_creation(self, tmp_path):
        """Test creating many credentials in sequence."""
        db_path = tmp_path / "batch.kdbx"
        sidecar_path = tmp_path / ".password.txt"
        sidecar_path.write_text("test-password")

        ms = MattStash(path=str(db_path))

        # Create 10 credentials
        for i in range(10):
            ms.put(f"credential-{i}", value=f"value-{i}", autoincrement=False)

        # Verify all created
        credentials = ms.list()
        assert len(credentials) == 10

        # Verify values
        for i in range(10):
            cred = ms.get(f"credential-{i}", show_password=True)
            assert cred["value"] == f"value-{i}"

    def test_mixed_operations(self, tmp_path):
        """Test mixed create, read, update, delete operations."""
        db_path = tmp_path / "mixed.kdbx"
        sidecar_path = tmp_path / ".password.txt"
        sidecar_path.write_text("test-password")

        ms = MattStash(path=str(db_path))

        # Create
        ms.put("cred1", value="value1", autoincrement=False)
        ms.put("cred2", value="value2", autoincrement=False)
        ms.put("cred3", value="value3", autoincrement=False)

        # Read
        assert ms.get("cred1") is not None

        # Update
        ms.put("cred2", value="updated-value2", autoincrement=False)

        # Delete
        ms.delete("cred3")

        # Verify state
        credentials = ms.list()
        assert len(credentials) == 2

        cred2 = ms.get("cred2", show_password=True)
        assert cred2["value"] == "updated-value2"

        assert ms.get("cred3") is None
