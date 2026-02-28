"""
Integration tests for CLI workflows.

Tests CLI commands with actual database operations.
"""

import json
import subprocess


def run_cli(args, env=None):
    """Helper to run CLI command and capture output."""
    cmd = ["mattstash", *args]
    result = subprocess.run(cmd, capture_output=True, text=True, env=env)
    return result


class TestCLISetup:
    """Test CLI setup command."""

    def test_setup_creates_database(self, tmp_path):
        """Test setup command creates database and sidecar."""
        db_path = tmp_path / "cli-test.kdbx"

        result = run_cli(["setup", "--db", str(db_path)])

        # Should succeed
        assert result.returncode == 0

        # Database should exist
        assert db_path.exists()

        # Sidecar should exist
        sidecar_path = tmp_path / ".password.txt"
        assert sidecar_path.exists()

    def test_setup_force_recreates(self, tmp_path):
        """Test setup --force recreates existing database."""
        db_path = tmp_path / "cli-test.kdbx"

        # First setup
        run_cli(["setup", "--db", str(db_path)])

        # Second setup with --force
        result = run_cli(["setup", "--db", str(db_path), "--force"])
        assert result.returncode == 0


class TestCLIPut:
    """Test CLI put command."""

    def test_put_simple_credential(self, tmp_path):
        """Test putting a simple credential via CLI."""
        db_path = tmp_path / "cli-test.kdbx"
        sidecar_path = tmp_path / ".password.txt"
        sidecar_path.write_text("test-password")

        # Setup
        run_cli(["setup", "--db", str(db_path)])

        # Put credential
        result = run_cli(["put", "api-key", "--value", "secret-123", "--db", str(db_path)])

        assert result.returncode == 0

    def test_put_database_credential(self, tmp_path):
        """Test putting a database credential via CLI."""
        db_path = tmp_path / "cli-test.kdbx"
        sidecar_path = tmp_path / ".password.txt"
        sidecar_path.write_text("test-password")

        run_cli(["setup", "--db", str(db_path)])

        # Put database credential
        result = run_cli(
            [
                "put",
                "postgres-prod",
                "--fields",
                "--username",
                "admin",
                "--password",
                "secret",
                "--url",
                "db.example.com:5432",
                "--db",
                str(db_path),
            ]
        )

        assert result.returncode == 0

    def test_put_with_notes(self, tmp_path):
        """Test putting credential with notes."""
        db_path = tmp_path / "cli-test.kdbx"
        sidecar_path = tmp_path / ".password.txt"
        sidecar_path.write_text("test-password")

        run_cli(["setup", "--db", str(db_path)])

        result = run_cli(
            [
                "put",
                "documented-secret",
                "--value",
                "secret",
                "--notes",
                "This is a test credential",
                "--db",
                str(db_path),
            ]
        )

        assert result.returncode == 0


class TestCLIGet:
    """Test CLI get command."""

    def test_get_existing_credential(self, tmp_path):
        """Test getting an existing credential."""
        db_path = tmp_path / "cli-test.kdbx"
        sidecar_path = tmp_path / ".password.txt"
        sidecar_path.write_text("test-password")

        run_cli(["setup", "--db", str(db_path)])
        run_cli(["put", "test-key", "--value", "test-value", "--db", str(db_path)])

        # Get credential (masked)
        result = run_cli(["get", "test-key", "--db", str(db_path)])

        assert result.returncode == 0
        assert "test-key" in result.stdout
        assert "*****" in result.stdout or "test-value" not in result.stdout

    def test_get_with_show_password(self, tmp_path):
        """Test getting credential with password shown."""
        db_path = tmp_path / "cli-test.kdbx"
        sidecar_path = tmp_path / ".password.txt"
        sidecar_path.write_text("test-password")

        run_cli(["setup", "--db", str(db_path)])
        run_cli(["put", "secret", "--value", "my-secret", "--db", str(db_path)])

        # Get with password shown
        result = run_cli(["get", "secret", "--show-password", "--db", str(db_path)])

        assert result.returncode == 0
        assert "my-secret" in result.stdout

    def test_get_json_output(self, tmp_path):
        """Test getting credential as JSON."""
        db_path = tmp_path / "cli-test.kdbx"
        sidecar_path = tmp_path / ".password.txt"
        sidecar_path.write_text("test-password")

        run_cli(["setup", "--db", str(db_path)])
        run_cli(["put", "json-test", "--value", "value", "--db", str(db_path)])

        # Get as JSON
        result = run_cli(["get", "json-test", "--json", "--db", str(db_path)])

        assert result.returncode == 0

        # Parse JSON output
        data = json.loads(result.stdout)
        assert data["title"] == "json-test"

    def test_get_nonexistent_credential(self, tmp_path):
        """Test getting a credential that doesn't exist."""
        db_path = tmp_path / "cli-test.kdbx"
        sidecar_path = tmp_path / ".password.txt"
        sidecar_path.write_text("test-password")

        run_cli(["setup", "--db", str(db_path)])

        result = run_cli(["get", "nonexistent", "--db", str(db_path)])

        # Should fail
        assert result.returncode != 0


class TestCLIList:
    """Test CLI list command."""

    def test_list_empty_database(self, tmp_path):
        """Test listing empty database."""
        db_path = tmp_path / "cli-test.kdbx"
        sidecar_path = tmp_path / ".password.txt"
        sidecar_path.write_text("test-password")

        run_cli(["setup", "--db", str(db_path)])

        result = run_cli(["list", "--db", str(db_path)])

        assert result.returncode == 0

    def test_list_multiple_credentials(self, tmp_path):
        """Test listing multiple credentials."""
        db_path = tmp_path / "cli-test.kdbx"
        sidecar_path = tmp_path / ".password.txt"
        sidecar_path.write_text("test-password")

        run_cli(["setup", "--db", str(db_path)])

        # Add credentials
        run_cli(["put", "cred1", "--value", "val1", "--db", str(db_path)])
        run_cli(["put", "cred2", "--value", "val2", "--db", str(db_path)])
        run_cli(["put", "cred3", "--value", "val3", "--db", str(db_path)])

        # List
        result = run_cli(["list", "--db", str(db_path)])

        assert result.returncode == 0
        assert "cred1" in result.stdout
        assert "cred2" in result.stdout
        assert "cred3" in result.stdout

    def test_list_json_output(self, tmp_path):
        """Test listing credentials as JSON."""
        db_path = tmp_path / "cli-test.kdbx"
        sidecar_path = tmp_path / ".password.txt"
        sidecar_path.write_text("test-password")

        run_cli(["setup", "--db", str(db_path)])
        run_cli(["put", "test", "--value", "val", "--db", str(db_path)])

        result = run_cli(["list", "--json", "--db", str(db_path)])

        assert result.returncode == 0

        # Parse JSON
        data = json.loads(result.stdout)
        assert isinstance(data, list)


class TestCLIDelete:
    """Test CLI delete command."""

    def test_delete_existing_credential(self, tmp_path):
        """Test deleting an existing credential."""
        db_path = tmp_path / "cli-test.kdbx"
        sidecar_path = tmp_path / ".password.txt"
        sidecar_path.write_text("test-password")

        run_cli(["setup", "--db", str(db_path)])
        run_cli(["put", "to-delete", "--value", "temp", "--db", str(db_path)])

        # Delete
        result = run_cli(["delete", "to-delete", "--db", str(db_path)])

        assert result.returncode == 0

        # Verify deletion
        get_result = run_cli(["get", "to-delete", "--db", str(db_path)])
        assert get_result.returncode != 0

    def test_delete_nonexistent_credential(self, tmp_path):
        """Test deleting a credential that doesn't exist."""
        db_path = tmp_path / "cli-test.kdbx"
        sidecar_path = tmp_path / ".password.txt"
        sidecar_path.write_text("test-password")

        run_cli(["setup", "--db", str(db_path)])

        run_cli(["delete", "nonexistent", "--db", str(db_path)])

        # Should handle gracefully (or fail)
        # Behavior depends on implementation


class TestCLIDbUrl:
    """Test CLI db-url command."""

    def test_db_url_generation(self, tmp_path):
        """Test generating database URL via CLI."""
        db_path = tmp_path / "cli-test.kdbx"
        sidecar_path = tmp_path / ".password.txt"
        sidecar_path.write_text("test-password")

        run_cli(["setup", "--db", str(db_path)])

        # Put database credential
        run_cli(
            [
                "put",
                "postgres",
                "--fields",
                "--username",
                "user",
                "--password",
                "pass",
                "--url",
                "localhost:5432",
                "--db",
                str(db_path),
            ]
        )

        # Generate URL
        result = run_cli(["db-url", "postgres", "--db", str(db_path)])

        assert result.returncode == 0
        assert "postgresql://" in result.stdout
        assert "localhost:5432" in result.stdout

    def test_db_url_with_driver(self, tmp_path):
        """Test generating database URL with driver."""
        db_path = tmp_path / "cli-test.kdbx"
        sidecar_path = tmp_path / ".password.txt"
        sidecar_path.write_text("test-password")

        run_cli(["setup", "--db", str(db_path)])

        run_cli(
            [
                "put",
                "postgres",
                "--fields",
                "--username",
                "user",
                "--password",
                "pass",
                "--url",
                "localhost:5432",
                "--db",
                str(db_path),
            ]
        )

        # Generate URL with driver
        result = run_cli(["db-url", "postgres", "--driver", "psycopg", "--db", str(db_path)])

        assert result.returncode == 0
        assert "postgresql+psycopg://" in result.stdout


class TestCLIKeys:
    """Test CLI keys command."""

    def test_keys_lists_titles(self, tmp_path):
        """Test keys command lists only titles."""
        db_path = tmp_path / "cli-test.kdbx"
        sidecar_path = tmp_path / ".password.txt"
        sidecar_path.write_text("test-password")

        run_cli(["setup", "--db", str(db_path)])

        # Add credentials
        run_cli(["put", "key1", "--value", "val1", "--db", str(db_path)])
        run_cli(["put", "key2", "--value", "val2", "--db", str(db_path)])

        # Get keys
        result = run_cli(["keys", "--db", str(db_path)])

        assert result.returncode == 0
        assert "key1" in result.stdout
        assert "key2" in result.stdout


class TestCLIVersions:
    """Test CLI versions command."""

    def test_versions_lists_all_versions(self, tmp_path):
        """Test versions command lists all versions."""
        db_path = tmp_path / "cli-test.kdbx"
        sidecar_path = tmp_path / ".password.txt"
        sidecar_path.write_text("test-password")

        run_cli(["setup", "--db", str(db_path)])

        # Create versioned credentials
        run_cli(["put", "secret@1", "--value", "v1", "--db", str(db_path)])
        run_cli(["put", "secret@2", "--value", "v2", "--db", str(db_path)])
        run_cli(["put", "secret@3", "--value", "v3", "--db", str(db_path)])

        # List versions
        result = run_cli(["versions", "secret", "--db", str(db_path)])

        assert result.returncode == 0
        assert "secret@1" in result.stdout
        assert "secret@2" in result.stdout
        assert "secret@3" in result.stdout


class TestCLICompleteWorkflow:
    """Test complete CLI workflows."""

    def test_complete_credential_lifecycle_cli(self, tmp_path):
        """Test complete lifecycle via CLI: setup → put → get → update → delete."""
        db_path = tmp_path / "workflow.kdbx"
        sidecar_path = tmp_path / ".password.txt"
        sidecar_path.write_text("test-password")

        # Setup
        result = run_cli(["setup", "--db", str(db_path)])
        assert result.returncode == 0

        # Put
        result = run_cli(["put", "workflow-test", "--value", "v1", "--db", str(db_path)])
        assert result.returncode == 0

        # Get
        result = run_cli(["get", "workflow-test", "--db", str(db_path)])
        assert result.returncode == 0
        assert "workflow-test" in result.stdout

        # Update
        result = run_cli(["put", "workflow-test", "--value", "v2", "--db", str(db_path)])
        assert result.returncode == 0

        # Verify update
        result = run_cli(["get", "workflow-test", "--show-password", "--db", str(db_path)])
        assert "v2" in result.stdout

        # Delete
        result = run_cli(["delete", "workflow-test", "--db", str(db_path)])
        assert result.returncode == 0

        # Verify deletion
        result = run_cli(["get", "workflow-test", "--db", str(db_path)])
        assert result.returncode != 0
