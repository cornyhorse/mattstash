"""
Integration tests for CLI delete and versions commands with server backend.

Tests the `mattstash delete` and `mattstash versions` commands.
"""


class TestCLIServerDelete:
    """Test CLI delete command against server."""

    def test_delete_existing_credential(self, run_mattstash_cli, cli_env):
        """Test deleting an existing credential."""
        # Create credential
        run_mattstash_cli(["put", "to-delete", "--value", "temporary"], cli_env)

        # Verify it exists
        result = run_mattstash_cli(["get", "to-delete"], cli_env)
        assert result.returncode == 0

        # Delete it
        result = run_mattstash_cli(["delete", "to-delete"], cli_env)
        assert result.returncode == 0
        assert "deleted" in result.stdout.lower()

        # Verify it's gone
        result = run_mattstash_cli(["get", "to-delete"], cli_env)
        assert result.returncode != 0

    def test_delete_nonexistent_credential(self, run_mattstash_cli, cli_env):
        """Test deleting a credential that doesn't exist."""
        result = run_mattstash_cli(["delete", "does-not-exist"], cli_env)
        assert result.returncode != 0


class TestCLIServerVersions:
    """Test CLI versions command against server."""

    def test_versions_of_nonexistent_credential(self, run_mattstash_cli, cli_env):
        """Test getting versions of credential that doesn't exist."""
        result = run_mattstash_cli(["versions", "nonexistent"], cli_env)
        assert result.returncode != 0

    def test_versions_after_single_put(self, run_mattstash_cli, cli_env):
        """Test versions list after single put."""
        run_mattstash_cli(["put", "versioned-cred", "--value", "v1"], cli_env)

        result = run_mattstash_cli(["versions", "versioned-cred"], cli_env)
        # Should succeed and show at least one version
        assert result.returncode == 0

    def test_versions_json_output(self, run_mattstash_cli, cli_env):
        """Test versions command with JSON output."""
        run_mattstash_cli(["put", "json-versions", "--value", "value"], cli_env)

        result = run_mattstash_cli(["versions", "json-versions", "--json"], cli_env)
        assert result.returncode == 0
        assert "[" in result.stdout  # JSON array


class TestCLIServerHealth:
    """Test server health check capabilities."""

    def test_server_responds_to_requests(self, run_mattstash_cli, cli_env):
        """Verify server is responsive by performing basic operation."""
        # Simple operation to verify server is working
        result = run_mattstash_cli(["keys"], cli_env)
        # Should succeed even if no keys exist
        assert result.returncode == 0
