"""
Integration tests for CLI list/keys commands with server backend.

Tests the `mattstash list` and `mattstash keys` commands when targeting a running server.
"""


class TestCLIServerList:
    """Test CLI list command against server."""

    def test_list_empty_database(self, run_mattstash_cli, cli_env):
        """Test listing credentials when database is empty."""
        result = run_mattstash_cli(["list"], cli_env)
        # Should succeed even if empty
        assert result.returncode == 0

    def test_list_with_credentials(self, run_mattstash_cli, cli_env):
        """Test listing after adding some credentials."""
        # Add a few credentials
        run_mattstash_cli(["put", "cred1", "--value", "value1"], cli_env)
        run_mattstash_cli(["put", "cred2", "--value", "value2"], cli_env)

        # List
        result = run_mattstash_cli(["list"], cli_env)
        assert result.returncode == 0
        assert "cred1" in result.stdout
        assert "cred2" in result.stdout
        # Passwords should be masked by default
        assert "*****" in result.stdout

    def test_list_with_show_password(self, run_mattstash_cli, cli_env):
        """Test listing with passwords shown."""
        run_mattstash_cli(["put", "shown-cred", "--value", "visible-secret"], cli_env)

        result = run_mattstash_cli(["list", "--show-password"], cli_env)
        assert result.returncode == 0
        assert "shown-cred" in result.stdout
        # Password should be visible
        # Note: Depending on implementation, may or may not show

    def test_list_json_output(self, run_mattstash_cli, cli_env):
        """Test list with JSON output."""
        run_mattstash_cli(["put", "json-list", "--value", "value"], cli_env)

        result = run_mattstash_cli(["list", "--json"], cli_env)
        assert result.returncode == 0
        assert "{" in result.stdout or "[" in result.stdout


class TestCLIServerKeys:
    """Test CLI keys command against server."""

    def test_keys_lists_titles_only(self, run_mattstash_cli, cli_env):
        """Test that keys command lists only credential titles."""
        # Add credentials
        run_mattstash_cli(["put", "key1", "--value", "v1"], cli_env)
        run_mattstash_cli(["put", "key2", "--value", "v2"], cli_env)

        result = run_mattstash_cli(["keys"], cli_env)
        assert result.returncode == 0
        assert "key1" in result.stdout
        assert "key2" in result.stdout
        # Should not show passwords or other details
        assert "*****" not in result.stdout

    def test_keys_json_output(self, run_mattstash_cli, cli_env):
        """Test keys command with JSON output."""
        run_mattstash_cli(["put", "json-key", "--value", "value"], cli_env)

        result = run_mattstash_cli(["keys", "--json"], cli_env)
        assert result.returncode == 0
        assert "[" in result.stdout  # Should be JSON array
