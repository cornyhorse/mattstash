"""
Integration tests for CLI get command with server backend.

Tests the `mattstash get` command when targeting a running server.
"""

import pytest


class TestCLIServerGet:
    """Test CLI get command against server."""
    
    def test_get_nonexistent_credential(self, run_mattstash_cli, cli_env):
        """Test getting a credential that doesn't exist."""
        result = run_mattstash_cli(["get", "nonexistent-cred"], cli_env)
        assert result.returncode != 0
        assert "not found" in result.stderr.lower()
    
    def test_put_and_get_simple_credential(self, run_mattstash_cli, cli_env):
        """Test storing and retrieving a simple credential via server."""
        # Put credential
        result = run_mattstash_cli(
            ["put", "test-api-key", "--value", "secret-value-123"],
            cli_env
        )
        assert result.returncode == 0, f"Put failed: {result.stderr}"
        assert "OK" in result.stdout or "test-api-key" in result.stdout
        
        # Get credential (masked)
        result = run_mattstash_cli(["get", "test-api-key"], cli_env)
        assert result.returncode == 0, f"Get failed: {result.stderr}"
        assert "test-api-key" in result.stdout
        assert "*****" in result.stdout
        assert "secret-value-123" not in result.stdout
        
        # Get credential (show password)
        result = run_mattstash_cli(
            ["get", "test-api-key", "--show-password"],
            cli_env
        )
        assert result.returncode == 0
        assert "secret-value-123" in result.stdout
    
    def test_get_with_json_output(self, run_mattstash_cli, cli_env):
        """Test getting credential with JSON output."""
        # Put credential first
        run_mattstash_cli(
            ["put", "json-test", "--value", "json-value"],
            cli_env
        )
        
        # Get with JSON
        result = run_mattstash_cli(
            ["get", "json-test", "--json", "--show-password"],
            cli_env
        )
        assert result.returncode == 0
        assert "{" in result.stdout
        assert "json-test" in result.stdout or "password" in result.stdout
    
    def test_authentication_failure(self, run_mattstash_cli, cli_env_invalid_key):
        """Test that invalid API key is rejected."""
        result = run_mattstash_cli(["get", "any-cred"], cli_env_invalid_key)
        assert result.returncode != 0
        # Server should reject with auth error
