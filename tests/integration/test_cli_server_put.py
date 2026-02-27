"""
Integration tests for CLI put command with server backend.

Tests the `mattstash put` command when targeting a running server.
"""

import pytest


class TestCLIServerPut:
    """Test CLI put command against server."""
    
    def test_put_simple_credential(self, run_mattstash_cli, cli_env):
        """Test storing a simple credential."""
        result = run_mattstash_cli(
            ["put", "simple-secret", "--value", "simple-value"],
            cli_env
        )
        assert result.returncode == 0, f"Put failed: {result.stderr}"
        assert "OK" in result.stdout or "simple-secret" in result.stdout
    
    def test_put_full_credential(self, run_mattstash_cli, cli_env):
        """Test storing a full credential with all fields."""
        result = run_mattstash_cli(
            [
                "put", "full-cred",
                "--fields",
                "--username", "testuser",
                "--password", "testpass",
                "--url", "https://example.com",
                "--notes", "Test notes"
            ],
            cli_env
        )
        assert result.returncode == 0, f"Put failed: {result.stderr}"
        
        # Verify by getting it back
        result = run_mattstash_cli(
            ["get", "full-cred", "--show-password"],
            cli_env
        )
        assert result.returncode == 0
        assert "testuser" in result.stdout
        assert "testpass" in result.stdout
    
    def test_update_credential(self, run_mattstash_cli, cli_env):
        """Test updating an existing credential."""
        # Create initial
        run_mattstash_cli(
            ["put", "update-test", "--value", "initial"],
            cli_env
        )
        
        # Update
        result = run_mattstash_cli(
            ["put", "update-test", "--value", "updated"],
            cli_env
        )
        assert result.returncode == 0
        
        # Verify update
        result = run_mattstash_cli(
            ["get", "update-test", "--show-password"],
            cli_env
        )
        assert "updated" in result.stdout
        assert "initial" not in result.stdout
    
    def test_put_with_notes(self, run_mattstash_cli, cli_env):
        """Test storing credential with notes."""
        result = run_mattstash_cli(
            [
                "put", "noted-cred",
                "--value", "secret",
                "--notes", "This is a test note"
            ],
            cli_env
        )
        assert result.returncode == 0
        
        # Verify notes are stored
        result = run_mattstash_cli(["get", "noted-cred"], cli_env)
        assert result.returncode == 0
        # Notes should appear in output
