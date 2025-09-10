"""
Test the PutHandler fix for correct parameter passing.

This test file specifically verifies that the CLI --password argument
is correctly used as the credential password (not database password)
when in --fields mode.
"""

import pytest
from unittest.mock import patch, Mock
from argparse import Namespace

from mattstash.cli.handlers.put import PutHandler


def test_put_handler_fields_mode_password_parameter_fix():
    """
    Test that in fields mode, CLI --password is used as credential password,
    not database password. This test verifies the fix for the bug where
    --password was incorrectly passed as db_password.
    """
    handler = PutHandler()
    args = Namespace(
        title="test-credential",
        path="/tmp/test.kdbx",
        password="credential_secret_password",  # This should be the credential password
        value=None,
        fields=True,
        username="test_user",
        url="https://example.com",
        notes="Test credential",
        comment=None,
        tags=["tag1", "tag2"],
        json=False
    )

    with patch('mattstash.cli.handlers.put.put') as mock_put:
        mock_put.return_value = Mock()  # Return a mock credential object

        result = handler.handle(args)

        # Verify the function was called successfully
        assert result == 0
        mock_put.assert_called_once()

        # Verify the correct parameters were passed
        call_args = mock_put.call_args
        assert call_args[0][0] == "test-credential"  # title (positional arg)

        # Check keyword arguments
        kwargs = call_args[1]
        assert kwargs['path'] == "/tmp/test.kdbx"
        assert kwargs['db_password'] is None  # Should be None to use sidecar/env resolution
        assert kwargs['username'] == "test_user"
        assert kwargs['password'] == "credential_secret_password"  # CLI password used as credential password
        assert kwargs['url'] == "https://example.com"
        assert kwargs['notes'] == "Test credential"
        assert kwargs['comment'] is None
        assert kwargs['tags'] == ["tag1", "tag2"]


def test_put_handler_value_mode_password_parameter():
    """
    Test that in value mode (--value), CLI --password is correctly used
    as database password (existing behavior should remain unchanged).
    """
    handler = PutHandler()
    args = Namespace(
        title="test-secret",
        path="/tmp/test.kdbx",
        password="db_password_123",  # This should be the database password in value mode
        value="secret_value",
        fields=False,
        username=None,
        url=None,
        notes="Simple secret",
        comment=None,
        tags=None,
        json=False
    )

    with patch('mattstash.cli.handlers.put.put') as mock_put:
        mock_put.return_value = {"name": "test-secret", "value": "secret_value"}

        result = handler.handle(args)

        # Verify the function was called successfully
        assert result == 0
        mock_put.assert_called_once()

        # Verify the correct parameters were passed
        call_args = mock_put.call_args
        assert call_args[0][0] == "test-secret"  # title (positional arg)

        # Check keyword arguments
        kwargs = call_args[1]
        assert kwargs['path'] == "/tmp/test.kdbx"
        assert kwargs['db_password'] == "db_password_123"  # CLI password used as db password
        assert kwargs['value'] == "secret_value"
        assert kwargs['notes'] == "Simple secret"
        assert kwargs['comment'] is None
        assert kwargs['tags'] is None


def test_put_handler_fields_mode_no_password():
    """
    Test that in fields mode when no --password is provided,
    None is passed as the credential password.
    """
    handler = PutHandler()
    args = Namespace(
        title="test-no-password",
        path="/tmp/test.kdbx",
        password=None,  # No CLI password provided
        value=None,
        fields=True,
        username="test_user",
        url="https://example.com",
        notes=None,
        comment=None,
        tags=None,
        json=False
    )

    with patch('mattstash.cli.handlers.put.put') as mock_put:
        mock_put.return_value = Mock()

        result = handler.handle(args)

        # Verify the function was called successfully
        assert result == 0
        mock_put.assert_called_once()

        # Verify the correct parameters were passed
        call_args = mock_put.call_args
        kwargs = call_args[1]
        assert kwargs['db_password'] is None  # No db password override
        assert kwargs['password'] is None  # No credential password provided
        assert kwargs['username'] == "test_user"
        assert kwargs['url'] == "https://example.com"


def test_put_handler_global_password_vs_field_password():
    """
    Test the distinction between global --password (for database)
    and field --password (for credential) in different modes.
    """
    # Test scenario: User provides --password at global level (for DB)
    # and wants to store a credential without a password field
    handler = PutHandler()

    # Simulate global --password being passed through args.password
    # In fields mode, this should NOT be used as db_password
    args = Namespace(
        title="db-credential",
        path="/tmp/test.kdbx",
        password="global_db_pass",  # This is from global --password
        value=None,
        fields=True,
        username="db_user",
        url="db.example.com:5432",
        notes="Database connection",
        comment=None,
        tags=["database"],
        json=False
    )

    with patch('mattstash.cli.handlers.put.put') as mock_put:
        mock_put.return_value = Mock()

        result = handler.handle(args)

        assert result == 0
        call_args = mock_put.call_args
        kwargs = call_args[1]

        # The fix ensures that in fields mode, global --password is NOT used as db_password
        assert kwargs['db_password'] is None
        # Instead, it's used as the credential password (which may not be intended,
        # but this is the current behavior after the fix)
        assert kwargs['password'] == "global_db_pass"
