"""
Test the GetHandler --version argument fix.

This test file specifically verifies that the CLI --version argument
is correctly passed through to the get() function and works as expected.
"""

from argparse import Namespace
from unittest.mock import Mock, patch

from mattstash.cli.handlers.get import GetHandler


def test_get_handler_with_version_parameter():
    """
    Test that the --version argument is correctly passed to the get() function.
    """
    handler = GetHandler()
    args = Namespace(
        title="test-credential",
        path="/tmp/test.kdbx",
        password="db_password",
        show_password=False,
        json=False,
        version=3,  # Specific version requested
    )

    mock_cred = Mock()
    mock_cred.credential_name = "test-credential"
    mock_cred.username = "test_user"
    mock_cred.password = "secret_password"
    mock_cred.url = "https://example.com"
    mock_cred.tags = ["tag1", "tag2"]
    mock_cred.notes = "Version 3 of credential"

    with patch("mattstash.cli.handlers.get.get") as mock_get:
        mock_get.return_value = mock_cred

        result = handler.handle(args)

        # Verify the function was called successfully
        assert result == 0
        mock_get.assert_called_once()

        # Verify the correct parameters were passed, including version
        call_args = mock_get.call_args
        assert call_args[0][0] == "test-credential"  # title (positional arg)

        # Check keyword arguments
        kwargs = call_args[1]
        assert kwargs["path"] == "/tmp/test.kdbx"
        assert kwargs["password"] == "db_password"
        assert kwargs["show_password"] is False
        assert kwargs["version"] == 3  # Version parameter should be passed through


def test_get_handler_with_version_and_json():
    """
    Test that the --version argument works correctly with JSON output.
    """
    handler = GetHandler()
    args = Namespace(
        title="api-key", path="/tmp/test.kdbx", password="db_password", show_password=True, json=True, version=1
    )

    mock_cred = Mock()
    mock_cred.credential_name = "api-key"

    with (
        patch("mattstash.cli.handlers.get.get") as mock_get,
        patch("mattstash.cli.handlers.get.serialize_credential") as mock_serialize,
        patch("builtins.print") as mock_print,
    ):
        mock_get.return_value = mock_cred
        mock_serialize.return_value = {"name": "api-key", "version": "1"}

        result = handler.handle(args)

        assert result == 0
        mock_get.assert_called_once()

        # Verify version parameter was passed
        kwargs = mock_get.call_args[1]
        assert kwargs["version"] == 1

        # Verify serialization and output
        mock_serialize.assert_called_once_with(mock_cred, show_password=True)
        mock_print.assert_called_once()


def test_get_handler_with_version_dict_result():
    """
    Test that the --version argument works with simple secret (dict) results.
    """
    handler = GetHandler()
    args = Namespace(
        title="simple-secret", path="/tmp/test.kdbx", password="db_password", show_password=False, json=False, version=2
    )

    # Mock a simple secret result (dict format)
    mock_dict_result = {"name": "simple-secret", "value": "secret_value_v2"}

    with patch("mattstash.cli.handlers.get.get") as mock_get, patch("builtins.print"):
        mock_get.return_value = mock_dict_result

        result = handler.handle(args)

        assert result == 0
        mock_get.assert_called_once()

        # Verify version parameter was passed
        kwargs = mock_get.call_args[1]
        assert kwargs["version"] == 2


def test_get_handler_without_version_parameter():
    """
    Test that when no --version is provided, None is passed (existing behavior).
    """
    handler = GetHandler()
    args = Namespace(
        title="test-credential",
        path="/tmp/test.kdbx",
        password="db_password",
        show_password=False,
        json=False,
        # No version attribute - should default to None
    )

    mock_cred = Mock()
    mock_cred.credential_name = "test-credential"
    mock_cred.username = "test_user"
    mock_cred.password = "secret_password"
    mock_cred.url = "https://example.com"
    mock_cred.tags = []
    mock_cred.notes = None

    with patch("mattstash.cli.handlers.get.get") as mock_get:
        mock_get.return_value = mock_cred

        result = handler.handle(args)

        assert result == 0
        mock_get.assert_called_once()

        # Verify version parameter defaults to None when not provided
        kwargs = mock_get.call_args[1]
        assert kwargs["version"] is None


def test_get_handler_version_not_found():
    """
    Test that when a specific version is requested but not found,
    the handler correctly returns error code 2.
    """
    handler = GetHandler()
    args = Namespace(
        title="nonexistent-version",
        path="/tmp/test.kdbx",
        password="db_password",
        show_password=False,
        json=False,
        version=99,  # Non-existent version
    )

    with patch("mattstash.cli.handlers.get.get") as mock_get:
        mock_get.return_value = None  # Version not found

        result = handler.handle(args)

        # Should return error code 2 for not found
        assert result == 2
        mock_get.assert_called_once()

        # Verify version parameter was passed
        kwargs = mock_get.call_args[1]
        assert kwargs["version"] == 99


def test_get_handler_version_zero():
    """
    Test that version 0 (if valid) is correctly passed through.
    """
    handler = GetHandler()
    args = Namespace(
        title="test-credential",
        path="/tmp/test.kdbx",
        password="db_password",
        show_password=False,
        json=False,
        version=0,
    )

    mock_cred = Mock()
    mock_cred.credential_name = "test-credential"
    mock_cred.username = "test_user"
    mock_cred.password = "secret_password"
    mock_cred.url = "https://example.com"
    mock_cred.tags = []
    mock_cred.notes = "Original version"

    with patch("mattstash.cli.handlers.get.get") as mock_get:
        mock_get.return_value = mock_cred

        result = handler.handle(args)

        assert result == 0
        mock_get.assert_called_once()

        # Verify version 0 is correctly passed
        kwargs = mock_get.call_args[1]
        assert kwargs["version"] == 0
