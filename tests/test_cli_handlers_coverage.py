"""
Test coverage for CLI handlers to reach 100% coverage.
"""

import pytest
import os
import tempfile
from unittest.mock import patch, Mock, MagicMock
from argparse import Namespace

from mattstash.cli.handlers.setup import SetupHandler
from mattstash.cli.handlers.list import ListHandler, KeysHandler
from mattstash.cli.handlers.get import GetHandler
from mattstash.cli.handlers.put import PutHandler
from mattstash.cli.handlers.delete import DeleteHandler
from mattstash.cli.handlers.versions import VersionsHandler
from mattstash.cli.handlers.s3_test import S3TestHandler
from mattstash.cli.handlers.base import BaseHandler


def test_base_handler_info_method():
    """Test the info method in BaseHandler"""
    handler = SetupHandler()  # Use a concrete implementation
    with patch('builtins.print') as mock_print:
        handler.info("test message")
        mock_print.assert_called_once_with("[mattstash] test message")


def test_setup_handler_force_overwrite():
    """Test setup handler with force flag when files exist"""
    handler = SetupHandler()
    args = Namespace(
        path="/tmp/test.kdbx",
        force=True
    )

    with patch('os.path.exists', return_value=True), \
         patch('mattstash.cli.handlers.setup.DatabaseBootstrapper') as mock_bootstrapper:

        mock_instance = Mock()
        mock_bootstrapper.return_value = mock_instance

        result = handler.handle(args)
        assert result == 0
        mock_instance._create_database_and_sidecar.assert_called_once()


def test_setup_handler_existing_files_no_force():
    """Test setup handler when files exist without force flag"""
    handler = SetupHandler()
    args = Namespace(
        path="/tmp/test.kdbx",
        force=False
    )

    with patch('os.path.exists', return_value=True):
        result = handler.handle(args)
        assert result == 1


def test_setup_handler_exception():
    """Test setup handler when an exception occurs"""
    handler = SetupHandler()
    args = Namespace(
        path="/tmp/test.kdbx",
        force=False
    )

    with patch('os.path.exists', return_value=False), \
         patch('mattstash.cli.handlers.setup.DatabaseBootstrapper', side_effect=Exception("Test error")):
        result = handler.handle(args)
        assert result == 1


def test_list_handler_json_output():
    """Test list handler with JSON output"""
    handler = ListHandler()
    args = Namespace(
        path="/tmp/test.kdbx",
        password="test",
        show_password=True,
        json=True
    )

    mock_cred = Mock()
    mock_cred.credential_name = "test"
    mock_cred.username = "user"
    mock_cred.password = "pass"
    mock_cred.url = "http://example.com"
    mock_cred.notes = "test notes"
    mock_cred.tags = ["tag1"]

    with patch('mattstash.cli.handlers.list.list_creds', return_value=[mock_cred]), \
         patch('mattstash.cli.handlers.list.serialize_credential', return_value={"test": "data"}), \
         patch('builtins.print') as mock_print:

        result = handler.handle(args)
        assert result == 0
        mock_print.assert_called()


def test_list_handler_with_notes():
    """Test list handler with credentials that have notes"""
    handler = ListHandler()
    args = Namespace(
        path="/tmp/test.kdbx",
        password="test",
        show_password=False,
        json=False
    )

    mock_cred = Mock()
    mock_cred.credential_name = "test"
    mock_cred.username = "user"
    mock_cred.password = "pass"
    mock_cred.url = "http://example.com"
    mock_cred.notes = "test notes\nline 2"
    mock_cred.tags = ["tag1"]

    with patch('mattstash.cli.handlers.list.list_creds', return_value=[mock_cred]), \
         patch('builtins.print') as mock_print:

        result = handler.handle(args)
        assert result == 0
        mock_print.assert_called()


def test_keys_handler():
    """Test keys handler"""
    handler = KeysHandler()
    args = Namespace(
        path="/tmp/test.kdbx",
        password="test",
        show_password=False,
        json=False
    )

    mock_cred = Mock()
    mock_cred.credential_name = "test"

    with patch('mattstash.cli.handlers.list.list_creds', return_value=[mock_cred]), \
         patch('builtins.print') as mock_print:

        result = handler.handle(args)
        assert result == 0
        mock_print.assert_called_with("test")


def test_keys_handler_json():
    """Test keys handler with JSON output"""
    handler = KeysHandler()
    args = Namespace(
        path="/tmp/test.kdbx",
        password="test",
        show_password=False,
        json=True
    )

    mock_cred = Mock()
    mock_cred.credential_name = "test"

    with patch('mattstash.cli.handlers.list.list_creds', return_value=[mock_cred]), \
         patch('builtins.print') as mock_print:

        result = handler.handle(args)
        assert result == 0


def test_get_handler_not_found():
    """Test get handler when credential not found"""
    handler = GetHandler()
    args = Namespace(
        title="nonexistent",
        path="/tmp/test.kdbx",
        password="test",
        show_password=False,
        json=False
    )

    with patch('mattstash.cli.handlers.get.get', return_value=None):
        result = handler.handle(args)
        assert result == 2


def test_get_handler_dict_result():
    """Test get handler with dict result (simple secret)"""
    handler = GetHandler()
    args = Namespace(
        title="test",
        path="/tmp/test.kdbx",
        password="test",
        show_password=False,
        json=False
    )

    with patch('mattstash.cli.handlers.get.get', return_value={"name": "test", "value": "secret"}), \
         patch('builtins.print') as mock_print:

        result = handler.handle(args)
        assert result == 0
        mock_print.assert_called()


def test_get_handler_dict_result_json():
    """Test get handler with dict result and JSON output"""
    handler = GetHandler()
    args = Namespace(
        title="test",
        path="/tmp/test.kdbx",
        password="test",
        show_password=False,
        json=True
    )

    with patch('mattstash.cli.handlers.get.get', return_value={"name": "test", "value": "secret"}), \
         patch('builtins.print') as mock_print:

        result = handler.handle(args)
        assert result == 0


def test_get_handler_credential_result():
    """Test get handler with credential object result"""
    handler = GetHandler()
    args = Namespace(
        title="test",
        path="/tmp/test.kdbx",
        password="test",
        show_password=True,
        json=False
    )

    mock_cred = Mock()
    mock_cred.credential_name = "test"
    mock_cred.username = "user"
    mock_cred.password = "pass"
    mock_cred.url = "http://example.com"
    mock_cred.tags = ["tag1"]
    mock_cred.notes = "test notes\nline 2"

    with patch('mattstash.cli.handlers.get.get', return_value=mock_cred), \
         patch('builtins.print') as mock_print:

        result = handler.handle(args)
        assert result == 0
        mock_print.assert_called()


def test_get_handler_credential_json():
    """Test get handler with credential object and JSON output"""
    handler = GetHandler()
    args = Namespace(
        title="test",
        path="/tmp/test.kdbx",
        password="test",
        show_password=True,
        json=True
    )

    mock_cred = Mock()
    mock_cred.credential_name = "test"

    with patch('mattstash.cli.handlers.get.get', return_value=mock_cred), \
         patch('mattstash.cli.handlers.get.serialize_credential', return_value={"test": "data"}), \
         patch('builtins.print') as mock_print:

        result = handler.handle(args)
        assert result == 0


def test_put_handler_dict_result():
    """Test put handler returning dict result"""
    handler = PutHandler()
    args = Namespace(
        title="test",
        path="/tmp/test.kdbx",
        password="test",
        value="secret",
        fields=False,
        username=None,
        url=None,
        notes=None,
        comment=None,
        tags=None,
        json=False
    )

    with patch('mattstash.cli.handlers.put.put', return_value={"name": "test", "value": "secret"}), \
         patch('builtins.print') as mock_print:

        result = handler.handle(args)
        assert result == 0
        mock_print.assert_called_with("test: secret")


def test_put_handler_credential_result_json():
    """Test put handler returning credential object with JSON"""
    handler = PutHandler()
    args = Namespace(
        title="test",
        path="/tmp/test.kdbx",
        password="test",
        value=None,
        fields=True,
        username="user",
        url="http://example.com",
        notes="test notes",
        comment=None,
        tags=["tag1"],
        json=True
    )

    mock_cred = Mock()

    with patch('mattstash.cli.handlers.put.put', return_value=mock_cred), \
         patch('mattstash.cli.handlers.put.serialize_credential', return_value={"test": "data"}), \
         patch('builtins.print') as mock_print:

        result = handler.handle(args)
        assert result == 0


def test_delete_handler_not_found():
    """Test delete handler when credential not found"""
    handler = DeleteHandler()
    args = Namespace(
        title="nonexistent",
        path="/tmp/test.kdbx",
        password="test"
    )

    with patch('mattstash.cli.handlers.delete.delete', return_value=False):
        result = handler.handle(args)
        assert result == 2


def test_versions_handler_with_results():
    """Test versions handler with results"""
    handler = VersionsHandler()
    args = Namespace(
        title="test",
        path="/tmp/test.kdbx",
        password="test",
        json=False
    )

    with patch('mattstash.cli.handlers.versions.list_versions', return_value=["0000000001", "0000000002"]), \
         patch('builtins.print') as mock_print:

        result = handler.handle(args)
        assert result == 0
        mock_print.assert_called()


def test_s3_test_handler_no_bucket_success():
    """Test S3 test handler without bucket"""
    handler = S3TestHandler()
    args = Namespace(
        title="test",
        path="/tmp/test.kdbx",
        password="test",
        region="us-east-1",
        addressing="path",
        signature_version="s3v4",
        retries_max_attempts=10,
        verbose=True,
        bucket=None,
        quiet=False
    )

    mock_client = Mock()

    with patch('mattstash.cli.handlers.s3_test.get_s3_client', return_value=mock_client):
        result = handler.handle(args)
        assert result == 0


def test_s3_test_handler_bucket_success_quiet():
    """Test S3 test handler with bucket success in quiet mode"""
    handler = S3TestHandler()
    args = Namespace(
        title="test",
        path="/tmp/test.kdbx",
        password="test",
        region="us-east-1",
        addressing="path",
        signature_version="s3v4",
        retries_max_attempts=10,
        verbose=False,
        bucket="test-bucket",
        quiet=True
    )

    mock_client = Mock()

    with patch('mattstash.cli.handlers.s3_test.get_s3_client', return_value=mock_client):
        result = handler.handle(args)
        assert result == 0


def test_s3_test_handler_client_error_quiet():
    """Test S3 test handler when client creation fails in quiet mode"""
    handler = S3TestHandler()
    args = Namespace(
        title="test",
        path="/tmp/test.kdbx",
        password="test",
        region="us-east-1",
        addressing="path",
        signature_version="s3v4",
        retries_max_attempts=10,
        verbose=False,
        bucket=None,
        quiet=True
    )

    with patch('mattstash.cli.handlers.s3_test.get_s3_client', side_effect=Exception("Test error")):
        result = handler.handle(args)
        assert result == 3
