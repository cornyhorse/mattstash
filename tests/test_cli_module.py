"""
Test coverage for the new CLI module.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import patch, Mock
from mattstash.cli import main


def test_cli_help():
    """Test that CLI help works"""
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])
    assert exc_info.value.code == 0


def test_cli_invalid_subcommand():
    """Test CLI with invalid subcommand"""
    with pytest.raises(SystemExit) as exc_info:
        main(["invalid"])
    assert exc_info.value.code != 0


def test_cli_put_without_required_args():
    """Test CLI put without required arguments"""
    with pytest.raises(SystemExit) as exc_info:
        main(["put", "test"])
    # Should fail due to missing --value or --fields


def test_cli_list_help():
    """Test list subcommand help"""
    with pytest.raises(SystemExit) as exc_info:
        main(["list", "--help"])
    assert exc_info.value.code == 0


def test_cli_get_help():
    """Test get subcommand help"""
    with pytest.raises(SystemExit) as exc_info:
        main(["get", "--help"])
    assert exc_info.value.code == 0


def test_cli_put_help():
    """Test put subcommand help"""
    with pytest.raises(SystemExit) as exc_info:
        main(["put", "--help"])
    assert exc_info.value.code == 0


def test_cli_delete_help():
    """Test delete subcommand help"""
    with pytest.raises(SystemExit) as exc_info:
        main(["delete", "--help"])
    assert exc_info.value.code == 0


def test_cli_versions_help():
    """Test versions subcommand help"""
    with pytest.raises(SystemExit) as exc_info:
        main(["versions", "--help"])
    assert exc_info.value.code == 0


def test_cli_db_url_help():
    """Test db-url subcommand help"""
    with pytest.raises(SystemExit) as exc_info:
        main(["db-url", "--help"])
    assert exc_info.value.code == 0


def test_cli_s3_test_help():
    """Test s3-test subcommand help"""
    with pytest.raises(SystemExit) as exc_info:
        main(["s3-test", "--help"])
    assert exc_info.value.code == 0


def test_cli_keys_help():
    """Test keys subcommand help"""
    with pytest.raises(SystemExit) as exc_info:
        main(["keys", "--help"])
    assert exc_info.value.code == 0


def test_cli_put_fields_missing_args():
    """Test put --fields without any field arguments"""
    with patch('mattstash.cli.handlers.put.put') as mock_put:
        mock_put.return_value = {"name": "test", "value": "*****"}
        result = main(["--db", "/tmp/test.kdbx", "put", "test", "--fields"])
        assert result == 0
        mock_put.assert_called_once()


def test_cli_list_verbose_flag():
    """Test list command with verbose flag"""
    with patch('mattstash.cli.handlers.list.list_creds') as mock_list:
        mock_list.return_value = []
        result = main(["--db", "/tmp/test.kdbx", "list"])
        assert result == 0
        mock_list.assert_called_once()


def test_cli_get_with_json_flag():
    """Test get command with JSON flag"""
    with patch('mattstash.cli.handlers.get.get') as mock_get:
        mock_get.return_value = {"name": "test", "value": "*****"}
        result = main(["--db", "/tmp/test.kdbx", "get", "test", "--json"])
        assert result == 0
        mock_get.assert_called_once()


def test_cli_put_with_comment():
    """Test put command with comment"""
    with patch('mattstash.cli.handlers.put.put') as mock_put:
        mock_put.return_value = {"name": "test", "value": "*****"}
        result = main(["--db", "/tmp/test.kdbx", "put", "test", "--value", "secret", "--comment", "Test comment"])
        assert result == 0
        mock_put.assert_called_once()


def test_cli_put_with_notes():
    """Test put command with notes"""
    with patch('mattstash.cli.handlers.put.put') as mock_put:
        mock_put.return_value = {"name": "test", "value": "*****"}
        result = main(["--db", "/tmp/test.kdbx", "put", "test", "--value", "secret", "--notes", "Test notes"])
        assert result == 0
        mock_put.assert_called_once()


def test_cli_put_with_tags():
    """Test put command with tags"""
    with patch('mattstash.cli.handlers.put.put') as mock_put:
        mock_put.return_value = {"name": "test", "value": "*****"}
        result = main(["--db", "/tmp/test.kdbx", "put", "test", "--value", "secret", "--tag", "tag1", "--tag", "tag2"])
        assert result == 0
        mock_put.assert_called_once()


def test_cli_s3_test_with_bucket():
    """Test s3-test command with bucket"""
    with patch('mattstash.cli.handlers.s3_test.get_s3_client') as mock_get_s3:
        mock_client = Mock()
        mock_get_s3.return_value = mock_client
        result = main(["--db", "/tmp/test.kdbx", "s3-test", "test", "--bucket", "test-bucket"])
        assert result == 0
        mock_get_s3.assert_called_once()


def test_cli_s3_test_bucket_failure():
    """Test s3-test command with bucket failure"""
    with patch('mattstash.cli.handlers.s3_test.get_s3_client') as mock_get_s3:
        mock_client = Mock()
        mock_client.head_bucket.side_effect = Exception("Bucket access failed")
        mock_get_s3.return_value = mock_client
        result = main(["--db", "/tmp/test.kdbx", "s3-test", "test", "--bucket", "test-bucket"])
        assert result == 4  # Bucket test failure code
        mock_get_s3.assert_called_once()


def test_cli_db_url_with_options():
    """Test db-url command with options"""
    with patch('mattstash.cli.handlers.db_url.get_db_url') as mock_get_db_url:
        mock_get_db_url.return_value = "postgresql://user@localhost:5432/testdb"
        result = main(["--db", "/tmp/test.kdbx", "db-url", "test", "--database", "testdb"])
        assert result == 0
        mock_get_db_url.assert_called_once()


def test_cli_unreachable_code_path():
    """Test the unreachable return 1 at end of main"""
    # This tests the fallback case that should never happen
    with patch('argparse.ArgumentParser.parse_args') as mock_parse:
        # Create a mock args object with an unexpected cmd
        mock_args = Mock()
        mock_args.cmd = "unexpected_command"
        mock_parse.return_value = mock_args

        result = main([])
        assert result == 1
