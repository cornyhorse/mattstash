"""
Test coverage for CLI functionality and main entry points.
"""

import pytest
import sys
import json
from pathlib import Path
from unittest.mock import patch, Mock
from mattstash.core import main
from mattstash.credential import serialize_credential, Credential


def test_serialize_credential_with_password():
    """Test serialize_credential with show_password=True"""
    cred = Credential(
        credential_name="test",
        username="user",
        password="secret",
        url="https://example.com",
        notes="notes",
        tags=["tag1"]
    )

    result = serialize_credential(cred, show_password=True)
    assert result["password"] == "secret"


def test_serialize_credential_without_password():
    """Test serialize_credential with show_password=False"""
    cred = Credential(
        credential_name="test",
        username="user",
        password="secret",
        url="https://example.com",
        notes="notes",
        tags=["tag1"]
    )

    result = serialize_credential(cred, show_password=False)
    assert result["password"] == "*****"


def test_main_invalid_command():
    """Test main function with invalid command"""
    with pytest.raises(SystemExit):
        main(["invalid_command"])


def test_main_put_value_mode(temp_db: Path):
    """Test main function with put command in value mode"""
    result = main([
        "--db", str(temp_db),
        "put", "test-key", "--value", "test-value"
    ])
    assert result == 0


def test_main_put_value_mode_with_json(temp_db: Path):
    """Test main function with put command in value mode with JSON output"""
    with patch('builtins.print') as mock_print:
        result = main([
            "--db", str(temp_db),
            "put", "test-key", "--value", "test-value", "--json"
        ])
        assert result == 0
        # Verify JSON output was printed
        mock_print.assert_called()


def test_main_put_fields_mode(temp_db: Path):
    """Test main function with put command in fields mode"""
    result = main([
        "--db", str(temp_db),
        "put", "test-cred", "--fields",
        "--username", "testuser",
        "--password", "testpass",
        "--url", "https://example.com"
    ])
    assert result == 0


def test_main_put_fields_mode_with_json(temp_db: Path):
    """Test main function with put command in fields mode with JSON output"""
    with patch('builtins.print') as mock_print:
        result = main([
            "--db", str(temp_db),
            "put", "test-cred", "--fields",
            "--username", "testuser",
            "--json"
        ])
        assert result == 0
        mock_print.assert_called()


def test_main_get_nonexistent(temp_db: Path):
    """Test main function getting nonexistent credential"""
    result = main([
        "--db", str(temp_db),
        "get", "nonexistent"
    ])
    assert result == 2  # Not found error code


def test_main_delete_nonexistent(temp_db: Path):
    """Test main function delete nonexistent entry"""
    result = main([
        "--db", str(temp_db),
        "delete", "nonexistent"
    ])
    assert result == 2


def test_main_versions_empty(temp_db: Path):
    """Test main function versions command with no versions"""
    # The MattStash class prints bootstrap messages to stderr, not stdout
    # So we should only check that no version output was printed to stdout
    import io
    from contextlib import redirect_stdout

    output = io.StringIO()
    with redirect_stdout(output):
        result = main([
            "--db", str(temp_db),
            "versions", "nonexistent"
        ])

    assert result == 0
    # Check that no versions were printed to stdout
    assert output.getvalue().strip() == ""


def test_main_versions_with_json(temp_db: Path):
    """Test main function versions command with JSON output"""
    with patch('builtins.print') as mock_print:
        result = main([
            "--db", str(temp_db),
            "versions", "test", "--json"
        ])
        assert result == 0
        mock_print.assert_called_with("[]")


def test_main_db_url_error(temp_db: Path):
    """Test main function db-url command with error"""
    result = main([
        "--db", str(temp_db),
        "db-url", "nonexistent"
    ])
    assert result == 5  # DB URL error code


def test_main_s3_test_missing_credential(temp_db: Path):
    """Test main function s3-test with missing credential"""
    result = main([
        "--db", str(temp_db),
        "s3-test", "nonexistent"
    ])
    assert result == 3  # S3 client error code


def test_main_s3_test_quiet_mode(temp_db: Path):
    """Test main function s3-test in quiet mode"""
    result = main([
        "--db", str(temp_db),
        "s3-test", "nonexistent", "--quiet"
    ])
    assert result == 3  # Should still fail but quietly


@pytest.fixture()
def temp_db(tmp_path: Path) -> Path:
    """Create an isolated directory for each test to hold DB + sidecar."""
    d = tmp_path / "mattstash"
    d.mkdir()
    return d / "test.kdbx"
