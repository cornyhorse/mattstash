"""
Additional comprehensive tests to reach higher coverage.
"""

import os
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from mattstash import MattStash, get_db_url, get_s3_client


def test_password_resolution_from_env(tmp_path: Path):
    """Test password resolution from environment variable"""
    db_path = tmp_path / "test_db.kdbx"
    sidecar_path = db_path.parent / ".mattstash.txt"

    # Create a dummy database file to prevent bootstrap
    db_path.write_text("dummy db content")

    # Ensure sidecar doesn't exist so it falls back to env
    if sidecar_path.exists():
        sidecar_path.unlink()

    with patch.dict(os.environ, {"KDBX_PASSWORD": "env_password"}, clear=False):
        ms = MattStash(path=str(db_path), password=None)
        # Test the resolution method through the password resolver
        resolved_password = ms._password_resolver.resolve_password()
        assert resolved_password == "env_password"


def test_password_resolution_no_sources(tmp_path: Path):
    """Test password resolution when no sources available"""
    db_path = tmp_path / "test_db.kdbx"
    sidecar_path = db_path.parent / ".mattstash.txt"

    # Create a dummy database file to prevent bootstrap
    db_path.write_text("dummy db content")

    # Ensure sidecar doesn't exist
    if sidecar_path.exists():
        sidecar_path.unlink()

    # Ensure no environment variable and test resolution directly
    env_backup = os.environ.get("KDBX_PASSWORD")
    if "KDBX_PASSWORD" in os.environ:
        del os.environ["KDBX_PASSWORD"]

    try:
        with patch("mattstash.core.password_resolver.logger") as mock_logger:
            ms = MattStash(path=str(db_path), password=None)
            resolved = ms._password_resolver.resolve_password()
            # Should return None when no sources available
            assert resolved is None
            # Should log debug messages about missing sources
            assert any("not set" in str(call) or "not found" in str(call) for call in mock_logger.debug.call_args_list)
    finally:
        # Restore env var if it existed
        if env_backup:
            os.environ["KDBX_PASSWORD"] = env_backup


def test_get_db_url_function_creates_instance():
    """Test get_db_url module-level function creates instance"""
    with patch("mattstash.module_functions.MattStash") as mock_class:
        mock_instance = Mock()
        mock_instance.get_db_url.return_value = "test://url"
        mock_class.return_value = mock_instance

        result = get_db_url("test_cred")

        mock_class.assert_called_once()
        mock_instance.get_db_url.assert_called_once()
        assert result == "test://url"


def test_get_db_url_with_path_and_password():
    """Test get_db_url with explicit path and password"""
    with patch("mattstash.module_functions.MattStash") as mock_class:
        mock_instance = Mock()
        mock_instance.get_db_url.return_value = "test://url"
        mock_class.return_value = mock_instance

        get_db_url("test_cred", path="/custom/path", password="custom_pass")

        mock_class.assert_called_once_with(path="/custom/path", password="custom_pass")


def test_get_s3_client_function():
    """Test get_s3_client module-level function"""
    # Need to clear the global instance to force creation
    import mattstash.module_functions

    mattstash.module_functions._default_instance = None

    with patch("mattstash.module_functions.MattStash") as mock_class:
        mock_instance = Mock()
        mock_client = Mock()
        mock_instance.get_s3_client.return_value = mock_client
        mock_class.return_value = mock_instance

        result = get_s3_client("test_cred", region="us-west-2")

        mock_class.assert_called_once()
        mock_instance.get_s3_client.assert_called_once_with(
            "test_cred",
            region="us-west-2",
            addressing="path",
            signature_version="s3v4",
            retries_max_attempts=10,
            verbose=False,
        )
        assert result == mock_client


def test_get_db_url_missing_database_property(temp_db: Path):
    """Test get_db_url when credential is missing database property"""
    ms = MattStash(path=str(temp_db))

    # Create credential without database property
    ms.put("test_cred", username="user", password="pass", url="localhost:5432")

    with pytest.raises(ValueError, match="Missing database name"):
        ms.get_db_url("test_cred")


def test_get_db_url_simple_secret_error(temp_db: Path):
    """Test get_db_url with simple secret (should fail)"""
    ms = MattStash(path=str(temp_db))

    # Create simple secret
    ms.put("simple_secret", value="just_a_value")

    with pytest.raises(ValueError, match="simple secret"):
        ms.get_db_url("simple_secret")


def test_get_s3_client_missing_url(temp_db: Path):
    """Test get_s3_client with credential missing URL"""
    ms = MattStash(path=str(temp_db))

    # Create credential without URL
    ms.put("s3_cred", username="key", password="secret")

    with pytest.raises(ValueError, match="empty URL"):
        ms.get_s3_client("s3_cred")


def test_get_s3_client_missing_credentials(temp_db: Path):
    """Test get_s3_client with incomplete credentials"""
    ms = MattStash(path=str(temp_db))

    # Create credential with URL but missing username/password
    ms.put("s3_cred", url="http://s3.example.com")

    with pytest.raises(ValueError, match="missing username/password"):
        ms.get_s3_client("s3_cred")


def test_get_s3_client_boto3_import_error(temp_db: Path):
    """Test get_s3_client when boto3 is not available"""
    ms = MattStash(path=str(temp_db))

    # Create valid S3 credential
    ms.put("s3_cred", username="accesskey", password="secretkey", url="http://s3.example.com")

    # Mock the import within the method by patching builtins.__import__
    def mock_import(name, *args, **kwargs):
        if name in ["boto3", "botocore.config"]:
            raise ImportError(f"No module named '{name}'")
        return __import__(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=mock_import):
        with pytest.raises(RuntimeError, match="boto3/botocore not available"):
            ms.get_s3_client("s3_cred")


def test_hydrate_env_missing_entry(temp_db: Path):
    """Test hydrate_env with missing entry"""
    ms = MattStash(path=str(temp_db))

    # Try to hydrate from non-existent entry
    ms.hydrate_env({"nonexistent:AWS_ACCESS_KEY_ID": "AWS_ACCESS_KEY_ID"})

    # Should not set environment variable
    assert "AWS_ACCESS_KEY_ID" not in os.environ


def test_hydrate_env_custom_property(temp_db: Path):
    """Test hydrate_env with custom property"""
    from pykeepass import PyKeePass

    ms = MattStash(path=str(temp_db))

    # Create entry with custom property
    kp = PyKeePass(str(temp_db), password=ms.password)
    entry = kp.add_entry(kp.root_group, title="test_entry", username="user", password="pass")
    entry.set_custom_property("CUSTOM_PROP", "custom_value")
    kp.save()

    # Clear any existing env var
    if "TEST_CUSTOM" in os.environ:
        del os.environ["TEST_CUSTOM"]

    # Hydrate environment
    ms.hydrate_env({"test_entry:CUSTOM_PROP": "TEST_CUSTOM"})

    # Should set the environment variable
    assert os.environ.get("TEST_CUSTOM") == "custom_value"
