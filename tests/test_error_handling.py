"""
Test error handling and edge cases for MattStash.
"""

from pathlib import Path

import pytest

from mattstash import Credential, MattStash
from mattstash.utils.exceptions import DatabaseAccessError, DatabaseNotFoundError, InvalidCredentialError


def test_corrupt_database_handling(tmp_path: Path):
    """Test behavior with corrupted database file"""
    corrupt_db = tmp_path / "corrupt.kdbx"
    corrupt_db.write_text("this is not a valid kdbx file")

    ms = MattStash(path=str(corrupt_db), password="test")
    # A corrupt database is a database error, never reported as "secret not found"
    with pytest.raises(DatabaseAccessError):
        ms._ensure_initialized()
    with pytest.raises(DatabaseAccessError):
        ms.get("anything")


def test_missing_database_file(tmp_path: Path):
    """Test behavior when database file doesn't exist"""
    nonexistent_db = tmp_path / "does_not_exist.kdbx"

    ms = MattStash(path=str(nonexistent_db), password="test")
    with pytest.raises(DatabaseNotFoundError):
        ms._ensure_initialized()
    # ...and nothing is created as a side effect of trying
    assert not nonexistent_db.exists()
    assert list(tmp_path.iterdir()) == []


def test_wrong_password_handling(temp_db: Path):
    """Test behavior with incorrect password"""
    # temp_db was created with a sidecar password; try to open with a different one
    ms_wrong = MattStash(path=str(temp_db), password="wrong_password")
    with pytest.raises(DatabaseAccessError):
        ms_wrong._ensure_initialized()
    # Every operation reports the failure instead of pretending the secret is missing
    with pytest.raises(DatabaseAccessError):
        ms_wrong.get("x")
    with pytest.raises(DatabaseAccessError):
        ms_wrong.delete("x")
    with pytest.raises(DatabaseAccessError):
        ms_wrong.list()


def test_special_characters_in_values(temp_db: Path):
    """Test handling of special characters in credential values"""
    ms = MattStash(path=str(temp_db))
    special_chars = "!@#$%^&*(){}[]|\\:;\"'<>,.?/~`"

    ms.put("special", value=special_chars)
    result = ms.get("special", show_password=True)
    assert isinstance(result, dict)
    assert result["value"] == special_chars


def test_very_long_values(temp_db: Path):
    """Test handling of very long strings"""
    ms = MattStash(path=str(temp_db))
    long_value = "x" * 10000

    ms.put("long", value=long_value)
    result = ms.get("long", show_password=True)
    assert isinstance(result, dict)
    assert result["value"] == long_value


def test_unicode_characters(temp_db: Path):
    """Test handling of unicode characters"""
    ms = MattStash(path=str(temp_db))
    unicode_value = "测试🚀🔒💻αβγδ"

    ms.put("unicode", value=unicode_value)
    result = ms.get("unicode", show_password=True)
    assert isinstance(result, dict)
    assert result["value"] == unicode_value


def test_empty_values_handling(temp_db: Path):
    """Test handling of empty and None values"""
    ms = MattStash(path=str(temp_db))

    # Test empty string - empty password should create a regular credential, not simple secret
    ms.put("empty", username="user", password="", url="", notes="")
    result = ms.get("empty", show_password=True)
    assert isinstance(result, Credential)
    assert result.password == ""

    # Test simple secret with non-empty value
    ms.put("simple_with_value", value="actual_value")
    result_simple = ms.get("simple_with_value", show_password=True)
    assert isinstance(result_simple, dict)
    assert result_simple["value"] == "actual_value"

    # Test that empty value creates a credential, not a simple secret
    # because _is_simple_secret requires non-empty password
    ms.put("empty_simple", value="")
    result_empty = ms.get("empty_simple", show_password=True)
    assert isinstance(result_empty, Credential)  # Not dict because password is empty
    assert result_empty.password == ""

    # Test with None values for other fields - KeePass converts None to empty string
    ms.put("partial", username="user", password=None, url=None, notes=None)
    result = ms.get("partial", show_password=True)
    assert result.username == "user"
    # KeePass/PyKeePass converts None password to empty string, so test for that
    assert result.password == ""


def test_concurrent_access_simulation(temp_db: Path):
    """Test multiple instances accessing same database"""
    ms1 = MattStash(path=str(temp_db))
    # Both instances need to use the same password
    password = ms1.password
    ms2 = MattStash(path=str(temp_db), password=password)

    # Both should be able to access the same database
    ms1.put("shared1", value="value1")
    ms2.put("shared2", value="value2")

    # Force refresh of the database connections to see each other's changes
    # In the refactored architecture, we need to reset the credential store and entry manager
    ms1._credential_store = None
    ms1._entry_manager = None
    ms2._credential_store = None
    ms2._entry_manager = None

    # Both should see each other's entries
    result1 = ms2.get("shared1", show_password=True)
    result2 = ms1.get("shared2", show_password=True)

    assert isinstance(result1, dict) and result1["value"] == "value1"
    assert isinstance(result2, dict) and result2["value"] == "value2"


def test_invalid_version_numbers(temp_db: Path):
    """Test handling of invalid version numbers"""
    ms = MattStash(path=str(temp_db))

    # Valid version
    ms.put("test", value="v1", version=1)

    # Negative versions used to be written as a malformed title ("test@00000000-1"); now rejected
    with pytest.raises(InvalidCredentialError):
        ms.put("test", value="v-1", version=-1)
    with pytest.raises(InvalidCredentialError):
        ms.put("test", value="v-bool", version=True)  # type: ignore[arg-type]

    # Test very large version numbers
    large_version = 999999999999
    result_large = ms.put("test", value="v_large", version=large_version)
    assert isinstance(result_large, dict)


def test_malformed_titles(temp_db: Path):
    """Test handling of malformed titles with special characters"""
    ms = MattStash(path=str(temp_db))

    # These should work
    valid_titles = ["test-title", "test_title", "test.title", "test123"]
    for title in valid_titles:
        ms.put(title, value="test")
        result = ms.get(title, show_password=True)
        assert isinstance(result, dict)
        assert result["value"] == "test"


def test_get_nonexistent_credential(temp_db: Path):
    """Test getting a credential that doesn't exist"""
    ms = MattStash(path=str(temp_db))

    result = ms.get("nonexistent")
    assert result is None


def test_delete_nonexistent_credential(temp_db: Path):
    """Test deleting a credential that doesn't exist"""
    ms = MattStash(path=str(temp_db))

    result = ms.delete("nonexistent")
    assert result is False


def test_list_versions_nonexistent_credential(temp_db: Path):
    """Test listing versions for a credential that doesn't exist"""
    ms = MattStash(path=str(temp_db))

    versions = ms.list_versions("nonexistent")
    assert versions == []
