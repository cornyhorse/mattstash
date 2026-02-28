"""
Test coverage for database URL parsing and S3 functionality.
"""

from pathlib import Path

import pytest

from mattstash import MattStash
from mattstash.builders.s3_client import _ensure_scheme


def test_ensure_scheme_with_none():
    """Test _ensure_scheme with None input"""
    result = _ensure_scheme(None)
    assert result is None


def test_ensure_scheme_with_empty_string():
    """Test _ensure_scheme with empty string"""
    result = _ensure_scheme("")
    assert result == ""


def test_ensure_scheme_with_http():
    """Test _ensure_scheme with http:// URL"""
    result = _ensure_scheme("http://example.com")
    assert result == "http://example.com"


def test_ensure_scheme_with_https():
    """Test _ensure_scheme with https:// URL"""
    result = _ensure_scheme("https://example.com")
    assert result == "https://example.com"


def test_ensure_scheme_without_scheme():
    """Test _ensure_scheme without scheme - should add https://"""
    result = _ensure_scheme("example.com")
    assert result == "https://example.com"


def test_parse_host_port_empty_endpoint(temp_db: Path):
    """Test _parse_host_port with empty endpoint"""
    ms = MattStash(path=str(temp_db))

    with pytest.raises(ValueError, match="Empty database endpoint URL"):
        ms._parse_host_port("")

    with pytest.raises(ValueError, match="Empty database endpoint URL"):
        ms._parse_host_port(None)


def test_parse_host_port_no_port_simple(temp_db: Path):
    """Test _parse_host_port with host but no port"""
    ms = MattStash(path=str(temp_db))

    with pytest.raises(ValueError, match="must include a port"):
        ms._parse_host_port("localhost")


def test_parse_host_port_invalid_port_simple(temp_db: Path):
    """Test _parse_host_port with invalid port in simple format"""
    ms = MattStash(path=str(temp_db))

    with pytest.raises(ValueError, match="Invalid database port"):
        ms._parse_host_port("localhost:abc")


def test_parse_host_port_valid_simple(temp_db: Path):
    """Test _parse_host_port with valid simple format"""
    ms = MattStash(path=str(temp_db))

    host, port = ms._parse_host_port("localhost:5432")
    assert host == "localhost"
    assert port == 5432


def test_parse_host_port_url_no_port(temp_db: Path):
    """Test _parse_host_port with URL format but no port"""
    ms = MattStash(path=str(temp_db))

    with pytest.raises(ValueError, match="must include a port"):
        ms._parse_host_port("postgres://localhost/db")


def test_parse_host_port_url_invalid_port(temp_db: Path):
    """Test _parse_host_port with URL format but invalid port"""
    ms = MattStash(path=str(temp_db))

    with pytest.raises(ValueError, match="Invalid database port"):
        ms._parse_host_port("postgres://localhost:abc/db")


def test_parse_host_port_url_with_auth(temp_db: Path):
    """Test _parse_host_port with URL format including auth"""
    ms = MattStash(path=str(temp_db))

    host, port = ms._parse_host_port("postgres://user:pass@localhost:5432/db")
    assert host == "localhost"
    assert port == 5432


def test_parse_host_port_url_simple(temp_db: Path):
    """Test _parse_host_port with simple URL format"""
    ms = MattStash(path=str(temp_db))

    host, port = ms._parse_host_port("postgres://localhost:5432/db")
    assert host == "localhost"
    assert port == 5432


@pytest.fixture()
def temp_db(tmp_path: Path) -> Path:
    """Create an isolated directory for each test to hold DB + sidecar."""
    d = tmp_path / "mattstash"
    d.mkdir()
    return d / "test.kdbx"
