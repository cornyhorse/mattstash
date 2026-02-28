"""
Test the version manager module functionality.
"""

from unittest.mock import Mock

from pykeepass.entry import Entry

from mattstash.version_manager import VersionManager


def test_format_version():
    """Test version formatting with zero padding"""
    vm = VersionManager(pad_width=5)

    assert vm.format_version(1) == "00001"
    assert vm.format_version(123) == "00123"
    assert vm.format_version(99999) == "99999"


def test_parse_version():
    """Test parsing titles to extract version information"""
    vm = VersionManager()

    # Versioned titles
    base, version = vm.parse_version("myapp@0000000001")
    assert base == "myapp"
    assert version == 1

    base, version = vm.parse_version("service@0000000123")
    assert base == "service"
    assert version == 123

    # Non-versioned titles
    base, version = vm.parse_version("simple-title")
    assert base == "simple-title"
    assert version is None

    # Invalid version format
    base, version = vm.parse_version("invalid@abc")
    assert base == "invalid@abc"
    assert version is None


def test_get_versioned_title():
    """Test creating versioned titles"""
    vm = VersionManager(pad_width=8)

    title = vm.get_versioned_title("myapp", 42)
    assert title == "myapp@00000042"


def test_get_next_version():
    """Test calculating next version number"""
    vm = VersionManager(pad_width=10)

    # Mock entries
    entries = []

    # Create mock entries with versions
    for version in [1, 3, 7, 2]:
        entry = Mock(spec=Entry)
        entry.title = f"myapp@{str(version).zfill(10)}"
        entries.append(entry)

    # Add non-matching entry
    other_entry = Mock(spec=Entry)
    other_entry.title = "other@0000000001"
    entries.append(other_entry)

    # Add entry with invalid version
    invalid_entry = Mock(spec=Entry)
    invalid_entry.title = "myapp@invalid"
    entries.append(invalid_entry)

    next_version = vm.get_next_version("myapp", entries)
    assert next_version == 8  # Max version was 7


def test_get_next_version_no_existing():
    """Test getting next version when no versions exist"""
    vm = VersionManager()

    entries = []
    next_version = vm.get_next_version("newapp", entries)
    assert next_version == 1


def test_find_latest_version():
    """Test finding the entry with the highest version"""
    vm = VersionManager(pad_width=10)

    entries = []

    # Create mock entries
    for version in [1, 5, 3]:
        entry = Mock(spec=Entry)
        entry.title = f"myapp@{str(version).zfill(10)}"
        entries.append(entry)

    latest = vm.find_latest_version("myapp", entries)
    assert latest is not None
    assert latest.title == "myapp@0000000005"


def test_find_latest_version_no_match():
    """Test finding latest version when no matching entries exist"""
    vm = VersionManager()

    entries = []
    entry = Mock(spec=Entry)
    entry.title = "different@0000000001"
    entries.append(entry)

    latest = vm.find_latest_version("myapp", entries)
    assert latest is None


def test_get_all_versions():
    """Test getting all version strings for a title"""
    vm = VersionManager(pad_width=10)

    entries = []

    # Create entries with different versions
    for version in [5, 1, 3, 2]:
        entry = Mock(spec=Entry)
        entry.title = f"myapp@{str(version).zfill(10)}"
        entries.append(entry)

    # Add entry with wrong pad width (should be ignored)
    wrong_pad = Mock(spec=Entry)
    wrong_pad.title = "myapp@123"
    entries.append(wrong_pad)

    # Add non-matching entry
    other = Mock(spec=Entry)
    other.title = "other@0000000001"
    entries.append(other)

    versions = vm.get_all_versions("myapp", entries)
    expected = ["0000000001", "0000000002", "0000000003", "0000000005"]
    assert versions == expected


def test_custom_pad_width():
    """Test version manager with custom pad width"""
    vm = VersionManager(pad_width=5)

    assert vm.pad_width == 5
    assert vm.format_version(42) == "00042"

    title = vm.get_versioned_title("test", 1)
    assert title == "test@00001"
