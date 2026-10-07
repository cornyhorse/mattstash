"""
mattstash.version_manager
-------------------------
Handles versioning logic for credentials.
"""

from typing import List, Optional, Tuple

from pykeepass.entry import Entry

from .models.config import config


def parse_version_suffix(entry_title: Optional[str], base_title: str) -> Optional[int]:
    """Return N if ``entry_title`` is exactly ``<base_title>@<N>`` (ASCII digits), else None."""
    if not entry_title:
        return None
    prefix = f"{base_title}@"
    if not entry_title.startswith(prefix):
        return None
    suffix = entry_title[len(prefix) :]
    # str.isdigit() accepts unicode digits such as '\u00b2' that int() rejects or mis-parses.
    if suffix.isascii() and suffix.isdigit():
        return int(suffix)
    return None


class VersionManager:
    """Handles versioning logic for credentials."""

    def __init__(self, pad_width: Optional[int] = None):
        self.pad_width = pad_width or config.version_pad_width

    def format_version(self, version: int) -> str:
        """Format a version number with zero padding.

        Args:
            version: Integer version number to format

        Returns:
            Zero-padded version string (e.g., "0000000001")

        Example:
            >>> vm = VersionManager()
            >>> vm.format_version(42)
            '0000000042'
        """
        return str(version).zfill(self.pad_width)

    def parse_version(self, title: str) -> Tuple[str, Optional[int]]:
        """
        Parse a title to extract base name and version number.

        Returns:
            Tuple of (base_title, version_number)
            version_number is None if not versioned
        """
        if "@" not in title:
            return title, None

        parts = title.rsplit("@", 1)
        if len(parts) != 2:
            return title, None

        base_title, version_str = parts
        try:
            version = int(version_str)
            return base_title, version
        except ValueError:
            return title, None

    def get_versioned_title(self, base_title: str, version: int) -> str:
        """Create a versioned title.

        Args:
            base_title: Base credential name
            version: Version number to append

        Returns:
            Formatted versioned title (e.g., "api-key@0000000003")

        Example:
            >>> vm = VersionManager()
            >>> vm.get_versioned_title("api-key", 3)
            'api-key@0000000003'
        """
        return f"{base_title}@{self.format_version(version)}"

    def get_next_version(self, base_title: str, entries: List[Entry]) -> int:
        """Calculate the next version number for a base title.

        Scans all entries to find the highest version number for the given
        base title and returns the next sequential version.

        Args:
            base_title: Base credential name (without version suffix)
            entries: List of KeePass entries to scan

        Returns:
            Next available version number (max_existing + 1, or 1 if none exist)

        Example:
            >>> vm = VersionManager()
            >>> # If entries contain api-key@0000000001 and api-key@0000000003
            >>> vm.get_next_version("api-key", entries)
            4
        """
        max_version = 0

        for entry in entries:
            version = parse_version_suffix(entry.title, base_title)
            if version is not None:
                max_version = max(max_version, version)

        return max_version + 1

    def find_latest_version(self, base_title: str, entries: List[Entry]) -> Optional[Entry]:
        """Find the entry with the highest version for a base title."""
        candidates = []

        for entry in entries:
            version = parse_version_suffix(entry.title, base_title)
            if version is not None:
                candidates.append((version, entry))

        if not candidates:
            return None

        # Return entry with highest version
        return max(candidates, key=lambda x: x[0])[1]

    def get_all_versions(self, base_title: str, entries: List[Entry]) -> List[str]:
        """Get well-formed version strings for a base title, sorted ascending.

        Only zero-padded versions of the configured width are reported; entries such as
        ``name@123`` (wrong width) are ignored here.
        """
        versions = []
        for entry in entries:
            number = parse_version_suffix(entry.title, base_title)
            if number is not None and len(entry.title[len(base_title) + 1 :]) == self.pad_width:
                versions.append(self.format_version(number))
        return sorted(versions)
