"""
mattstash.version_manager
-------------------------
Handles versioning logic for credentials.
"""

import re
from typing import Optional, Tuple, List
from pykeepass.entry import Entry

from .config import config


class VersionManager:
    """Handles versioning logic for credentials."""

    def __init__(self, pad_width: int = None):
        self.pad_width = pad_width or config.version_pad_width

    def format_version(self, version: int) -> str:
        """Format a version number with zero padding."""
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
        """Create a versioned title."""
        return f"{base_title}@{self.format_version(version)}"

    def get_next_version(self, base_title: str, entries: List[Entry]) -> int:
        """Calculate the next version number for a base title."""
        prefix = f"{base_title}@"
        max_version = 0

        for entry in entries:
            if entry.title and entry.title.startswith(prefix):
                version_str = entry.title[len(prefix):]
                try:
                    version = int(version_str)
                    max_version = max(max_version, version)
                except ValueError:
                    continue

        return max_version + 1

    def find_latest_version(self, base_title: str, entries: List[Entry]) -> Optional[Entry]:
        """Find the entry with the highest version for a base title."""
        prefix = f"{base_title}@"
        candidates = []

        for entry in entries:
            if entry.title and entry.title.startswith(prefix):
                version_str = entry.title[len(prefix):]
                try:
                    version = int(version_str)
                    candidates.append((version, entry))
                except ValueError:
                    continue

        if not candidates:
            return None

        # Return entry with highest version
        return max(candidates, key=lambda x: x[0])[1]

    def get_all_versions(self, base_title: str, entries: List[Entry]) -> List[str]:
        """Get all version strings for a base title, sorted ascending."""
        prefix = f"{base_title}@"
        versions = []

        for entry in entries:
            if entry.title and entry.title.startswith(prefix):
                version_str = entry.title[len(prefix):]
                if version_str.isdigit() and len(version_str) == self.pad_width:
                    versions.append(version_str)

        return sorted(versions)
