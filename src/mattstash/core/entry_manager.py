"""
mattstash.core.entry_manager
----------------------------
Handles CRUD operations for KeePass entries.
"""

from typing import Optional, List, Dict, Union
from pykeepass import PyKeePass
from pykeepass.entry import Entry

from ..models.credential import Credential, CredentialResult
from ..version_manager import VersionManager
from ..models.config import config
from ..utils.logging_config import get_logger
from ..utils.validation import validate_credential_title, validate_username, validate_url, validate_notes

logger = get_logger(__name__)


class EntryManager:
    """Handles CRUD operations for KeePass entries."""

    def __init__(self, kp: PyKeePass):
        self.kp = kp
        self.version_manager = VersionManager()

    def _is_simple_secret(self, entry: Entry) -> bool:
        """
        A 'simple secret' mimics credstash semantics: only the password field is used.
        Consider it simple if username and url are empty/None and password is non-empty.
        Notes/comments are allowed and do not change this classification. Tags are ignored.
        """
        def _empty(v):
            return v is None or (isinstance(v, str) and v.strip() == "")

        try:
            # Treat entries with only password set (regardless of notes) as simple secrets
            return (not _empty(entry.password)) and _empty(entry.username) and _empty(entry.url)
        except Exception:
            return False

    def get_entry(self, title: str, show_password: bool = False, version: Optional[int] = None) -> Optional[CredentialResult]:
        """
        Fetch a KeePass entry by its Title (optionally versioned) and return a Credential payload.
        Returns None if the entry cannot be found.
        
        Returns:
            Union[Dict, Credential]: Either a simple secret dict or a full Credential object
            None: If entry not found
        """
        if version is not None:
            return self._get_versioned_entry(title, version, show_password)

        # No version specified: scan for versioned entries first
        versioned_entry = self._get_latest_versioned_entry(title, show_password)
        if versioned_entry:
            return versioned_entry

        # Fallback to unversioned
        return self._get_unversioned_entry(title, show_password)

    def _get_versioned_entry(self, title: str, version: int, show_password: bool) -> Optional[CredentialResult]:
        """Get a specific versioned entry."""
        entry_title = self.version_manager.get_versioned_title(title, version)
        entry = self.kp.find_entries(title=entry_title, first=True)

        if not entry:
            logger.info(f"Entry not found: {entry_title}")
            return None

        return self._format_entry_result(entry, title, str(version).zfill(config.version_pad_width), show_password)

    def _get_latest_versioned_entry(self, title: str, show_password: bool) -> Optional[CredentialResult]:
        """Get the latest versioned entry for a title."""
        prefix = f"{title}@"
        candidates = [e for e in self.kp.entries if e.title and e.title.startswith(prefix)]

        if not candidates:
            return None

        # Find max version
        def extract_ver(e):
            try:
                return int(e.title[len(prefix):])
            except Exception:
                return -1

        versioned_candidates = [(extract_ver(e), e) for e in candidates if extract_ver(e) >= 0]
        if not versioned_candidates:
            logger.info(f"No valid versioned entries found for {title}")
            return None

        max_ver, entry = max(versioned_candidates, key=lambda t: t[0])
        vstr = str(max_ver).zfill(config.version_pad_width)

        return self._format_entry_result(entry, title, vstr, show_password)

    def _get_unversioned_entry(self, title: str, show_password: bool) -> Optional[CredentialResult]:
        """Get an unversioned entry."""
        entry = self.kp.find_entries(title=title, first=True)
        if not entry:
            logger.info(f"Entry not found: {title}")
            return None

        return self._format_entry_result(entry, title, None, show_password)

    def _format_entry_result(self, entry: Entry, title: str, version: Optional[str], show_password: bool) -> CredentialResult:
        """Format an entry into the appropriate result format."""
        if self._is_simple_secret(entry):
            value = entry.password if show_password else ("*****" if entry.password else None)
            return {
                "name": title,
                "version": version,
                "value": value,
                "notes": entry.notes if entry.notes else None
            }

        return Credential(
            credential_name=title,
            username=entry.username,
            password=entry.password,
            url=entry.url,
            notes=entry.notes,
            tags=list(entry.tags or []),
            show_password=show_password,
        )

    def list_entries(self, show_password: bool = False) -> List[Credential]:
        """Return a list of Credential objects for all entries in the KeePass database."""
        creds = []
        for entry in self.kp.entries:
            creds.append(Credential(
                credential_name=entry.title,
                username=entry.username,
                password=entry.password,
                url=entry.url,
                notes=entry.notes,
                tags=list(entry.tags or []),
                show_password=show_password,
            ))
        return creds

    def put_entry(self, title: str, **kwargs) -> Optional[CredentialResult]:
        """
        Create or update an entry.

        Args:
            title: Entry title
            value: Simple secret value (stored in password field)
            username: Username for full credential
            password: Password for full credential
            url: URL for full credential
            notes: Notes/comments
            tags: List of tags
            version: Specific version number
            autoincrement: Whether to auto-increment version
        
        Raises:
            InvalidCredentialError: If inputs are invalid
        """
        # Validate inputs
        validate_credential_title(title)
        
        value = kwargs.get('value')
        username = kwargs.get('username')
        password = kwargs.get('password')
        url = kwargs.get('url')
        notes = kwargs.get('notes')
        tags = kwargs.get('tags')
        version = kwargs.get('version')
        autoincrement = kwargs.get('autoincrement', True)
        
        # Validate other fields
        validate_username(username)
        validate_url(url)
        validate_notes(notes)

        # Determine entry title (with versioning)
        entry_title, vstr = self._determine_entry_title(title, version, autoincrement)

        # Find or create entry
        entry = self.kp.find_entries(title=entry_title, first=True)
        if entry is None:
            entry = self.kp.add_entry(self.kp.root_group, title=entry_title,
                                    username="", password="", url="", notes="")

        # Decide mode: simple vs full credential
        simple_mode = (value is not None and username is None and password is None
                      and url is None and (tags is None or len(tags) == 0))

        if simple_mode:
            return self._put_simple_entry(entry, title, value, notes, tags, vstr)
        else:
            return self._put_full_entry(entry, title, username, password, url, notes, tags)

    def _determine_entry_title(self, title: str, version: Optional[int], autoincrement: bool) -> tuple[str, Optional[str]]:
        """Determine the entry title and version string."""
        if version is not None or autoincrement:
            if version is None and autoincrement:
                # Find next version
                next_version = self.version_manager.get_next_version(title, list(self.kp.entries))
                vstr = self.version_manager.format_version(next_version)
            elif version is not None:
                vstr = self.version_manager.format_version(version)
            else:
                vstr = self.version_manager.format_version(1)

            entry_title = self.version_manager.get_versioned_title(title, int(vstr))
            return entry_title, vstr

        return title, None

    def _put_simple_entry(self, entry: Entry, title: str, value: str, notes: Optional[str],
                         tags: Optional[List[str]], vstr: Optional[str]) -> Dict:
        """Handle simple secret entry creation/update."""
        entry.username = ""
        entry.url = ""
        if notes is not None:
            entry.notes = notes
        entry.password = value

        if tags is not None:
            self._set_entry_tags(entry, tags)

        self.kp.save()

        return {
            "name": title,
            "version": vstr,
            "value": "*****" if (value is not None) else None,
            "notes": entry.notes if entry.notes else None,
        }

    def _put_full_entry(self, entry: Entry, title: str, username: Optional[str],
                       password: Optional[str], url: Optional[str], notes: Optional[str],
                       tags: Optional[List[str]]) -> Credential:
        """Handle full credential entry creation/update."""
        if username is not None:
            entry.username = username
        if password is not None:
            entry.password = password
        if url is not None:
            entry.url = url
        if notes is not None:
            entry.notes = notes
        if tags is not None:
            self._set_entry_tags(entry, tags)

        self.kp.save()

        return Credential(
            credential_name=title,
            username=entry.username,
            password=entry.password,
            url=entry.url,
            notes=entry.notes,
            tags=list(entry.tags or []),
            show_password=False,
        )

    def _set_entry_tags(self, entry: Entry, tags: List[str]):
        """Set tags on an entry, handling different PyKeePass versions."""
        try:
            entry.tags = set(tags)
        except Exception:
            # Fallback for older versions
            for t in list(entry.tags or []):
                try:
                    entry.remove_tag(t)
                except Exception:
                    pass
            for t in tags:
                try:
                    entry.add_tag(t)
                except Exception:
                    pass

    def list_versions(self, title: str) -> List[str]:
        """List all versions (zero-padded strings) for a given title, sorted ascending."""
        prefix = f"{title}@"
        versions = []

        for entry in self.kp.entries:
            if entry.title and entry.title.startswith(prefix):
                vstr = entry.title[len(prefix):]
                if vstr.isdigit() and len(vstr) == config.version_pad_width:
                    versions.append(vstr)

        versions.sort()
        return versions

    def delete_entry(self, title: str) -> bool:
        """Delete an entry by title. Returns True if deleted, False otherwise."""
        entry = self.kp.find_entries(title=title, first=True)
        if not entry:
            logger.info(f"Entry not found: {title}")
            return False

        try:
            self.kp.delete_entry(entry)
            self.kp.save()
            return True
        except Exception as ex:
            logger.error(f"Failed to delete entry '{title}': {ex}")
            return False
