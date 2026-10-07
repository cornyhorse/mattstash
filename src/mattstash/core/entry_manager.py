"""
mattstash.core.entry_manager
----------------------------
Handles CRUD operations for KeePass entries.

All title lookups are exact string comparisons done in Python. pykeepass' own
``find_entries(title=...)`` interpolates the title into an XPath expression, so a title
containing quotes could match (or delete) unrelated entries.
"""

import contextlib
from collections.abc import Callable
from typing import Any, Dict, List, Optional

from pykeepass import PyKeePass
from pykeepass.entry import Entry

from ..models.credential import Credential, CredentialResult
from ..utils.exceptions import InvalidCredentialError
from ..utils.logging_config import get_logger
from ..utils.validation import validate_credential_title, validate_notes, validate_url, validate_username
from ..version_manager import VersionManager, parse_version_suffix

logger = get_logger(__name__)


class EntryManager:
    """Handles CRUD operations for KeePass entries."""

    def __init__(self, kp: PyKeePass, save_callback: Optional[Callable[[], None]] = None) -> None:
        self.kp = kp
        self._save_callback = save_callback
        self.version_manager = VersionManager()

    def _save(self) -> None:
        """Save changes via the store callback if available, otherwise directly."""
        if self._save_callback is not None:
            self._save_callback()
        else:
            self.kp.save()

    # ---- lookup -----------------------------------------------------------

    def _scan(self, title: str) -> tuple[Optional[Entry], list[tuple[int, Entry]]]:
        """Single pass over the database: (exact-title entry, [(version, entry), ...])."""
        exact: Optional[Entry] = None
        versions: list[tuple[int, Entry]] = []
        for entry in self.kp.entries:
            entry_title = entry.title
            if entry_title is None:
                continue
            if entry_title == title:
                if exact is None:
                    exact = entry
                continue
            number = parse_version_suffix(entry_title, title)
            if number is not None:
                versions.append((number, entry))
        return exact, versions

    def find_entry(self, title: str) -> Optional[Entry]:
        """Return the entry whose title is exactly ``title`` (no version resolution)."""
        return next((e for e in self.kp.entries if e.title == title), None)

    def resolve_entry(self, title: str, version: Optional[int] = None) -> Optional[tuple[Entry, Optional[str]]]:
        """Resolve ``title`` (and optional version) to ``(entry, version_string)``.

        Without ``version``: the highest versioned entry wins; an unversioned entry is used
        only when no versions exist. With ``version``: that exact version, else None.
        """
        exact, versions = self._scan(title)
        if version is not None:
            for number, entry in versions:
                if number == version:
                    return entry, self.version_manager.format_version(number)
            return None
        if versions:
            number, entry = max(versions, key=lambda t: t[0])
            return entry, self.version_manager.format_version(number)
        if exact is not None:
            return exact, None
        return None

    def _new_entry(self, title: str) -> Entry:
        """Create an empty entry in the root group.

        ``PyKeePass.add_entry`` runs its own ``find_entries(title=...)`` duplicate check, which
        builds an XPath from the title (breaks on a double quote). We have already done an exact
        lookup, so build the entry directly, as ``add_entry`` itself does after its check.
        """
        entry = Entry(title=title, username="", password="", url="", notes="", kp=self.kp)
        self.kp.root_group.append(entry)
        return entry

    @staticmethod
    def custom_property(entry: Entry, name: str) -> Optional[str]:
        """Read a custom property without going through pykeepass' XPath-based lookup."""
        value = entry.custom_properties.get(name)
        return value if isinstance(value, str) else None

    def _is_simple_secret(self, entry: Entry) -> bool:
        """
        A 'simple secret' mimics credstash semantics: only the password field is used.
        Consider it simple if username and url are empty/None and password is non-empty.
        Notes/comments are allowed and do not change this classification. Tags are ignored.
        """

        def _empty(v: Optional[str]) -> bool:
            return v is None or (isinstance(v, str) and v.strip() == "")

        try:
            # Treat entries with only password set (regardless of notes) as simple secrets
            return (not _empty(entry.password)) and _empty(entry.username) and _empty(entry.url)
        except Exception:
            return False

    # ---- read -------------------------------------------------------------

    def get_entry(
        self, title: str, show_password: bool = False, version: Optional[int] = None
    ) -> Optional[CredentialResult]:
        """
        Fetch a KeePass entry by its Title (optionally versioned) and return a Credential payload.
        Returns None if the entry cannot be found.

        Returns:
            Union[Dict, Credential]: Either a simple secret dict or a full Credential object
            None: If entry not found
        """
        resolved = self.resolve_entry(title, version)
        if resolved is None:
            logger.info(f"Entry not found: {title}" + (f" (version {version})" if version is not None else ""))
            return None
        entry, vstr = resolved
        return self._format_entry_result(entry, title, vstr, show_password)

    def _get_versioned_entry(self, title: str, version: int, show_password: bool) -> Optional[CredentialResult]:
        """Get a specific versioned entry."""
        return self.get_entry(title, show_password, version)

    def _get_latest_versioned_entry(self, title: str, show_password: bool) -> Optional[CredentialResult]:
        """Get the latest versioned entry for a title (None if the title has no versions)."""
        _exact, versions = self._scan(title)
        if not versions:
            return None
        number, entry = max(versions, key=lambda t: t[0])
        return self._format_entry_result(entry, title, self.version_manager.format_version(number), show_password)

    def _get_unversioned_entry(self, title: str, show_password: bool) -> Optional[CredentialResult]:
        """Get an unversioned entry."""
        entry = self.find_entry(title)
        if entry is None:
            logger.info(f"Entry not found: {title}")
            return None
        return self._format_entry_result(entry, title, None, show_password)

    def _format_entry_result(
        self, entry: Entry, title: str, version: Optional[str], show_password: bool
    ) -> CredentialResult:
        """Format an entry into the appropriate result format."""
        if self._is_simple_secret(entry):
            value = entry.password if show_password else ("*****" if entry.password else None)
            return {"name": title, "version": version, "value": value, "notes": entry.notes if entry.notes else None}

        return Credential(
            credential_name=title,
            username=entry.username,
            password=entry.password,
            url=entry.url,
            notes=entry.notes,
            tags=list(entry.tags or []),
            show_password=show_password,
            version=version,
        )

    def list_entries(self, show_password: bool = False, latest_only: bool = False) -> List[Credential]:
        """Return a list of Credential objects for entries in the KeePass database.

        By default every stored entry is returned, versions included (``name@0000000001``).
        With ``latest_only`` versions are collapsed: each base name appears once, as its
        latest version, with ``credential_name`` set to the base name and ``version`` filled in.
        """
        creds: List[Credential] = []
        if not latest_only:
            for entry in self.kp.entries:
                creds.append(self._credential_from_entry(entry, entry.title, None, show_password))
            return creds

        # Group "<base>@<digits>" entries by base name; keep the highest version of each.
        best: Dict[str, tuple[int, Entry]] = {}
        plain: List[Entry] = []
        for entry in self.kp.entries:
            title = entry.title or ""
            base, sep, suffix = title.rpartition("@")
            if sep and base and suffix.isascii() and suffix.isdigit():
                number = int(suffix)
                if base not in best or number > best[base][0]:
                    best[base] = (number, entry)
            else:
                plain.append(entry)
        for entry in plain:
            if entry.title not in best:
                creds.append(self._credential_from_entry(entry, entry.title, None, show_password))
        for base, (number, entry) in best.items():
            creds.append(
                self._credential_from_entry(entry, base, self.version_manager.format_version(number), show_password)
            )
        creds.sort(key=lambda c: c.credential_name)
        return creds

    @staticmethod
    def _credential_from_entry(
        entry: Entry, name: Optional[str], version: Optional[str], show_password: bool
    ) -> Credential:
        return Credential(
            credential_name=name or "",
            username=entry.username,
            password=entry.password,
            url=entry.url,
            notes=entry.notes,
            tags=list(entry.tags or []),
            show_password=show_password,
            version=version,
        )

    # ---- write ------------------------------------------------------------

    def put_entry(self, title: str, **kwargs: Any) -> Optional[CredentialResult]:
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

        value = kwargs.get("value")
        username = kwargs.get("username")
        password = kwargs.get("password")
        url = kwargs.get("url")
        notes = kwargs.get("notes")
        tags = kwargs.get("tags")
        version = kwargs.get("version")
        autoincrement = kwargs.get("autoincrement", True)

        # Validate other fields
        validate_username(username)
        validate_url(url)
        validate_notes(notes)
        if version is not None and (not isinstance(version, int) or isinstance(version, bool) or version < 0):
            raise InvalidCredentialError("Version must be a non-negative integer")

        # Determine target entry (and its version) from a single scan of the database
        exact, versions = self._scan(title)
        entry: Optional[Entry]
        if version is not None:
            vstr: Optional[str] = self.version_manager.format_version(version)
            entry = next((e for n, e in versions if n == version), None)
            entry_title = self.version_manager.get_versioned_title(title, version)
        elif autoincrement:
            next_version = max((n for n, _ in versions), default=0) + 1
            vstr = self.version_manager.format_version(next_version)
            entry = None
            entry_title = self.version_manager.get_versioned_title(title, next_version)
        else:
            vstr = None
            entry = exact
            entry_title = title

        if entry is None:
            entry = self._new_entry(entry_title)

        # Decide mode: simple vs full credential
        simple_mode = (
            value is not None
            and username is None
            and password is None
            and url is None
            and (tags is None or len(tags) == 0)
        )

        if simple_mode:
            return self._put_simple_entry(entry, title, value, notes, tags, vstr)
        else:
            return self._put_full_entry(entry, title, username, password, url, notes, tags, vstr)

    def _determine_entry_title(
        self, title: str, version: Optional[int], autoincrement: bool
    ) -> tuple[str, Optional[str]]:
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

    def _put_simple_entry(
        self,
        entry: Entry,
        title: str,
        value: Optional[str],
        notes: Optional[str],
        tags: Optional[List[str]],
        vstr: Optional[str],
    ) -> Dict[str, Any]:
        """Handle simple secret entry creation/update."""
        entry.username = ""
        entry.url = ""
        if notes is not None:
            entry.notes = notes
        entry.password = value or ""

        if tags is not None:
            self._set_entry_tags(entry, tags)

        self._save()

        return {
            "name": title,
            "version": vstr,
            "value": "*****" if (value is not None) else None,
            "notes": entry.notes if entry.notes else None,
        }

    def _put_full_entry(
        self,
        entry: Entry,
        title: str,
        username: Optional[str],
        password: Optional[str],
        url: Optional[str],
        notes: Optional[str],
        tags: Optional[List[str]],
        vstr: Optional[str] = None,
    ) -> Credential:
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

        self._save()

        return Credential(
            credential_name=title,
            username=entry.username,
            password=entry.password,
            url=entry.url,
            notes=entry.notes,
            tags=list(entry.tags or []),
            show_password=False,
            version=vstr,
        )

    def _set_entry_tags(self, entry: Entry, tags: List[str]) -> None:
        """Set tags on an entry, handling different PyKeePass versions."""
        try:
            entry.tags = set(tags)
        except Exception:
            # Fallback for older versions
            for t in list(entry.tags or []):
                with contextlib.suppress(Exception):
                    entry.remove_tag(t)
            for t in tags:
                with contextlib.suppress(Exception):
                    entry.add_tag(t)

    # ---- versions / delete --------------------------------------------------

    def list_versions(self, title: str) -> List[str]:
        """List all versions (zero-padded strings) for a given title, sorted ascending."""
        _exact, versions = self._scan(title)
        return [self.version_manager.format_version(n) for n in sorted(n for n, _ in versions)]

    def delete_entry(self, title: str, version: Optional[int] = None) -> bool:
        """Delete an entry. Returns True if something was deleted, False if nothing matched.

        Without ``version`` the unversioned entry *and every* ``title@<version>`` entry are
        removed, so a deleted secret can no longer be read through an older version.
        With ``version`` only that version is removed.

        Errors (including save failures) propagate; callers decide how to recover.
        """
        exact, versions = self._scan(title)
        if version is not None:
            targets = [e for n, e in versions if n == version]
        else:
            targets = ([exact] if exact is not None else []) + [e for _n, e in versions]
        if not targets:
            logger.info(f"Entry not found: {title}")
            return False
        for entry in targets:
            self.kp.delete_entry(entry)
        self._save()
        return True

    def prune_versions(self, title: str, keep: int) -> List[str]:
        """Delete all but the newest ``keep`` versions of ``title``. Returns deleted version strings."""
        if keep < 1:
            raise InvalidCredentialError("keep must be at least 1")
        _exact, versions = self._scan(title)
        versions.sort(key=lambda t: t[0])
        doomed = versions[:-keep] if len(versions) > keep else []
        if not doomed:
            return []
        for _number, entry in doomed:
            self.kp.delete_entry(entry)
        self._save()
        return [self.version_manager.format_version(n) for n, _ in doomed]

    def get_entry_with_custom_properties(self, title: str) -> Optional[tuple[CredentialResult, Entry]]:
        """
        Fetch an entry and return both the formatted result and the raw Entry object.
        This allows callers to access custom properties without re-opening the database.
        Version resolution is identical to :meth:`get_entry` (latest version wins).

        Returns:
            Tuple of (CredentialResult, Entry) if found, None if not found
        """
        resolved = self.resolve_entry(title)
        if resolved is None:
            return None
        entry, vstr = resolved
        return (self._format_entry_result(entry, title, vstr, True), entry)
