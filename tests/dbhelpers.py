"""Test helpers for building databases with custom properties in a single (slow) KDF write."""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from pykeepass import PyKeePass

from mattstash import MattStash


def populate(db: Path, password: str, entries: List[Dict[str, Any]]) -> None:
    """Add ``entries`` to an existing database in one save.

    Each entry is ``{"title", "username", "password", "url", "notes", "props": {name: value}}``;
    only ``title`` is required. Titles are used verbatim (use ``name@0000000001`` for versions).
    """
    kp = PyKeePass(str(db), password=password)
    for spec in entries:
        entry = kp.add_entry(
            kp.root_group,
            title=spec["title"],
            username=spec.get("username", ""),
            password=spec.get("password", ""),
            url=spec.get("url", ""),
            notes=spec.get("notes", ""),
        )
        for name, value in spec.get("props", {}).items():
            entry.set_custom_property(name, value)
    kp.save()
    os.chmod(db, 0o600)


def create_db(
    path: Path,
    entries: List[Dict[str, Any]],
    password: str = "test-master-pw",  # noqa: S107
    sidecar: bool = True,
) -> Path:
    """Create a database at ``path`` (optionally with a sidecar) holding ``entries``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    MattStash.create(str(path), password=password, sidecar=sidecar)
    if entries:
        populate(path, password, entries)
    return path


def stored_password(db: Path, title: str, password: Optional[str] = None) -> Optional[str]:
    """Password/value of the latest version of ``title`` (simple secret or full credential)."""
    found = MattStash(path=str(db), password=password).get(title, show_password=True)
    if found is None:
        return None
    return found["value"] if isinstance(found, dict) else found.password
