"""
Tests for database reload functionality: CredentialStore, MattStash, and server integration.
"""

import time
from pathlib import Path
from unittest.mock import patch

import pytest
from pykeepass import PyKeePass

from mattstash import MattStash
from mattstash.credential_store import CredentialStore


@pytest.fixture()
def temp_db(tmp_path: Path) -> Path:
    """Create an isolated directory for each test to hold DB + sidecar."""
    d = tmp_path / "mattstash"
    d.mkdir()
    return d / "test.kdbx"


# ---------------------------------------------------------------------------
# CredentialStore.reload / has_file_changed
# ---------------------------------------------------------------------------


class TestCredentialStoreReload:
    """Tests for CredentialStore reload and file change detection."""

    def test_has_file_changed_false_after_open(self, temp_db: Path):
        """After opening, has_file_changed should be False."""
        ms = MattStash(path=str(temp_db))
        ms._ensure_initialized()
        store = ms._credential_store
        assert store is not None
        assert store.has_file_changed() is False

    def test_has_file_changed_true_after_external_write(self, temp_db: Path):
        """If the file is modified externally, has_file_changed should be True."""
        ms = MattStash(path=str(temp_db))
        ms._ensure_initialized()
        store = ms._credential_store
        assert store is not None

        # Simulate external modification by opening kdbx and saving it directly
        kp = PyKeePass(str(temp_db), password=ms.password)
        kp.add_entry(kp.root_group, title="ext_entry", username="u", password="p")
        # Ensure mtime actually changes (filesystem granularity)
        time.sleep(0.05)
        kp.save()

        assert store.has_file_changed() is True

    def test_has_file_changed_false_after_save(self, temp_db: Path):
        """After our own save, has_file_changed should be False."""
        ms = MattStash(path=str(temp_db))
        result = ms.put("my-key", value="my-val")
        assert result is not None

        store = ms._credential_store
        assert store is not None
        assert store.has_file_changed() is False

    def test_has_file_changed_nonexistent_db(self):
        """has_file_changed returns False if the file doesn't exist."""
        store = CredentialStore("/nonexistent/db.kdbx", "pw")
        assert store.has_file_changed() is False

    def test_reload_reopens_database(self, temp_db: Path):
        """reload() should close and reopen the database from disk."""
        ms = MattStash(path=str(temp_db))
        ms._ensure_initialized()
        store = ms._credential_store
        assert store is not None

        old_kp = store._kp
        new_kp = store.reload()

        # Should be a new instance
        assert new_kp is not old_kp
        assert new_kp is store._kp

    def test_reload_picks_up_external_entries(self, temp_db: Path):
        """After an external write, reload should make the new entry visible."""
        ms = MattStash(path=str(temp_db))
        ms._ensure_initialized()
        store = ms._credential_store
        assert store is not None

        # External write
        kp_ext = PyKeePass(str(temp_db), password=ms.password)
        kp_ext.add_entry(kp_ext.root_group, title="ext_secret", username="", password="external-val")
        kp_ext.save()

        # Before reload: not visible in the old kp instance
        old_entry = store._kp.find_entries(title="ext_secret", first=True)
        assert old_entry is None

        # Reload
        store.reload()

        # After reload: visible
        new_entry = store._kp.find_entries(title="ext_secret", first=True)
        assert new_entry is not None
        assert new_entry.password == "external-val"


# ---------------------------------------------------------------------------
# MattStash.reload / reload_if_changed
# ---------------------------------------------------------------------------


class TestMattStashReload:
    """Tests for MattStash reload and reload_if_changed."""

    def test_reload_returns_true(self, temp_db: Path):
        """reload() should return True on success."""
        ms = MattStash(path=str(temp_db))
        ms._ensure_initialized()
        assert ms.reload() is True

    def test_reload_before_init(self, temp_db: Path):
        """reload() before initialization should perform init."""
        ms = MattStash(path=str(temp_db))
        # Not yet initialized
        assert ms._credential_store is None
        result = ms.reload()
        assert result is True
        assert ms._credential_store is not None

    def test_reload_if_changed_no_change(self, temp_db: Path):
        """reload_if_changed returns False when nothing changed."""
        ms = MattStash(path=str(temp_db))
        ms._ensure_initialized()
        assert ms.reload_if_changed() is False

    def test_reload_if_changed_after_external_write(self, temp_db: Path):
        """reload_if_changed returns True and reloads after external change."""
        ms = MattStash(path=str(temp_db))
        ms._ensure_initialized()

        # External write
        kp_ext = PyKeePass(str(temp_db), password=ms.password)
        kp_ext.add_entry(kp_ext.root_group, title="ext_val", username="", password="xyz")
        time.sleep(0.05)
        kp_ext.save()

        assert ms.reload_if_changed() is True

        # Verify the entry is now visible
        result = ms.get("ext_val", show_password=True)
        assert result is not None

    def test_reload_if_changed_not_initialized(self, temp_db: Path):
        """reload_if_changed returns False when not initialized."""
        ms = MattStash(path=str(temp_db))
        assert ms.reload_if_changed() is False

    def test_reload_recreates_entry_manager(self, temp_db: Path):
        """reload() should create a new EntryManager with the new kp."""
        ms = MattStash(path=str(temp_db))
        ms._ensure_initialized()
        old_em = ms._entry_manager

        ms.reload()
        assert ms._entry_manager is not old_em

    def test_reload_failure_returns_false(self, temp_db: Path):
        """reload() returns False when the reload raises an error."""
        ms = MattStash(path=str(temp_db))
        ms._ensure_initialized()

        with patch.object(ms._credential_store, "reload", side_effect=Exception("disk error")):
            assert ms.reload() is False
