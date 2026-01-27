"""
Tests for connection caching functionality.
"""

import time
import unittest
from unittest.mock import MagicMock, patch, Mock
from pykeepass.entry import Entry

from mattstash.credential_store import CredentialStore


class TestConnectionCaching(unittest.TestCase):
    """Test connection caching with TTL."""

    def setUp(self):
        """Set up test fixtures."""
        self.db_path = "/fake/db.kdbx"
        self.password = "test_password"

    @patch("mattstash.credential_store.PyKeePass")
    @patch("mattstash.credential_store.os.path.exists", return_value=True)
    def test_cache_disabled_by_default(self, mock_exists, mock_pykeepass):
        """Test that caching is disabled by default."""
        store = CredentialStore(self.db_path, self.password)
        self.assertFalse(store.cache_enabled)
        self.assertEqual(store._entry_cache, {})

    @patch("mattstash.credential_store.PyKeePass")
    @patch("mattstash.credential_store.os.path.exists", return_value=True)
    def test_cache_can_be_enabled(self, mock_exists, mock_pykeepass):
        """Test that caching can be enabled explicitly."""
        store = CredentialStore(self.db_path, self.password, cache_enabled=True)
        self.assertTrue(store.cache_enabled)

    @patch("mattstash.credential_store.PyKeePass")
    @patch("mattstash.credential_store.os.path.exists", return_value=True)
    def test_cache_ttl_default(self, mock_exists, mock_pykeepass):
        """Test default cache TTL."""
        store = CredentialStore(self.db_path, self.password, cache_enabled=True)
        self.assertEqual(store.cache_ttl, 300)  # 5 minutes

    @patch("mattstash.credential_store.PyKeePass")
    @patch("mattstash.credential_store.os.path.exists", return_value=True)
    def test_cache_ttl_custom(self, mock_exists, mock_pykeepass):
        """Test custom cache TTL."""
        store = CredentialStore(self.db_path, self.password, cache_enabled=True, cache_ttl=60)
        self.assertEqual(store.cache_ttl, 60)

    @patch("mattstash.credential_store.PyKeePass")
    @patch("mattstash.credential_store.os.path.exists", return_value=True)
    def test_entry_caching_on_find(self, mock_exists, mock_pykeepass):
        """Test that entries are cached when found."""
        # Mock entry
        mock_entry = Mock(spec=Entry)
        mock_entry.title = "test-cred"
        mock_entry.password = "secret"
        
        # Mock KeePass instance
        mock_kp_instance = MagicMock()
        mock_kp_instance.find_entries.return_value = mock_entry
        mock_pykeepass.return_value = mock_kp_instance
        
        # Create store with caching enabled
        store = CredentialStore(self.db_path, self.password, cache_enabled=True)
        
        # First lookup - should hit database
        result1 = store.find_entry_by_title("test-cred")
        self.assertEqual(result1, mock_entry)
        self.assertEqual(mock_kp_instance.find_entries.call_count, 1)
        
        # Entry should be in cache
        self.assertIn("test-cred", store._entry_cache)
        self.assertIn("test-cred", store._cache_timestamps)
        
        # Second lookup - should hit cache
        result2 = store.find_entry_by_title("test-cred")
        self.assertEqual(result2, mock_entry)
        # Should not call find_entries again
        self.assertEqual(mock_kp_instance.find_entries.call_count, 1)

    @patch("mattstash.credential_store.PyKeePass")
    @patch("mattstash.credential_store.os.path.exists", return_value=True)
    def test_cache_expiration(self, mock_exists, mock_pykeepass):
        """Test that cache entries expire after TTL."""
        # Mock entry
        mock_entry = Mock(spec=Entry)
        mock_entry.title = "test-cred"
        
        # Mock KeePass instance
        mock_kp_instance = MagicMock()
        mock_kp_instance.find_entries.return_value = mock_entry
        mock_pykeepass.return_value = mock_kp_instance
        
        # Create store with short TTL
        store = CredentialStore(self.db_path, self.password, cache_enabled=True, cache_ttl=1)
        
        # First lookup
        result1 = store.find_entry_by_title("test-cred")
        self.assertEqual(result1, mock_entry)
        self.assertEqual(mock_kp_instance.find_entries.call_count, 1)
        
        # Wait for cache to expire
        time.sleep(1.1)
        
        # Second lookup - should hit database again
        result2 = store.find_entry_by_title("test-cred")
        self.assertEqual(result2, mock_entry)
        self.assertEqual(mock_kp_instance.find_entries.call_count, 2)
        
        # Cache should have been cleared and repopulated
        self.assertIn("test-cred", store._entry_cache)

    @patch("mattstash.credential_store.PyKeePass")
    @patch("mattstash.credential_store.os.path.exists", return_value=True)
    def test_cache_invalidated_on_save(self, mock_exists, mock_pykeepass):
        """Test that cache is cleared when database is saved."""
        # Mock entry
        mock_entry = Mock(spec=Entry)
        mock_entry.title = "test-cred"
        
        # Mock KeePass instance
        mock_kp_instance = MagicMock()
        mock_kp_instance.find_entries.return_value = mock_entry
        mock_pykeepass.return_value = mock_kp_instance
        
        # Create store with caching
        store = CredentialStore(self.db_path, self.password, cache_enabled=True)
        
        # Populate cache
        store.find_entry_by_title("test-cred")
        self.assertIn("test-cred", store._entry_cache)
        
        # Save database (should clear cache)
        store.save()
        
        # Cache should be empty
        self.assertEqual(len(store._entry_cache), 0)
        self.assertEqual(len(store._cache_timestamps), 0)

    @patch("mattstash.credential_store.PyKeePass")
    @patch("mattstash.credential_store.os.path.exists", return_value=True)
    def test_clear_cache_method(self, mock_exists, mock_pykeepass):
        """Test manual cache clearing."""
        mock_kp_instance = MagicMock()
        mock_pykeepass.return_value = mock_kp_instance
        
        store = CredentialStore(self.db_path, self.password, cache_enabled=True)
        
        # Manually add to cache
        mock_entry = Mock(spec=Entry)
        store._cache_entry("test", mock_entry)
        
        # Verify cache has data
        self.assertEqual(len(store._entry_cache), 1)
        
        # Clear cache
        store.clear_cache()
        
        # Verify cache is empty
        self.assertEqual(len(store._entry_cache), 0)
        self.assertEqual(len(store._cache_timestamps), 0)

    @patch("mattstash.credential_store.PyKeePass")
    @patch("mattstash.credential_store.os.path.exists", return_value=True)
    def test_no_caching_when_disabled(self, mock_exists, mock_pykeepass):
        """Test that caching doesn't occur when disabled."""
        # Mock entry
        mock_entry = Mock(spec=Entry)
        mock_entry.title = "test-cred"
        
        # Mock KeePass instance
        mock_kp_instance = MagicMock()
        mock_kp_instance.find_entries.return_value = mock_entry
        mock_pykeepass.return_value = mock_kp_instance
        
        # Create store without caching
        store = CredentialStore(self.db_path, self.password, cache_enabled=False)
        
        # Multiple lookups
        store.find_entry_by_title("test-cred")
        store.find_entry_by_title("test-cred")
        store.find_entry_by_title("test-cred")
        
        # Should hit database every time
        self.assertEqual(mock_kp_instance.find_entries.call_count, 3)
        
        # Cache should remain empty
        self.assertEqual(len(store._entry_cache), 0)


if __name__ == "__main__":
    unittest.main()
