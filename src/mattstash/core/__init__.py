"""
mattstash.core
--------------
Core functionality for MattStash.
"""

from .bootstrap import DatabaseBootstrapper
from .entry_manager import EntryManager
from .mattstash import MattStash
from .password_resolver import PasswordResolver

__all__ = ["DatabaseBootstrapper", "EntryManager", "MattStash", "PasswordResolver"]
