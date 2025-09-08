"""
mattstash.core
--------------
Core functionality for MattStash.
"""

from .mattstash import MattStash
from .bootstrap import DatabaseBootstrapper
from .password_resolver import PasswordResolver
from .entry_manager import EntryManager

__all__ = ['MattStash', 'DatabaseBootstrapper', 'PasswordResolver', 'EntryManager']
