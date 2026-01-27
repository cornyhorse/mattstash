"""
mattstash.cli.handlers
---------------------
Command handlers for the CLI interface.
"""

from .base import BaseHandler
from .setup import SetupHandler
from .list import ListHandler, KeysHandler
from .get import GetHandler
from .put import PutHandler
from .delete import DeleteHandler
from .versions import VersionsHandler
from .db_url import DbUrlHandler
from .s3_test import S3TestHandler
from .config import ConfigHandler

__all__ = [
    "BaseHandler",
    "SetupHandler",
    "ListHandler",
    "KeysHandler",
    "GetHandler",
    "PutHandler",
    "DeleteHandler",
    "VersionsHandler",
    "DbUrlHandler",
    "S3TestHandler",
    "ConfigHandler",
]
