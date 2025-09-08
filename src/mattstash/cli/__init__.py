"""
mattstash.cli
-------------
Command-line interface components.
"""

from .main import main

# Import module-level functions for backward compatibility with tests
from ..module_functions import (
    get, put, delete, list_creds, list_versions,
    get_db_url, get_s3_client
)

__all__ = [
    'main', 'get', 'put', 'delete', 'list_creds',
    'list_versions', 'get_db_url', 'get_s3_client'
]
