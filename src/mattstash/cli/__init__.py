"""
mattstash.cli
-------------
Command-line interface components.
"""

# Import module-level functions for backward compatibility with tests
from ..module_functions import delete, get, get_db_url, get_s3_client, list_creds, list_versions, put
from .main import main

__all__ = ["delete", "get", "get_db_url", "get_s3_client", "list_creds", "list_versions", "main", "put"]
