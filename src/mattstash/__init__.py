from .core import (
    Credential,
    MattStash,
    get,
    list_creds,
    get_s3_client,
)

__all__ = ["Credential", "MattStash", "get", "list_creds", "get_s3_client"]

# Single-source version if you prefer; otherwise keep in pyproject only.
__version__ = "0.1.0"