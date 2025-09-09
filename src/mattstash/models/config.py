"""
mattstash.config
----------------
Configuration constants and settings for MattStash.
"""

from dataclasses import dataclass


@dataclass
class MattStashConfig:
    """Configuration settings for MattStash operations."""

    # Database settings
    default_db_path: str = "~/.config/mattstash/mattstash.kdbx"
    sidecar_basename: str = ".mattstash.txt"

    # Versioning settings
    version_pad_width: int = 10

    # Display settings
    password_mask: str = "*****"

    # S3 client defaults
    default_region: str = "us-east-1"
    default_addressing: str = "path"
    default_signature_version: str = "s3v4"
    default_retries: int = 10


# Global configuration instance
config = MattStashConfig()
