"""
mattstash.config
----------------
Configuration constants and settings for MattStash.
"""

import os
from dataclasses import dataclass


@dataclass
class MattStashConfig:
    """Configuration settings for MattStash operations."""

    # Database settings
    default_db_path: str = os.getenv("MATTSTASH_DB_PATH", "~/.config/mattstash/mattstash.kdbx")
    sidecar_basename: str = os.getenv("MATTSTASH_SIDECAR_BASENAME", ".mattstash.txt")

    # Versioning settings
    version_pad_width: int = int(os.getenv("MATTSTASH_VERSION_PAD_WIDTH", "10"))

    # Display settings
    password_mask: str = os.getenv("MATTSTASH_PASSWORD_MASK", "*****")

    # S3 client defaults
    default_region: str = os.getenv("MATTSTASH_S3_REGION", "us-east-1")
    default_addressing: str = os.getenv("MATTSTASH_S3_ADDRESSING", "path")
    default_signature_version: str = os.getenv("MATTSTASH_S3_SIGNATURE_VERSION", "s3v4")
    default_retries: int = int(os.getenv("MATTSTASH_S3_RETRIES", "10"))


# Global configuration instance
config = MattStashConfig()
