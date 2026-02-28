"""
mattstash.config
----------------
Configuration constants and settings for MattStash.

Configuration priority (highest to lowest):
1. Explicit parameters (e.g., MattStash(path="/custom/path"))
2. Environment variables (e.g., MATTSTASH_DB_PATH)
3. Configuration file (~/.config/mattstash/config.yml)
4. Default values
"""

import os
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
    password_mask: str = "*****"  # noqa: S105

    # S3 client defaults
    default_region: str = "us-east-1"
    default_addressing: str = "path"
    default_signature_version: str = "s3v4"
    default_retries: int = 10

    # Cache settings (opt-in)
    cache_enabled: bool = False
    cache_ttl: int = 300  # 5 minutes

    # Logging
    log_level: str = "INFO"
    verbose: bool = False

    def __post_init__(self) -> None:
        """Apply configuration from environment and files after initialization."""
        self._load_from_environment()
        self._load_from_file()

    def _load_from_environment(self) -> None:
        """Load configuration from environment variables."""
        env_val = os.getenv("MATTSTASH_DB_PATH")
        if env_val:
            self.default_db_path = env_val
        env_val = os.getenv("MATTSTASH_SIDECAR_BASENAME")
        if env_val:
            self.sidecar_basename = env_val
        env_val = os.getenv("MATTSTASH_VERSION_PAD_WIDTH")
        if env_val:
            self.version_pad_width = int(env_val)
        env_val = os.getenv("MATTSTASH_PASSWORD_MASK")
        if env_val:
            self.password_mask = env_val
        env_val = os.getenv("MATTSTASH_S3_REGION")
        if env_val:
            self.default_region = env_val
        env_val = os.getenv("MATTSTASH_S3_ADDRESSING")
        if env_val:
            self.default_addressing = env_val
        env_val = os.getenv("MATTSTASH_S3_SIGNATURE_VERSION")
        if env_val:
            self.default_signature_version = env_val
        env_val = os.getenv("MATTSTASH_S3_RETRIES")
        if env_val:
            self.default_retries = int(env_val)
        env_val = os.getenv("MATTSTASH_ENABLE_CACHE")
        if env_val:
            self.cache_enabled = env_val.lower() in ("true", "1", "yes")
        env_val = os.getenv("MATTSTASH_CACHE_TTL")
        if env_val:
            self.cache_ttl = int(env_val)
        env_val = os.getenv("MATTSTASH_LOG_LEVEL")
        if env_val:
            self.log_level = env_val

    def _load_from_file(self) -> None:
        """Load configuration from YAML file if available."""
        try:
            from ..utils.config_loader import get_config_value, load_yaml_config

            file_config = load_yaml_config()
            if not file_config:
                return

            # Apply file config (only if not already set by environment)
            if not os.getenv("MATTSTASH_DB_PATH"):
                db_path = get_config_value(file_config, "database", "path")
                if db_path:
                    self.default_db_path = db_path

            if not os.getenv("MATTSTASH_SIDECAR_BASENAME"):
                sidecar = get_config_value(file_config, "database", "sidecar_basename")
                if sidecar:
                    self.sidecar_basename = sidecar

            if not os.getenv("MATTSTASH_VERSION_PAD_WIDTH"):
                pad_width = get_config_value(file_config, "versioning", "pad_width")
                if pad_width is not None:
                    self.version_pad_width = int(pad_width)

            if not os.getenv("MATTSTASH_LOG_LEVEL"):
                log_level = get_config_value(file_config, "logging", "level")
                if log_level:
                    self.log_level = log_level

            verbose = get_config_value(file_config, "logging", "verbose")
            if verbose is not None:
                self.verbose = bool(verbose)

            if not os.getenv("MATTSTASH_S3_REGION"):
                region = get_config_value(file_config, "s3", "region")
                if region:
                    self.default_region = region

            if not os.getenv("MATTSTASH_S3_ADDRESSING"):
                addressing = get_config_value(file_config, "s3", "addressing")
                if addressing:
                    self.default_addressing = addressing

            if not os.getenv("MATTSTASH_S3_RETRIES"):
                retries = get_config_value(file_config, "s3", "retries")
                if retries is not None:
                    self.default_retries = int(retries)

            if not os.getenv("MATTSTASH_ENABLE_CACHE"):
                cache_enabled = get_config_value(file_config, "cache", "enabled")
                if cache_enabled is not None:
                    self.cache_enabled = bool(cache_enabled)

            if not os.getenv("MATTSTASH_CACHE_TTL"):
                cache_ttl = get_config_value(file_config, "cache", "ttl")
                if cache_ttl is not None:
                    self.cache_ttl = int(cache_ttl)

        except ImportError:
            # Config loader not available, skip file loading
            pass


# Global configuration instance
config = MattStashConfig()
