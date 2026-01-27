"""Configuration management for MattStash API server."""
import os
from pathlib import Path
from typing import Optional


class Config:
    """Application configuration loaded from environment variables."""
    
    # KeePass database
    DB_PATH: str = os.getenv("MATTSTASH_DB_PATH", "/data/mattstash.kdbx")
    KDBX_PASSWORD: Optional[str] = os.getenv("KDBX_PASSWORD")
    KDBX_PASSWORD_FILE: Optional[str] = os.getenv("KDBX_PASSWORD_FILE")
    
    # Server settings
    HOST: str = os.getenv("MATTSTASH_HOST", "0.0.0.0")
    PORT: int = int(os.getenv("MATTSTASH_PORT", "8000"))
    LOG_LEVEL: str = os.getenv("MATTSTASH_LOG_LEVEL", "info")
    
    # API Security
    API_KEY: Optional[str] = os.getenv("MATTSTASH_API_KEY")
    API_KEYS_FILE: Optional[str] = os.getenv("MATTSTASH_API_KEYS_FILE")
    
    # Rate limiting
    RATE_LIMIT: str = os.getenv("MATTSTASH_RATE_LIMIT", "100/minute")
    
    # API metadata
    API_VERSION: str = "v1"
    API_TITLE: str = "MattStash API"
    API_DESCRIPTION: str = "Secure credential management API using KeePass backend"
    
    @classmethod
    def get_kdbx_password(cls) -> str:
        """Get KeePass database password from env or file."""
        if cls.KDBX_PASSWORD:
            return cls.KDBX_PASSWORD
        
        if cls.KDBX_PASSWORD_FILE:
            password_path = Path(cls.KDBX_PASSWORD_FILE)
            if password_path.exists():
                return password_path.read_text().strip()
            raise FileNotFoundError(f"Password file not found: {cls.KDBX_PASSWORD_FILE}")
        
        raise ValueError("KDBX password must be provided via KDBX_PASSWORD or KDBX_PASSWORD_FILE")
    
    @classmethod
    def get_api_keys(cls) -> set[str]:
        """Get set of valid API keys from env or file."""
        api_keys = set()
        
        # Single API key from env
        if cls.API_KEY:
            api_keys.add(cls.API_KEY)
        
        # Multiple keys from file
        if cls.API_KEYS_FILE:
            keys_path = Path(cls.API_KEYS_FILE)
            if keys_path.exists():
                for line in keys_path.read_text().splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        api_keys.add(line)
        
        if not api_keys:
            raise ValueError("At least one API key must be provided via MATTSTASH_API_KEY or MATTSTASH_API_KEYS_FILE")
        
        return api_keys


config = Config()
