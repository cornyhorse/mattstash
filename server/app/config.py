"""Configuration management for MattStash API server."""

import os
from pathlib import Path
from typing import Optional

from mattstash.core.password_resolver import read_password_file

_TRUE = frozenset({"1", "true", "yes", "on"})


def _get_int_env(name: str, default: int, *, minimum: int, maximum: int) -> int:
    """Read and validate a bounded integer environment variable."""
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if value < minimum or value > maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _get_bool_env(name: str, default: bool = False) -> bool:
    """Read a boolean environment variable (1/true/yes/on, case-insensitive)."""
    raw_value = os.getenv(name)
    if raw_value is None or raw_value.strip() == "":
        return default
    return raw_value.strip().lower() in _TRUE


class Config:
    """Application configuration loaded from environment variables."""

    # KeePass database
    DB_PATH: str = os.getenv("MATTSTASH_DB_PATH", "/data/mattstash.kdbx")
    KDBX_PASSWORD: Optional[str] = os.getenv("KDBX_PASSWORD")
    KDBX_PASSWORD_FILE: Optional[str] = os.getenv("KDBX_PASSWORD_FILE")

    # Server settings
    HOST: str = os.getenv("MATTSTASH_HOST", "0.0.0.0")
    PORT: int = _get_int_env("MATTSTASH_PORT", 8000, minimum=1, maximum=65535)
    LOG_LEVEL: str = os.getenv("MATTSTASH_LOG_LEVEL", "info")
    TLS_CERT_FILE: Optional[str] = os.getenv("MATTSTASH_TLS_CERT_FILE")
    TLS_KEY_FILE: Optional[str] = os.getenv("MATTSTASH_TLS_KEY_FILE")

    # Writes are OFF unless explicitly enabled (read-only by default).
    ALLOW_WRITES: bool = _get_bool_env("MATTSTASH_ALLOW_WRITES")
    # Hide /docs, /redoc and /openapi.json.
    DISABLE_DOCS: bool = _get_bool_env("MATTSTASH_DISABLE_DOCS")
    # Refuse to start if a plaintext sidecar password file sits next to the database.
    REFUSE_SIDECAR: bool = _get_bool_env("MATTSTASH_REFUSE_SIDECAR")

    # API Security
    # Stripped like the key files: a Kubernetes Secret or `echo` adds a newline that no client can ever send.
    API_KEY: Optional[str] = (os.getenv("MATTSTASH_API_KEY") or "").strip() or None
    API_KEYS_FILE: Optional[str] = os.getenv("MATTSTASH_API_KEYS_FILE")
    MIN_KEY_LENGTH: int = _get_int_env("MATTSTASH_MIN_KEY_LENGTH", 32, minimum=8, maximum=256)
    REQUIRE_SCOPED_KEYS: bool = _get_bool_env("MATTSTASH_REQUIRE_SCOPED_KEYS")

    # Throttling of FAILED authentication attempts, per client IP (applied before auth runs)
    AUTH_FAIL_LIMIT: int = _get_int_env("MATTSTASH_AUTH_FAIL_LIMIT", 10, minimum=1, maximum=10_000)
    AUTH_FAIL_WINDOW: int = _get_int_env("MATTSTASH_AUTH_FAIL_WINDOW_SECONDS", 60, minimum=1, maximum=86_400)
    # Number of trusted reverse proxies in front of the server; the client IP is then taken from
    # X-Forwarded-For (that many entries from the right). 0 = use the TCP peer address.
    TRUSTED_PROXY_HOPS: int = _get_int_env("MATTSTASH_TRUSTED_PROXY_HOPS", 0, minimum=0, maximum=10)

    # Rate limiting (per client IP) for read endpoints; writes/deletes/admin have fixed lower limits
    RATE_LIMIT: str = os.getenv("MATTSTASH_RATE_LIMIT", "100/minute")
    #: Writes (POST/DELETE) that may be in flight at once. Each waits for the database write lock in a worker thread;
    #: more than this are answered 503 immediately, so a stuck lock holder cannot use up every worker thread and
    #: take reads and the readiness probe down with it.
    MAX_CONCURRENT_WRITES: int = _get_int_env("MATTSTASH_MAX_CONCURRENT_WRITES", 8, minimum=1, maximum=32)
    MAX_REQUEST_BODY_BYTES: int = _get_int_env(
        "MATTSTASH_MAX_REQUEST_BODY_BYTES",
        1_048_576,
        minimum=1,
        maximum=10_485_760,
    )

    # Database file change polling
    DB_POLL_INTERVAL: int = _get_int_env("MATTSTASH_DB_POLL_INTERVAL", 5, minimum=0, maximum=3600)

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
                # The library's reader, so the server and the CLI can never disagree about the same file
                # (surrounding whitespace, a UTF-8 BOM and the size cap are handled in one place).
                try:
                    password = read_password_file(str(password_path))
                except (OSError, UnicodeDecodeError) as exc:
                    raise ValueError(f"KDBX password file cannot be read: {exc.__class__.__name__}") from None
                if not password:
                    raise ValueError("KDBX password file is empty")
                return password
            raise FileNotFoundError(f"Password file not found: {cls.KDBX_PASSWORD_FILE}")

        raise ValueError("KDBX password must be provided via KDBX_PASSWORD or KDBX_PASSWORD_FILE")

    @classmethod
    def validate_tls(cls) -> bool:
        """Return True if TLS is configured; raise if only half of it is."""
        if bool(cls.TLS_CERT_FILE) != bool(cls.TLS_KEY_FILE):
            raise ValueError("MATTSTASH_TLS_CERT_FILE and MATTSTASH_TLS_KEY_FILE must be set together")
        return bool(cls.TLS_CERT_FILE)


config = Config()
