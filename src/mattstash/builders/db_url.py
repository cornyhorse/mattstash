"""
mattstash.db_url
----------------
Database URL construction functionality.
"""

from typing import Optional
from urllib.parse import urlparse

# Updated import path for refactored structure
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..core.mattstash import MattStash


class DatabaseUrlBuilder:
    """Handles construction of SQLAlchemy database URLs from KeePass entries."""

    def __init__(self, mattstash: 'MattStash'):
        self.mattstash = mattstash

    def _parse_host_port(self, endpoint: Optional[str]) -> tuple[str, int]:
        """Parse host and port from an endpoint string.
        Accepts either a raw `host:port` or a URL like `scheme://host:port/...`.
        Raises ValueError if the port is missing or invalid.
        """
        if not endpoint:
            raise ValueError("[mattstash] Empty database endpoint URL")
        ep = endpoint.strip()
        host = None
        port = None
        if "://" in ep:
            parsed = urlparse(ep)
            netloc = parsed.netloc or parsed.path  # some urlparse variants put everything in path for odd inputs
            if ":" not in netloc:
                raise ValueError("[mattstash] Database endpoint must include a port (e.g., host:5432)")
            host, port_str = netloc.split("@", 1)[-1].rsplit(":", 1) if "@" in netloc else netloc.rsplit(":", 1)
            if not port_str.isdigit():
                raise ValueError("[mattstash] Invalid database port in endpoint")
            port = int(port_str)
        else:
            if ":" not in ep:
                raise ValueError("[mattstash] Database endpoint must include a port (e.g., host:5432)")
            host, port_str = ep.rsplit(":", 1)
            if not port_str.isdigit():
                raise ValueError("[mattstash] Invalid database port in endpoint")
            port = int(port_str)
        host = host.strip("/")
        return host, port

    def build_url(
            self,
            title: str,
            *,
            driver: Optional[str] = None,
            mask_password: bool = True,
            mask_style: str = "stars",  # "stars" -> user:*****, "omit" -> user (no password section)
            database: Optional[str] = None,
            sslmode_override: Optional[str] = None,
    ) -> str:
        """Construct a SQLAlchemy URL from a KeePass entry.

        Mapping:
          - entry.username -> user
          - entry.password -> password
          - entry.url      -> host:port (required; raises if no port)
          - custom property `database` or `dbname` -> database name (required, unless `database` arg is provided)
          - optional custom property `sslmode` -> added as query param (can be overridden with sslmode_override)
        Additional:
          - database: can be provided explicitly and will override custom props.
          - sslmode_override: can override the custom property.
          - driver: optional driver suffix (e.g. "psycopg"); if provided the URL is `postgresql+{driver}://...`,
            otherwise `postgresql://...`.
          - mask_password:
              True  -> do not reveal the real password (use mask_style behavior)
              False -> include the real password when present
          - mask_style:
              "stars" -> include `:*****` after the username (API default)
              "omit"  -> omit the password entirely and render only `user@` (CLI default)

        Examples:
          - API default (masked stars, no driver):    `postgresql://user:*****@host:5432/db`
          - CLI masked default (omit, with driver):   `postgresql+psycopg://user@host:5432/db`
          - Unmasked with driver:                     `postgresql+psycopg://user:pw@host:5432/db`
        """
        cred = self.mattstash.get(title, show_password=True)
        if cred is None:
            raise ValueError(f"[mattstash] Credential not found: {title}")
        # If `cred` is a dict (simple secret), this is not a full DB cred
        if isinstance(cred, dict):
            raise ValueError("[mattstash] Entry is a simple secret and cannot be used for a DB connection")

        host, port = self._parse_host_port(cred.url)

        # Use the refactored approach to get the KeePass database
        if not self.mattstash._ensure_initialized():
            raise ValueError("[mattstash] Unable to open KeePass database")
        kp = self.mattstash._credential_store.open()
        entry = kp.find_entries(title=title, first=True)
        if not entry:
            # If versioning was used and latest resolved above, we still need the entry object to read custom props
            # Attempt to resolve latest versioned entry
            prefix = f"{title}@"
            candidates = [e for e in kp.entries if e.title and e.title.startswith(prefix)]
            if candidates:
                entry = max(candidates, key=lambda e: int(e.title[len(prefix):]))
            else:
                raise ValueError(f"[mattstash] Credential entry not found: {title}")

        dbname = database or entry.get_custom_property("database") or entry.get_custom_property("dbname")
        if not dbname:
            raise ValueError("[mattstash] Missing database name. Provide --database/`database=` or set custom property 'database'/'dbname' on the credential.")

        sslmode = sslmode_override if sslmode_override is not None else entry.get_custom_property("sslmode")

        dialect = "postgresql" + (f"+{driver}" if driver else "")
        user = cred.username or ""
        pwd = cred.password or ""

        if mask_password:
            if mask_style == "omit":
                userinfo = user
            else:  # "stars" (default)
                if pwd:
                    userinfo = f"{user}:*****"
                else:
                    userinfo = user
        else:
            # include the real password if available
            if pwd:
                userinfo = f"{user}:{pwd}"
            else:
                userinfo = user

        base = f"{dialect}://{userinfo}@{host}:{port}/{dbname}"
        if sslmode:
            base = f"{base}?sslmode={sslmode}"
        return base
