"""
mattstash.db_url
----------------
Database URL construction functionality.
"""

# Updated import path for refactored structure
import re
from typing import TYPE_CHECKING, Dict, FrozenSet, Optional
from urllib.parse import quote, urlencode, urlparse

if TYPE_CHECKING:
    from ..core.mattstash import MattStash

_SSLMODES = frozenset({"disable", "allow", "prefer", "require", "verify-ca", "verify-full"})
_HOST_RE = re.compile(r"[A-Za-z0-9._\-\[\]:%]+")

#: Dialect used when neither the ``dialect`` argument nor the entry's ``dialect`` property is set.
DEFAULT_DIALECT = "postgresql"

#: Allow-list: SQLAlchemy dialect -> drivers that may follow it (``dialect+driver://``).
DIALECT_DRIVERS: Dict[str, FrozenSet[str]] = {
    "postgresql": frozenset({"psycopg", "psycopg2", "asyncpg", "pg8000"}),
    "mysql": frozenset({"pymysql", "mysqlconnector", "asyncmy", "aiomysql"}),
    "mariadb": frozenset({"mariadbconnector", "pymysql"}),
}

#: ``driver="auto"``: psycopg for PostgreSQL, no driver suffix (SQLAlchemy's default driver) otherwise.
AUTO_DRIVER = "auto"
_AUTO_DRIVERS: Dict[str, Optional[str]] = {"postgresql": "psycopg", "mysql": None, "mariadb": None}


def normalize_dialect(dialect: Optional[str], *, source: str = "dialect") -> str:
    """Return the canonical (lower-case) dialect name; ``ValueError`` if it is not on the allow-list.

    ``None`` or an empty value means the default dialect (PostgreSQL).
    """
    if dialect is None or not str(dialect).strip():
        return DEFAULT_DIALECT
    name = str(dialect).strip().lower()
    if name not in DIALECT_DRIVERS:
        raise ValueError(f"[mattstash] Unsupported {source} {dialect!r}; expected one of {sorted(DIALECT_DRIVERS)}")
    return name


def resolve_driver(dialect: str, driver: Optional[str]) -> Optional[str]:
    """Validate ``driver`` for ``dialect`` (``ValueError`` otherwise) and return its canonical name.

    ``None``/empty -> no driver suffix; ``"auto"`` -> the conventional default for the dialect.
    """
    if driver is None or not str(driver).strip():
        return None
    name = str(driver).strip().lower()
    if name == AUTO_DRIVER:
        return _AUTO_DRIVERS[dialect]
    allowed = DIALECT_DRIVERS[dialect]
    if name not in allowed:
        raise ValueError(f"[mattstash] Driver {driver!r} is not valid for {dialect}; expected one of {sorted(allowed)}")
    return name


def build_db_url(
    mattstash: "MattStash",
    name: str,
    driver: Optional[str] = AUTO_DRIVER,
    database: Optional[str] = None,
    sslmode_override: Optional[str] = None,
    mask_password: bool = False,
    mask_style: str = "stars",
    dialect: Optional[str] = None,
) -> str:
    """
    Convenience function to build a database URL from a credential.

    Args:
        mattstash: MattStash instance
        name: Name of the credential
        driver: Optional driver suffix (e.g., "psycopg"). The default ``"auto"`` means ``psycopg`` for
            PostgreSQL (the historical default) and no suffix for the other dialects.
        database: Optional database name
        sslmode_override: Optional SSL mode override (PostgreSQL only)
        mask_password: Whether to mask the password
        mask_style: "stars" or "omit"
        dialect: ``postgresql`` (default), ``mysql`` or ``mariadb``; overrides the entry's ``dialect`` property

    Returns:
        Database connection URL string
    """
    builder = DatabaseUrlBuilder(mattstash)
    return builder.build_url(
        title=name,
        driver=driver,
        database=database,
        sslmode_override=sslmode_override,
        mask_password=mask_password,
        mask_style=mask_style,
        dialect=dialect,
    )


class DatabaseUrlBuilder:
    """Handles construction of SQLAlchemy database URLs from KeePass entries."""

    def __init__(self, mattstash: "MattStash"):
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
        if not host or not _HOST_RE.fullmatch(host):
            raise ValueError("[mattstash] Invalid database host in endpoint")
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
        dialect: Optional[str] = None,
    ) -> str:
        """Construct a SQLAlchemy URL from a KeePass entry.

        Mapping:
          - entry.username -> user
          - entry.password -> password
          - entry.url      -> host:port (required; raises if no port)
          - custom property `database` or `dbname` -> database name (required, unless `database` arg is provided)
          - optional custom property `sslmode` -> added as query param (can be overridden with sslmode_override);
            PostgreSQL only (rejected for other dialects: dropping it silently could leave TLS off)
          - optional custom property `dialect` -> `postgresql` (default), `mysql` or `mariadb`
        Additional:
          - database: can be provided explicitly and will override custom props.
          - sslmode_override: can override the custom property.
          - dialect: overrides the `dialect` custom property (default PostgreSQL). Unknown dialects raise ValueError.
          - driver: optional driver suffix (e.g. "psycopg"); if provided the URL is `{dialect}+{driver}://...`,
            otherwise `{dialect}://...`. Drivers are allow-listed per dialect (postgresql: psycopg, psycopg2,
            asyncpg, pg8000; mysql: pymysql, mysqlconnector, asyncmy, aiomysql; mariadb: mariadbconnector,
            pymysql); anything else raises ValueError. `"auto"` picks `psycopg` for PostgreSQL and no suffix
            for the other dialects.
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
          - MySQL with PyMySQL:                       `mysql+pymysql://user:*****@host:3306/db`
        """
        # Validate what the caller passed before touching the database.
        explicit_dialect = normalize_dialect(dialect) if dialect is not None else None

        # Credential + custom properties in one consistent snapshot of the database
        found = self.mattstash.get_entry_with_properties(title, ("database", "dbname", "sslmode", "dialect"))
        if found is None:
            raise ValueError(f"[mattstash] Credential not found: {title}")

        cred, props = found

        # If `cred` is a dict (simple secret), this is not a full DB cred
        if isinstance(cred, dict):
            raise ValueError("[mattstash] Entry is a simple secret and cannot be used for a DB connection")

        effective_dialect = explicit_dialect or normalize_dialect(props.get("dialect"), source="'dialect' property")
        driver_name = resolve_driver(effective_dialect, driver)

        host, port = self._parse_host_port(cred.url)

        dbname = database or props.get("database") or props.get("dbname")
        if not dbname:
            raise ValueError(
                "[mattstash] Missing database name. Provide --database/`database=`"
                " or set custom property 'database'/'dbname' on the credential."
            )

        sslmode = sslmode_override if sslmode_override is not None else props.get("sslmode")
        if sslmode and effective_dialect != "postgresql":
            # Silently dropping it could leave a connection unencrypted that the entry says must use TLS.
            raise ValueError(
                f"[mattstash] sslmode is only supported for postgresql URLs, not {effective_dialect}; remove the "
                "'sslmode' property/option (configure TLS through your driver instead)"
            )
        if sslmode and sslmode not in _SSLMODES:
            raise ValueError(f"[mattstash] Invalid sslmode {sslmode!r}; expected one of {sorted(_SSLMODES)}")

        scheme = effective_dialect + (f"+{driver_name}" if driver_name else "")
        # Percent-encode everything that is user data: a password such as "p@ss/w:rd#1" would
        # otherwise change the meaning of the URL (host, path, query).
        user = quote(cred.username or "", safe="")
        pwd = quote(cred.password or "", safe="")

        if mask_password:
            if mask_style == "omit":
                userinfo = user
            else:  # "stars" (default)
                userinfo = f"{user}:*****" if pwd else user
        else:
            # include the real password if available
            userinfo = f"{user}:{pwd}" if pwd else user

        base = f"{scheme}://{userinfo}@{host}:{port}/{quote(dbname, safe='')}"
        if sslmode:
            base = f"{base}?{urlencode({'sslmode': sslmode})}"
        return base
