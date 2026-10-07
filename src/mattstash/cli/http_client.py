"""
mattstash.cli.http_client
-------------------------
HTTP client for communicating with MattStash API server.

Security notes
~~~~~~~~~~~~~~
* Path segments (credential names) are always percent-encoded, so a name such as ``db#prod``
  or ``a/b`` cannot change which resource the request addresses.
* TLS certificates are verified (``verify=True``); redirects are not followed, so the API key
  is never replayed to another location.
* Errors raised by the client (:class:`~mattstash.utils.exceptions.ServerError`) contain the HTTP
  status and the request path only -- never the API key, the query string or any part of the
  response body (which may carry secrets).
* A plain ``http://`` URL to a non-loopback host triggers one warning, because the API key then
  travels in clear text. It never refuses: plain HTTP on a private (compose/cluster) network is a
  supported setup. Silence the warning with ``MATTSTASH_ALLOW_INSECURE_HTTP=1``.
"""

import ipaddress
import os
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urlparse

import httpx

from ..utils.exceptions import ServerError
from ..utils.logging_config import get_logger

logger = get_logger(__name__)

#: Environment variable that silences the plain-HTTP warning.
ALLOW_INSECURE_HTTP_ENV = "MATTSTASH_ALLOW_INSECURE_HTTP"
_TRUTHY = frozenset({"1", "true", "yes"})


def is_loopback_host(host: Optional[str]) -> bool:
    """True for ``localhost`` and loopback IP literals (127.0.0.0/8, ::1)."""
    if not host:
        return False
    name = host.strip().strip("[]").rstrip(".").lower()
    if name == "localhost":
        return True
    try:
        return ipaddress.ip_address(name).is_loopback
    except ValueError:
        return False


def insecure_http_allowed() -> bool:
    """True if ``MATTSTASH_ALLOW_INSECURE_HTTP`` is set to 1/true/yes."""
    return os.environ.get(ALLOW_INSECURE_HTTP_ENV, "").strip().lower() in _TRUTHY


def warn_if_insecure(base_url: str) -> bool:
    """Log one warning if ``base_url`` is ``http://`` to a non-loopback host. Returns True if it warned."""
    try:
        parsed = urlparse(base_url)
        host = parsed.hostname
    except ValueError:
        return False
    if parsed.scheme.lower() != "http" or is_loopback_host(host) or insecure_http_allowed():
        return False
    logger.warning(
        "The API key is sent in clear text to %s over plain http://. Use an https:// URL, or set %s=1 "
        "if this network is trusted.",
        host or "the server",
        ALLOW_INSECURE_HTTP_ENV,
    )
    return True


def segment(value: str) -> str:
    """Percent-encode one URL path segment (``/``, ``#``, ``?``, ``%`` ... are all escaped).

    ``.`` and ``..`` are additionally escaped so URL normalisation cannot turn them into path navigation.
    """
    if value in (".", ".."):
        return value.replace(".", "%2E")
    return quote(value, safe="")


_STATUS_HINTS = {
    400: "the server rejected the request (invalid name or parameter)",
    401: "authentication failed; check the API key",
    403: "this API key is not allowed to do that",
    404: "not found",
    405: "the server does not allow this operation (it may be read-only)",
    413: "the request is too large for the server",
    429: "too many requests; slow down and retry",
}


class MattStashServerClient:
    """Client for MattStash API server."""

    def __init__(self, base_url: str, api_key: str, timeout: float = 30.0):
        """
        Initialize server client.

        Args:
            base_url: Base URL of MattStash server (e.g., http://localhost:8000)
            api_key: API key for authentication
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.headers = {"X-API-Key": api_key}
        warn_if_insecure(self.base_url)

    def __repr__(self) -> str:
        return f"MattStashServerClient(base_url={self.base_url!r})"

    # ---- plumbing -----------------------------------------------------------

    def _redact(self, text: str) -> str:
        """Remove the API key from text that is about to be shown."""
        if self.api_key:
            text = text.replace(self.api_key, "***")
        return text

    def _status_error(self, method: str, endpoint: str, response: "httpx.Response") -> ServerError:
        code = response.status_code
        message = f"server returned HTTP {code} for {method} {endpoint}"
        hint = _STATUS_HINTS.get(code)
        if code >= 500:
            hint = "server-side error"
        elif 300 <= code < 400:
            hint = "unexpected redirect (redirects are not followed; check the server URL, e.g. http vs https)"
        if hint:
            message += f" ({hint})"
        retry_after = response.headers.get("Retry-After", "")
        if code == 429 and retry_after.isdigit():
            message += f"; retry after {retry_after}s"
        return ServerError(message, status_code=code)

    def _make_request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Make HTTP request to server.

        Args:
            method: HTTP method (GET, POST, DELETE, etc.)
            endpoint: API endpoint path (path segments already percent-encoded)
            params: Query parameters
            json_data: JSON request body

        Returns:
            Response data as dictionary

        Raises:
            ServerError: on network errors, non-2xx responses or an unusable response body.
        """
        url = f"{self.base_url}{endpoint}"

        try:
            with httpx.Client(timeout=self.timeout, verify=True) as client:
                response = client.request(method=method, url=url, headers=self.headers, params=params, json=json_data)
        except httpx.HTTPError as exc:
            detail = self._redact(str(exc)).strip()[:200]
            raise ServerError(
                f"request to server failed ({type(exc).__name__}{': ' + detail if detail else ''})"
            ) from None

        if not response.is_success:
            raise self._status_error(method, endpoint, response)
        try:
            result = response.json()
        except ValueError:
            raise ServerError("server returned a response that is not valid JSON") from None
        if not isinstance(result, dict):
            raise ServerError("server returned an unexpected response format")
        return result

    # ---- operations ---------------------------------------------------------

    def get(self, title: str, show_password: bool = False, version: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """
        Get credential from server.

        Args:
            title: Credential name
            show_password: Whether to show actual password
            version: Specific version to retrieve

        Returns:
            Credential data or None if not found
        """
        try:
            params: Dict[str, Any] = {"show_password": show_password}
            if version is not None:
                params["version"] = version

            return self._make_request("GET", f"/api/v1/credentials/{segment(title)}", params=params)
        except ServerError as e:
            if e.status_code == 404:
                return None
            raise

    def put(
        self,
        title: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        url: Optional[str] = None,
        notes: Optional[str] = None,
        comment: Optional[str] = None,
        tags: Optional[List[str]] = None,
        value: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Store credential on server.

        Args:
            title: Credential name
            username: Username
            password: Password
            url: URL
            notes: Notes
            comment: Comment (alias for notes)
            tags: List of tags
            value: Simple value mode (stored as password)

        Returns:
            Created/updated credential data
        """
        # Build request body
        data: Dict[str, Any] = {}

        if value is not None:
            # Simple value mode
            data["value"] = value
        else:
            # Full credential mode
            if username is not None:
                data["username"] = username
            if password is not None:
                data["password"] = password
            if url is not None:
                data["url"] = url

        # Handle notes/comment
        final_notes = comment if comment is not None else notes
        if final_notes is not None:
            data["notes"] = final_notes

        if tags:
            data["tags"] = tags

        return self._make_request("POST", f"/api/v1/credentials/{segment(title)}", json_data=data)

    def delete(self, title: str, version: Optional[int] = None) -> bool:
        """
        Delete credential from server.

        Args:
            title: Credential name
            version: Delete only this version (``DELETE ...?version=N``); all versions if omitted

        Returns:
            True if deleted, False if not found
        """
        params: Optional[Dict[str, Any]] = {"version": version} if version is not None else None
        try:
            self._make_request("DELETE", f"/api/v1/credentials/{segment(title)}", params=params)
            return True
        except ServerError as e:
            if e.status_code == 404:
                return False
            raise

    def list(self, show_password: bool = False, prefix: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List all credentials from server.

        Args:
            show_password: Whether to show actual passwords
            prefix: Filter by name prefix

        Returns:
            List of credential data dictionaries
        """
        params: Dict[str, Any] = {"show_password": show_password}
        if prefix:
            params["prefix"] = prefix

        result = self._make_request("GET", "/api/v1/credentials", params=params)
        creds: List[Dict[str, Any]] = result.get("credentials", [])
        return creds

    def versions(self, title: str) -> List[str]:
        """
        Get version history from server.

        Args:
            title: Credential name

        Returns:
            List of version strings
        """
        try:
            result = self._make_request("GET", f"/api/v1/credentials/{segment(title)}/versions")
            vers: List[str] = result.get("versions", [])
            return vers
        except ServerError as e:
            if e.status_code == 404:
                return []
            raise

    def health_check(self) -> Dict[str, Any]:
        """
        Check server health.

        Returns:
            Health status dictionary
        """
        return self._make_request("GET", "/api/health")

    def db_url(
        self,
        title: str,
        driver: Optional[str] = "psycopg",
        database: Optional[str] = None,
        mask_password: bool = True,
        dialect: Optional[str] = None,
    ) -> str:
        """
        Get database URL from credential.

        Args:
            title: Credential name
            driver: Database driver (omitted from the request when ``None``)
            database: Database name override
            mask_password: Whether to mask password in URL
            dialect: Database dialect (``postgresql``, ``mysql``, ``mariadb``); omitted when ``None``

        Returns:
            Database URL string
        """
        params: Dict[str, Any] = {"mask_password": mask_password}
        if driver:
            params["driver"] = driver
        if dialect:
            params["dialect"] = dialect
        if database:
            params["database"] = database

        result = self._make_request("GET", f"/api/v1/db-url/{segment(title)}", params=params)
        url: str = result.get("url", "")
        return url
