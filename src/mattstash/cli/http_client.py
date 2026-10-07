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
* A plain ``http://`` URL to a non-loopback host -- or to any host when an ``HTTP_PROXY`` applies -- triggers one
  warning, because the API key then travels in clear text. It never refuses: plain HTTP on a private
  (compose/cluster) network is a supported setup. Silence the warning with ``MATTSTASH_ALLOW_INSECURE_HTTP=1``.
* Responses are bounded: at most ``MAX_RESPONSE_BYTES`` and ``total_timeout`` seconds per request, so a broken or
  hostile server cannot make the CLI hang or exhaust memory.
* Only the server's own "Credential not found" 404 means "no such secret". Any other 404 (wrong URL, a proxy's
  error page, a name the server cannot route) is an error -- ``delete`` must never report "already gone" for it.
* A rate-limited GET (HTTP 429) is retried a few times, honouring ``Retry-After``.
"""

import contextlib
import ipaddress
import json
import os
import threading
import time
import urllib.request
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urlparse

import httpx

from ..utils.exceptions import ServerError
from ..utils.logging_config import get_logger
from ..utils.validation import api_key_problem

logger = get_logger(__name__)

#: Environment variable that silences the plain-HTTP warning.
ALLOW_INSECURE_HTTP_ENV = "MATTSTASH_ALLOW_INSECURE_HTTP"
_TRUTHY = frozenset({"1", "true", "yes"})

#: Largest response accepted (a listing of thousands of secrets is far below this).
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
#: Largest error body inspected (only to recognise the server's own "Credential not found" answer).
_MAX_ERROR_BODY_BYTES = 64 * 1024
#: Retries of a rate-limited (429) GET, and the longest single wait.
MAX_RETRIES = 3
_MAX_RETRY_WAIT = 60.0
#: Server answers whose text is fixed and value-free, so they may be shown to the user.
_SAFE_DETAIL_PREFIXES = ("Entry cannot be used for a database URL:", "Invalid dialect name", "Invalid driver name")


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


def _http_proxy_applies(host: Optional[str]) -> bool:
    """True if the environment (``HTTP_PROXY``/``ALL_PROXY`` minus ``NO_PROXY``) proxies plain-http requests."""
    proxies = urllib.request.getproxies()
    if not (proxies.get("http") or proxies.get("all")):
        return False
    try:
        return not urllib.request.proxy_bypass(host or "")
    except Exception:  # unusable proxy settings: assume the proxy is used
        return True


def warn_if_insecure(base_url: str) -> bool:
    """Log one warning if the API key would travel in clear text. Returns True if it warned.

    That is the case for ``http://`` to a non-loopback host, and for ``http://`` to *any* host when an
    ``HTTP_PROXY`` applies (the key then goes to the proxy, loopback or not).
    """
    try:
        parsed = urlparse(base_url)
        host = parsed.hostname
    except ValueError:
        return False
    if parsed.scheme.lower() != "http" or insecure_http_allowed():
        return False
    if is_loopback_host(host) and not _http_proxy_applies(host):
        return False
    logger.warning(
        "The API key is sent in clear text to %s over plain http://. Use an https:// URL, or set %s=1 "
        "if this network is trusted.",
        host or "the server",
        ALLOW_INSECURE_HTTP_ENV,
    )
    return True


def _is_ascii_digits(text: str) -> bool:
    """``str.isdigit`` accepts superscripts and other Unicode digits that ``float``/``int`` then refuse."""
    return text.isascii() and text.isdigit()


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
    404: "not found: a wrong --server-url, or a name the server cannot route (letters, digits, '_', '.', '-')",
    405: "the server does not allow this operation (it may be read-only)",
    413: "the request is too large for the server",
    429: "too many requests; slow down and retry",
}


class MattStashServerClient:
    """Client for MattStash API server."""

    def __init__(self, base_url: str, api_key: str, timeout: float = 30.0, total_timeout: float = 120.0):
        """
        Initialize server client.

        Args:
            base_url: Base URL of MattStash server (e.g., http://localhost:8000)
            api_key: API key for authentication (visible ASCII only)
            timeout: Per-operation socket timeout in seconds
            total_timeout: Upper bound for one whole request/response exchange (a slow-drip server cannot exceed it)

        Raises:
            ServerError: the URL or the key cannot be used (the message never contains either).
        """
        base_url = base_url.strip().rstrip("/")
        try:
            parsed = urlparse(base_url)
            usable = (
                parsed.scheme.lower() in ("http", "https")
                and bool(parsed.hostname)
                and parsed.port != 0  # also raises ValueError for a malformed port
                # Everything after the host would silently misroute the API path (query, fragment) or put a password
                # into repr()/Authorization (userinfo): the base URL is scheme://host[:port][/prefix] only.
                and not (parsed.query or parsed.fragment or parsed.username or parsed.password or "?" in base_url)
            )
        except ValueError:
            usable = False
        if not usable or not base_url.isprintable() or any(ch.isspace() for ch in base_url):
            raise ServerError(
                "the server URL must look like http(s)://host[:port][/prefix] (no query, fragment or user:password)"
            )
        problem = api_key_problem(api_key)
        if problem:
            raise ServerError(problem)
        self.base_url = base_url
        self.api_key = api_key
        self.timeout = timeout
        self.total_timeout = total_timeout
        # `identity`: the API has no use for compression, and an inflating response is a memory-bomb vector.
        self.headers = {"X-API-Key": api_key, "Accept-Encoding": "identity"}
        self._client: Optional[httpx.Client] = None
        warn_if_insecure(self.base_url)

    def __repr__(self) -> str:
        return f"MattStashServerClient(base_url={self.base_url!r})"

    def close(self) -> None:
        """Close the connection pool (also happens when the process exits)."""
        if self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> "MattStashServerClient":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # ---- plumbing -----------------------------------------------------------

    def _redact(self, text: str) -> str:
        """Remove the API key from text that is about to be shown."""
        if self.api_key:
            for form in (self.api_key, repr(self.api_key)[1:-1]):
                text = text.replace(form, "***")
        return text

    @staticmethod
    def _loads(body: bytes) -> Any:
        """``json.loads`` that reports every problem (bad bytes, absurd nesting) as ``ValueError``."""
        try:
            return json.loads(body)
        except RecursionError:
            raise ValueError("JSON nested too deeply") from None

    @classmethod
    def _safe_detail(cls, body: bytes) -> Optional[str]:
        """The server's ``detail`` text, but only if it is one of its fixed, value-free messages."""
        try:
            payload = cls._loads(body)
        except ValueError:
            return None
        detail = payload.get("detail") if isinstance(payload, dict) else None
        if isinstance(detail, str) and detail.startswith(_SAFE_DETAIL_PREFIXES) and detail.isprintable():
            return detail[:200]
        return None

    @classmethod
    def _is_missing_secret(cls, body: bytes) -> bool:
        try:
            payload = cls._loads(body)
        except ValueError:
            return False
        detail = payload.get("detail") if isinstance(payload, dict) else None
        return isinstance(detail, str) and detail.startswith("Credential not found")

    def _status_error(self, method: str, endpoint: str, response: "httpx.Response", body: bytes) -> ServerError:
        code = response.status_code
        message = f"server returned HTTP {code} for {method} {endpoint}"
        hint = _STATUS_HINTS.get(code)
        if code >= 500:
            hint = "server-side error"
        elif 300 <= code < 400:
            hint = "unexpected redirect (redirects are not followed; check the server URL, e.g. http vs https)"
        if hint:
            message += f" ({hint})"
        if code == 400:
            detail = self._safe_detail(body)
            if detail:
                message += f": {detail}"
        retry_after = response.headers.get("Retry-After", "")
        if code == 429 and _is_ascii_digits(retry_after):
            message += f"; retry after {retry_after}s"
        missing = code == 404 and self._is_missing_secret(body)
        if missing:
            message = f"server returned HTTP 404 for {method} {endpoint} (credential not found)"
        return ServerError(message, status_code=code, secret_missing=missing)

    def _exchange(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]],
        json_data: Optional[Dict[str, Any]],
    ) -> "tuple[httpx.Response, bytes]":
        """One request; the body is read with a size and time bound. Raises ``httpx`` errors and ``ServerError``."""
        if self._client is None:
            self._client = httpx.Client(timeout=self.timeout, verify=True)
        client = self._client
        deadline = time.monotonic() + self.total_timeout
        # httpx's timeouts are per socket operation, so a server that dribbles its response HEADERS one byte at a time
        # would never trip them. A watchdog enforces the real wall-clock bound by closing the connection.
        expired = threading.Event()

        def abort() -> None:
            expired.set()
            with contextlib.suppress(Exception):
                client.close()

        watchdog = threading.Timer(self.total_timeout, abort)
        watchdog.daemon = True
        watchdog.start()
        try:
            with client.stream(
                method, f"{self.base_url}{endpoint}", headers=self.headers, params=params, json=json_data
            ) as response:
                limit = MAX_RESPONSE_BYTES if response.is_success else _MAX_ERROR_BODY_BYTES
                declared = response.headers.get("Content-Length", "")
                if _is_ascii_digits(declared) and int(declared) > limit:
                    raise ServerError("server response is too large", status_code=response.status_code)
                chunks: List[bytes] = []
                received = 0
                for chunk in response.iter_bytes():
                    received += len(chunk)
                    if received > limit:
                        if response.is_success:
                            raise ServerError("server response is too large", status_code=response.status_code)
                        break  # an oversized error page: the part read is enough to classify it
                    chunks.append(chunk)
                    if time.monotonic() > deadline:
                        raise ServerError(f"server did not finish responding within {self.total_timeout:g}s")
                return response, b"".join(chunks)
        except Exception:
            if expired.is_set():
                self._client = None  # the watchdog closed it
                raise ServerError(f"server did not finish responding within {self.total_timeout:g}s") from None
            raise
        finally:
            watchdog.cancel()

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
        attempt = 0
        while True:
            try:
                response, body = self._exchange(method, endpoint, params, json_data)
            except ServerError:
                raise
            except (httpx.InvalidURL, UnicodeError):
                # Never include the exception text: it may quote the URL.
                raise ServerError("the request could not be built (invalid server URL or secret name)") from None
            except httpx.HTTPError as exc:
                detail = self._redact(str(exc)).strip()[:200]
                raise ServerError(
                    f"request to server failed ({type(exc).__name__}{': ' + detail if detail else ''})"
                ) from None

            if response.status_code == 429 and method == "GET" and attempt < MAX_RETRIES:
                retry_after = response.headers.get("Retry-After", "")
                wait = min(float(retry_after), _MAX_RETRY_WAIT) if _is_ascii_digits(retry_after) else 2.0**attempt
                logger.warning("The server is rate limiting this client (HTTP 429); retrying in %gs", wait)
                time.sleep(wait)
                attempt += 1
                continue
            break

        if not response.is_success:
            raise self._status_error(method, endpoint, response, body)
        try:
            result = self._loads(body)
        except ValueError:
            raise ServerError("server returned a response that is not valid JSON") from None
        if not isinstance(result, dict):
            raise ServerError("server returned an unexpected response format")
        return result

    @staticmethod
    def _require(result: Dict[str, Any], key: str, kind: type) -> Any:
        """``result[key]`` if it has the expected type, else a ``ServerError`` (success must look like success)."""
        value = result.get(key)
        if not isinstance(value, kind):
            raise ServerError(f"server returned an unexpected response (missing or invalid '{key}')")
        return value

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

            result = self._make_request("GET", f"/api/v1/credentials/{segment(title)}", params=params)
        except ServerError as e:
            if e.secret_missing:
                return None
            raise
        self._require(result, "name", str)
        return result

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

        # Handle notes/comment (same precedence as the local database: --notes wins over --comment)
        final_notes = notes if notes is not None else comment
        if final_notes is not None:
            data["notes"] = final_notes

        if tags:
            data["tags"] = tags

        result = self._make_request("POST", f"/api/v1/credentials/{segment(title)}", json_data=data)
        self._require(result, "name", str)
        return result

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
            result = self._make_request("DELETE", f"/api/v1/credentials/{segment(title)}", params=params)
        except ServerError as e:
            if e.secret_missing:
                return False
            raise
        self._require(result, "detail", str)
        return True

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
        creds: List[Dict[str, Any]] = self._require(result, "credentials", list)
        if not all(isinstance(c, dict) for c in creds):
            raise ServerError("server returned an unexpected response (invalid 'credentials')")
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
        except ServerError as e:
            if e.secret_missing:
                return []
            raise
        vers: List[str] = self._require(result, "versions", list)
        return vers

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
        if driver is not None:  # "" is meaningful: no driver suffix
            params["driver"] = driver
        if dialect and dialect.strip():  # blank means "not given", exactly as in local mode
            params["dialect"] = dialect
        if database:
            params["database"] = database

        result = self._make_request("GET", f"/api/v1/db-url/{segment(title)}", params=params)
        url: str = self._require(result, "url", str)
        if not url:
            raise ServerError("server returned an unexpected response (empty 'url')")
        return url
