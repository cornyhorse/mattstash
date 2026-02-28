"""
mattstash.cli.http_client
-------------------------
HTTP client for communicating with MattStash API server.
"""

from typing import Any, Dict, List, Optional

import httpx


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
            endpoint: API endpoint path
            params: Query parameters
            json_data: JSON request body

        Returns:
            Response data as dictionary

        Raises:
            httpx.HTTPError: On network or HTTP errors
        """
        url = f"{self.base_url}{endpoint}"

        with httpx.Client(timeout=self.timeout) as client:
            response = client.request(method=method, url=url, headers=self.headers, params=params, json=json_data)
            response.raise_for_status()
            result: Dict[str, Any] = response.json()
            return result

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

            result = self._make_request("GET", f"/api/v1/credentials/{title}", params=params)
            return result
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
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
            data["password"] = value
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

        result = self._make_request("POST", f"/api/v1/credentials/{title}", json_data=data)
        return result

    def delete(self, title: str) -> bool:
        """
        Delete credential from server.

        Args:
            title: Credential name

        Returns:
            True if deleted, False if not found
        """
        try:
            self._make_request("DELETE", f"/api/v1/credentials/{title}")
            return True
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
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
            result = self._make_request("GET", f"/api/v1/credentials/{title}/versions")
            vers: List[str] = result.get("versions", [])
            return vers
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
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
        self, title: str, driver: str = "psycopg", database: Optional[str] = None, mask_password: bool = True
    ) -> str:
        """
        Get database URL from credential.

        Args:
            title: Credential name
            driver: Database driver
            database: Database name override
            mask_password: Whether to mask password in URL

        Returns:
            Database URL string
        """
        params = {"driver": driver, "mask_password": mask_password}
        if database:
            params["database"] = database

        result = self._make_request("GET", f"/api/v1/db-url/{title}", params=params)
        url: str = result.get("url", "")
        return url
