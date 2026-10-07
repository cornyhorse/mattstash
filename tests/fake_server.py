"""In-process fake of the MattStash server API, used to test the CLI's server mode without Docker.

``FakeServer.install`` swaps ``httpx.Client`` for one that talks to a ``MockTransport``, so the real
``MattStashServerClient`` code path (URL building, encoding, error mapping) is exercised.
Every request is recorded (raw path as sent on the wire, query, headers, body).
"""

import json
from typing import Any, Callable, Dict, Optional
from urllib.parse import unquote

import httpx
import pytest

_FIELDS = ("username", "password", "url", "notes")
Entry = Dict[str, Optional[str]]


class FakeServer:
    """Minimal server: ``store`` maps a base name to ``{version number: entry}``."""

    def __init__(self, api_key: str = "test-api-key", *, allow_writes: bool = True) -> None:
        self.api_key = api_key
        self.allow_writes = allow_writes
        self.store: Dict[str, Dict[int, Entry]] = {}
        self.requests: list[httpx.Request] = []
        #: Optional hook to force a response: ``override(request) -> Response | None``.
        self.override: Optional[Callable[[httpx.Request], Optional[httpx.Response]]] = None

    # ---- test helpers ---------------------------------------------------------

    def add(self, name: str, password: Optional[str] = None, **fields: Optional[str]) -> None:
        """Add a new version of ``name`` (the next number)."""
        entry: Entry = {"username": None, "password": password, "url": None, "notes": None}
        entry.update(fields)
        versions = self.store.setdefault(name, {})
        versions[max(versions, default=0) + 1] = entry

    def install(self, monkeypatch: pytest.MonkeyPatch) -> "FakeServer":
        real_client = httpx.Client

        def factory(**kwargs: Any) -> httpx.Client:
            return real_client(transport=httpx.MockTransport(self.handler), **kwargs)

        monkeypatch.setattr(httpx, "Client", factory)
        return self

    # ---- the API --------------------------------------------------------------

    @staticmethod
    def _json(status: int, payload: Dict[str, Any]) -> httpx.Response:
        return httpx.Response(status, json=payload)

    def _credential(self, name: str, version: Optional[int], show: bool) -> Optional[Dict[str, Any]]:
        versions = self.store.get(name)
        if not versions:
            return None
        number = max(versions) if version is None else version
        entry = versions.get(number)
        if entry is None:
            return None
        password = entry["password"]
        return {
            "name": name,
            "username": entry["username"],
            "password": password if show else "*****",
            "url": entry["url"],
            "notes": entry["notes"],
            "version": str(number).zfill(10),
        }

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.headers.get("X-API-Key") != self.api_key:
            return self._json(401, {"detail": "Invalid API key"})
        if self.override is not None:
            forced = self.override(request)
            if forced is not None:
                return forced

        raw_path = request.url.raw_path.decode().split("?")[0]
        parts = raw_path.split("/")
        query = dict(request.url.params)
        # ['', 'api', 'v1', 'credentials', '<name>', ('versions')]
        if parts[:4] == ["", "api", "v1", "credentials"]:
            if len(parts) == 4 and request.method == "GET":
                return self._list(query)
            name = unquote(parts[4]) if len(parts) > 4 else ""
            if len(parts) == 6 and parts[5] == "versions" and request.method == "GET":
                versions = sorted(self.store.get(name, {}))
                if not versions:
                    return self._json(404, {"detail": f"Credential not found: {name}"})
                labels = [str(n).zfill(10) for n in versions]
                return self._json(200, {"name": name, "versions": labels, "latest": labels[-1]})
            if len(parts) == 5:
                return self._credential_route(request, name, query)
        if len(parts) == 5 and parts[:4] == ["", "api", "v1", "db-url"]:
            return self._json(200, {"url": f"fake://{unquote(parts[4])}?{request.url.query.decode()}"})
        return self._json(404, {"detail": "no such route"})

    def _list(self, query: Dict[str, str]) -> httpx.Response:
        show = query.get("show_password") == "true"
        prefix = query.get("prefix") or ""
        creds = []
        for name in sorted(self.store):
            if name.startswith(prefix):
                cred = self._credential(name, None, show)
                if cred is not None:
                    creds.append(cred)
        return self._json(200, {"credentials": creds, "count": len(creds)})

    def _credential_route(self, request: httpx.Request, name: str, query: Dict[str, str]) -> httpx.Response:
        if request.method == "GET":
            version = int(query["version"]) if "version" in query else None
            cred = self._credential(name, version, query.get("show_password") == "true")
            if cred is None:
                return self._json(404, {"detail": f"Credential not found: {name}"})
            return self._json(200, cred)
        if not self.allow_writes:
            return self._json(405, {"detail": "writes are disabled; secret-looking detail should never be shown"})
        if request.method == "POST":
            body = json.loads(request.content or b"{}")
            entry: Entry = {"username": None, "password": None, "url": None, "notes": None}
            if "value" in body:
                entry["password"] = body["value"]
            for key in _FIELDS:
                if key in body:
                    entry[key] = body[key]
            versions = self.store.setdefault(name, {})
            number = max(versions, default=0) + 1
            versions[number] = entry
            return self._json(201, {"name": name, "version": str(number).zfill(10), "created": True})
        if request.method == "DELETE":
            versions = self.store.get(name)
            if not versions:
                return self._json(404, {"detail": f"Credential not found: {name}"})
            if "version" in query:
                if int(query["version"]) not in versions:
                    return self._json(404, {"detail": f"Credential not found: {name}"})
                del versions[int(query["version"])]
                if not versions:
                    del self.store[name]
            else:
                del self.store[name]
            return self._json(200, {"detail": f"Credential deleted: {name}"})
        return self._json(405, {"detail": "method not allowed"})
