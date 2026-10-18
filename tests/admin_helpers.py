"""Shared helpers for the ``mattstash admin`` tests: a runner, and a fake admin API over a real policy file."""

import json
import re
from pathlib import Path
from typing import Any, Callable, NamedTuple, Optional

import httpx
import pytest

from mattstash.authz import PolicyError, empty_policy, save_policy
from mattstash.cli.handlers.admin import AdminError, _LocalBackend
from mattstash.cli.main import main

TOKEN_RE = re.compile(r"mst_[a-z2-7]{12}_[A-Za-z0-9_-]+")


class Result(NamedTuple):
    code: int
    out: str
    err: str


class Runner:
    """Runs ``main(argv)`` and returns the exit code with stdout and everything written to stderr or the log."""

    def __init__(self, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture) -> None:
        self.capsys = capsys
        self.caplog = caplog

    def __call__(self, *argv: str) -> Result:
        self.capsys.readouterr()
        self.caplog.clear()
        code = main(list(argv))
        captured = self.capsys.readouterr()
        return Result(code, captured.out, captured.err + self.caplog.text)


class FakeAdminServer:
    """The admin API of docs/design and the contract, implemented over a policy file with the library.

    It answers exactly like the contract says (statuses, ``detail`` texts, shapes), so the real
    ``MattStashServerClient`` and ``AdminHandler`` run end to end against it.
    """

    def __init__(self, policy_file: Path, api_key: str, *, log_file: Optional[Path] = None) -> None:
        self.api_key = api_key
        save_policy(policy_file, empty_policy())
        self.policy_file = policy_file
        self.log_file = log_file
        self.requests: list[httpx.Request] = []
        self.is_admin = True
        self.read_only = False
        self.no_policy = False
        self.warning: Optional[str] = None  # saved but not active: every successful mutation carries this text
        self.forced: Optional[Callable[[httpx.Request], Optional[httpx.Response]]] = None

    def install(self, monkeypatch: pytest.MonkeyPatch) -> "FakeAdminServer":
        real_client = httpx.Client

        def factory(**kwargs: Any) -> httpx.Client:
            return real_client(transport=httpx.MockTransport(self.handler), **kwargs)

        monkeypatch.setattr(httpx, "Client", factory)
        return self

    @staticmethod
    def _reply(status: int, payload: Any) -> httpx.Response:
        return httpx.Response(status, json=payload)

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.headers.get("X-API-Key") != self.api_key:
            return self._reply(401, {"detail": "Authentication failed"})
        if self.forced is not None:
            forced = self.forced(request)
            if forced is not None:
                return forced
        if not self.is_admin:
            return self._reply(403, {"detail": "Insufficient permissions"})
        raw = request.url.raw_path.decode().split("?")[0]
        prefix = "/api/v1/admin/"
        if not raw.startswith(prefix):
            return self._reply(404, {"detail": "Not Found"})
        from urllib.parse import unquote

        parts = [unquote(p) for p in raw[len(prefix) :].split("/")]
        mutating = request.method != "GET"
        if mutating and parts[0] != "check":
            if self.no_policy:
                return self._reply(503, {"detail": "No policy file configured (MATTSTASH_POLICY_FILE)"})
            if self.read_only:
                return self._reply(
                    409,
                    {"detail": "Policy file is read-only; edit it and POST /admin/invalidate-api-key-cache"},
                )
        body = json.loads(request.content) if request.content else {}
        backend = _LocalBackend(str(self.policy_file), str(self.log_file) if self.log_file else None)
        try:
            status, payload = self._route(request, backend, parts, body)
        except AdminError as exc:
            return self._reply(404, {"detail": str(exc)})
        except PolicyError as exc:
            text = str(exc)
            return self._reply(400, {"detail": text})
        if self.warning is not None and mutating and status < 300 and isinstance(payload, dict):
            payload = {**payload, "warning": self.warning}
        return self._reply(status, payload)

    def _route(self, request: httpx.Request, b: _LocalBackend, parts: list[str], body: dict[str, Any]) -> Any:
        method = request.method
        query = dict(request.url.params)
        match (method, parts):
            case ("GET", ["principals"]):
                return 200, {"principals": b.principals()}
            case ("POST", ["principals"]):
                made = b.principal_add(
                    body["name"], body["kind"], body.get("description", ""), body.get("admin", False)
                )
                return 201, made
            case ("GET", ["principals", name]):
                return 200, b.principal(name)
            case ("PATCH", ["principals", name]):
                if "disabled" in body:
                    return 200, b.principal_set_disabled(name, body["disabled"])
                return 200, b.principal_update(name, body.get("admin"), body.get("description"))
            case ("DELETE", ["principals", name]):
                return 200, b.principal_remove(name)
            case ("GET", ["principals", name, "tokens"]):
                return 200, {"tokens": b.tokens(name)}
            case ("POST", ["principals", name, "tokens"]):
                issued = b.token_issue(name, body.get("expires"), body.get("description", ""))
                return 201, issued
            case ("POST", ["principals", name, "tokens", "import"]):
                imported = b.token_import(
                    name, body["key"], body.get("expires"), body.get("description", ""), body.get("min_length", 32)
                )
                return 201, imported
            case ("DELETE", ["principals", name, "tokens", token_id]):
                return 200, b.token_revoke(name, token_id)
            case ("POST", ["principals", name, "tokens", token_id, "rotate"]):
                rotated = b.token_rotate(
                    name, token_id, body.get("grace"), body.get("expires"), body.get("description", "")
                )
                return 201, rotated
            case ("GET", ["grants"]):
                return 200, {"grants": b.grants(query.get("principal"))}
            case ("POST", ["grants"]):
                grant = b.grant_add(
                    body["principal"],
                    body.get("key"),
                    body.get("tag"),
                    body.get("actions", ["list", "read"]),
                    body.get("expires"),
                    body.get("description", ""),
                )
                return 201, grant
            case ("DELETE", ["grants", grant_id]):
                return 200, b.grant_remove(grant_id)
            case ("POST", ["check"]):
                return 200, b.check(body["principal"], body["action"], body["name"], body.get("tags", []))
            case ("GET", ["access-log"]):
                if self.log_file is None:
                    return 503, {"detail": "No access log file configured (MATTSTASH_ACCESS_LOG_FILE)"}
                records = b.log(
                    query.get("principal"), query.get("decision"), query.get("since"), int(query.get("limit", "100"))
                )
                return 200, {"records": records, "count": len(records)}
        return 404, {"detail": "Not Found"}  # pragma: no cover
