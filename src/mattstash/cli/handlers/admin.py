"""
mattstash.cli.handlers.admin
----------------------------
``mattstash admin ...``: principals, tokens, grants, ``check`` and the access log (design section 8).

Two modes with one set of commands. A *backend* turns each operation into data shaped like the admin HTTP contract
(``PrincipalOut``, ``TokenOut``, ``GrantOut`` ...), and the handler formats that data:

* server mode (``--server-url``): :class:`_ServerBackend` calls ``/api/v1/admin/...`` through the hardened client;
* local mode (``--policy-file`` / ``MATTSTASH_POLICY_FILE``): :class:`_LocalBackend` edits the policy file directly with
  :mod:`mattstash.authz` (bootstrapping the first admin, offline repair). The file's permissions are the access control.

Token plaintext is printed once, alone on stdout (or written to a new 0600 file) and never logged.
"""

import argparse
import contextlib
import json
import os
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol

from ...authz import (
    ACTIONS,
    KINDS,
    Grant,
    PolicyError,
    Principal,
    Token,
    edit_policy,
    evaluate,
    load_policy,
    parse_duration_or_time,
    read_records,
    validate_pattern,
    validate_tag,
)
from ...authz.models import utcnow
from ...utils.exceptions import ServerError
from .. import exit_codes
from ..inputs import InputError
from .base import BaseHandler

POLICY_FILE_ENV = "MATTSTASH_POLICY_FILE"
ACCESS_LOG_FILE_ENV = "MATTSTASH_ACCESS_LOG_FILE"
DEFAULT_MIN_KEY_LENGTH = 32
MAX_LOG_LIMIT = 1000
_MAX_MIGRATION_FILE = 4 * 1024 * 1024
_RELATIVE = re.compile(r"\d{1,6}[mhdw]", re.ASCII)

Data = Dict[str, Any]


class AdminError(Exception):
    """A failure to report as ``mattstash: <message>``; ``code`` is the process exit status."""

    def __init__(self, message: str, code: int = exit_codes.ERROR) -> None:
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# Serialisation (policy objects -> the shapes of the HTTP contract; never a hash)
# ---------------------------------------------------------------------------


def _ts(value: Optional[datetime]) -> Optional[str]:
    return None if value is None else value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _token_out(token: Token, now: datetime) -> Data:
    return {
        "id": token.id,
        "created": _ts(token.created),
        "expires": _ts(token.expires),
        "description": token.description,
        "expired": token.is_expired(now),
    }


def _principal_out(principal: Principal, now: datetime) -> Data:
    return {
        "name": principal.name,
        "kind": principal.kind,
        "description": principal.description,
        "admin": principal.admin,
        "disabled": principal.disabled,
        "created": _ts(principal.created),
        "legacy": False,
        "tokens": [_token_out(token, now) for token in principal.tokens],
    }


def _grant_out(grant: Grant, now: datetime) -> Data:
    return {
        "id": grant.id,
        "principal": grant.principal,
        "key": grant.key,
        "tag": grant.tag,
        "actions": sorted(grant.actions),
        "expires": _ts(grant.expires),
        "description": grant.description,
        "created": _ts(grant.created),
        "expired": grant.is_expired(now),
        "legacy": False,
    }


def _now() -> datetime:
    return utcnow().replace(microsecond=0)


def _since(text: str, now: datetime) -> datetime:
    """``24h`` means 24 hours ago; anything else is an absolute date or time."""
    cleaned = text.strip()
    if _RELATIVE.fullmatch(cleaned):
        return now - (parse_duration_or_time(cleaned, now) - now)
    return parse_duration_or_time(cleaned, now)


# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------


class _Backend(Protocol):
    """One method per operation; results have the shapes of the admin HTTP contract."""

    def principals(self) -> List[Data]:
        """All principals."""

    def principal(self, name: str) -> Data:
        """One principal, with its ``grants``."""

    def principal_add(self, name: str, kind: str, description: str, admin: bool) -> Data:
        """Create a principal."""

    def principal_set_disabled(self, name: str, disabled: bool) -> Data:
        """Disable or enable a principal."""

    def principal_remove(self, name: str) -> Data:
        """Remove a principal and its grants."""

    def tokens(self, principal: str) -> List[Data]:
        """The tokens of a principal."""

    def token_issue(self, principal: str, expires: Optional[str], description: str) -> Data:
        """Issue a token; the result holds the plaintext."""

    def token_revoke(self, principal: str, token_id: str) -> Data:
        """Revoke a token."""

    def token_rotate(
        self, principal: str, token_id: str, grace: Optional[str], expires: Optional[str], description: str
    ) -> Data:
        """Issue a replacement token and retire the old one."""

    def grants(self, principal: Optional[str]) -> List[Data]:
        """All grants, or those of one principal."""

    def grant_add(
        self,
        principal: str,
        key: Optional[str],
        tag: Optional[str],
        actions: List[str],
        expires: Optional[str],
        description: str,
    ) -> Data:
        """Create a grant."""

    def grant_remove(self, grant_id: str) -> Data:
        """Remove a grant."""

    def check(self, principal: str, action: str, name: str, tags: List[str]) -> Data:
        """Would this be allowed, and by which grant?"""

    def log(self, principal: Optional[str], decision: Optional[str], since: Optional[str], limit: int) -> List[Data]:
        """The newest matching access-log records, oldest first."""


class _LocalBackend:
    """Operations on a policy file (and an access-log file) on this machine."""

    def __init__(self, policy_file: Optional[str], log_file: Optional[str]) -> None:
        self.policy_file = policy_file
        self.log_file = log_file

    def _path(self) -> str:
        if self.policy_file is None:  # pragma: no cover - only `log` runs without one, and it never calls this
            raise AdminError("this command needs a policy file: use --policy-file or set " + POLICY_FILE_ENV)
        return self.policy_file

    def _load(self) -> Any:
        path = self._path()
        try:
            return load_policy(path)
        except FileNotFoundError:
            raise AdminError(
                f"policy file not found: {path} (create it with `mattstash admin --policy-file {path} "
                "principal add NAME --kind human-device --admin`)"
            ) from None

    @staticmethod
    def _find(policy: Any, name: str) -> Principal:
        found = policy.principal(name)
        if found is None:
            raise AdminError(f"Principal not found: {name}", exit_codes.NOT_FOUND)
        return found  # type: ignore[no-any-return]

    @classmethod
    def _find_token(cls, policy: Any, principal: str, token_id: str) -> None:
        if all(token.id != token_id for token in cls._find(policy, principal).tokens):
            raise AdminError(f"Token not found: {token_id}", exit_codes.NOT_FOUND)

    def principals(self) -> List[Data]:
        now = _now()
        return [_principal_out(p, now) for p in self._load().principals]

    def principal(self, name: str) -> Data:
        policy = self._load()
        now = _now()
        found = self._find(policy, name)
        out = _principal_out(found, now)
        out["grants"] = [_grant_out(g, now) for g in policy.grants_for(found.name)]
        return out

    def principal_add(self, name: str, kind: str, description: str, admin: bool) -> Data:
        with edit_policy(self._path(), create=True) as editor:  # the first principal bootstraps the file
            created = editor.add_principal(name, kind, description, admin)
        return _principal_out(created, _now())

    def principal_set_disabled(self, name: str, disabled: bool) -> Data:
        with edit_policy(self._path()) as editor:
            self._find(editor.policy, name)
            editor.set_disabled(name, disabled)
            updated = self._find(editor.policy, name)
        return _principal_out(updated, _now())

    def principal_remove(self, name: str) -> Data:
        with edit_policy(self._path()) as editor:
            found = self._find(editor.policy, name)
            removed = editor.remove_principal(name)
        return {"detail": f"Principal removed: {found.name}", "grants_removed": removed}

    def tokens(self, principal: str) -> List[Data]:
        tokens: List[Data] = self.principal(principal)["tokens"]
        return tokens

    def token_issue(self, principal: str, expires: Optional[str], description: str) -> Data:
        now = _now()
        when = None if expires is None else parse_duration_or_time(expires, now)
        with edit_policy(self._path(), now=now) as editor:
            self._find(editor.policy, principal)
            token, plaintext = editor.issue_token(principal, when, description)
        return {"token": plaintext, "id": token.id, "expires": _ts(token.expires)}

    def token_revoke(self, principal: str, token_id: str) -> Data:
        with edit_policy(self._path()) as editor:
            self._find_token(editor.policy, principal, token_id)
            editor.revoke_token(principal, token_id)
        return {"detail": f"Token revoked: {token_id}"}

    def token_rotate(
        self, principal: str, token_id: str, grace: Optional[str], expires: Optional[str], description: str
    ) -> Data:
        now = _now()
        delay = timedelta(0) if grace is None else parse_duration_or_time(grace, now) - now
        when = None if expires is None else parse_duration_or_time(expires, now)
        with edit_policy(self._path(), now=now) as editor:
            self._find_token(editor.policy, principal, token_id)
            token, plaintext = editor.rotate_token(principal, token_id, delay, when, description)
            old_expires: Optional[str] = None
            for kept in self._find(editor.policy, principal).tokens:
                if kept.id == token_id:  # still there only during a grace period
                    old_expires = _ts(kept.expires)
        return {"token": plaintext, "id": token.id, "expires": _ts(token.expires), "old_token_expires": old_expires}

    def grants(self, principal: Optional[str]) -> List[Data]:
        policy = self._load()
        now = _now()
        if principal is None:
            return [_grant_out(g, now) for g in policy.grants]
        found = self._find(policy, principal)
        return [_grant_out(g, now) for g in policy.grants_for(found.name)]

    def grant_add(
        self,
        principal: str,
        key: Optional[str],
        tag: Optional[str],
        actions: List[str],
        expires: Optional[str],
        description: str,
    ) -> Data:
        now = _now()
        when = None if expires is None else parse_duration_or_time(expires, now)
        with edit_policy(self._path(), now=now) as editor:
            self._find(editor.policy, principal)
            grant = editor.add_grant(principal, key, tag, actions, when, description)
        return _grant_out(grant, now)

    def grant_remove(self, grant_id: str) -> Data:
        with edit_policy(self._path()) as editor:
            try:
                editor.remove_grant(grant_id)
            except PolicyError:
                raise AdminError(f"Grant not found: {grant_id}", exit_codes.NOT_FOUND) from None
        return {"detail": f"Grant removed: {grant_id}"}

    def check(self, principal: str, action: str, name: str, tags: List[str]) -> Data:
        policy = self._load()
        decision = evaluate(policy, self._find(policy, principal), action, name, tags)
        return {"allowed": decision.allowed, "reason": decision.reason, "grant": decision.grant_id}

    def log(self, principal: Optional[str], decision: Optional[str], since: Optional[str], limit: int) -> List[Data]:
        if self.log_file is None:
            raise AdminError("no access log file: use --log-file or set " + ACCESS_LOG_FILE_ENV)
        moment = None if since is None else _since(since, _now())
        return read_records(self.log_file, principal=principal, decision=decision, since=moment, limit=limit)


class _ServerBackend:
    """Operations through the server's admin API."""

    def __init__(self, client: Any) -> None:
        self.client = client

    def principals(self) -> List[Data]:
        return self.client.admin_principals()  # type: ignore[no-any-return]

    def principal(self, name: str) -> Data:
        return self.client.admin_principal(name)  # type: ignore[no-any-return]

    def principal_add(self, name: str, kind: str, description: str, admin: bool) -> Data:
        return self.client.admin_principal_add(name, kind, description, admin)  # type: ignore[no-any-return]

    def principal_set_disabled(self, name: str, disabled: bool) -> Data:
        return self.client.admin_principal_update(name, {"disabled": disabled})  # type: ignore[no-any-return]

    def principal_remove(self, name: str) -> Data:
        return self.client.admin_principal_remove(name)  # type: ignore[no-any-return]

    def tokens(self, principal: str) -> List[Data]:
        return self.client.admin_tokens(principal)  # type: ignore[no-any-return]

    def token_issue(self, principal: str, expires: Optional[str], description: str) -> Data:
        return self.client.admin_token_issue(principal, expires, description)  # type: ignore[no-any-return]

    def token_revoke(self, principal: str, token_id: str) -> Data:
        return self.client.admin_token_revoke(principal, token_id)  # type: ignore[no-any-return]

    def token_rotate(
        self, principal: str, token_id: str, grace: Optional[str], expires: Optional[str], description: str
    ) -> Data:
        return self.client.admin_token_rotate(principal, token_id, grace, expires, description)  # type: ignore[no-any-return]

    def grants(self, principal: Optional[str]) -> List[Data]:
        return self.client.admin_grants(principal)  # type: ignore[no-any-return]

    def grant_add(
        self,
        principal: str,
        key: Optional[str],
        tag: Optional[str],
        actions: List[str],
        expires: Optional[str],
        description: str,
    ) -> Data:
        return self.client.admin_grant_add(principal, key, tag, actions, expires, description)  # type: ignore[no-any-return]

    def grant_remove(self, grant_id: str) -> Data:
        return self.client.admin_grant_remove(grant_id)  # type: ignore[no-any-return]

    def check(self, principal: str, action: str, name: str, tags: List[str]) -> Data:
        return self.client.admin_check(principal, action, name, tags)  # type: ignore[no-any-return]

    def log(self, principal: Optional[str], decision: Optional[str], since: Optional[str], limit: int) -> List[Data]:
        return self.client.admin_access_log(principal, decision, since, limit)  # type: ignore[no-any-return]


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def _clean(value: Any) -> str:
    """A table cell: ``-`` for missing values, control characters escaped (the text may come from a server)."""
    if value is None or value == "":
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    text = str(value)
    return "".join(
        ch if ch.isprintable() else f"\\x{ord(ch):02x}" if ord(ch) < 256 else f"\\u{ord(ch):04x}" for ch in text
    )


def _table(headers: List[str], rows: List[List[Any]]) -> str:
    cells = [[_clean(c) for c in row] for row in rows]
    widths = [max(len(h), *(len(row[i]) for row in cells)) if cells else len(h) for i, h in enumerate(headers)]
    lines = ["  ".join(h.ljust(w) for h, w in zip(headers, widths, strict=True)).rstrip()]
    lines += ["  ".join(c.ljust(w) for c, w in zip(row, widths, strict=True)).rstrip() for row in cells]
    return "\n".join(lines)


def _strip_hashes(value: Any) -> Any:
    """Defence in depth for ``--json``: whatever produced the data, a token hash is never printed."""
    if isinstance(value, dict):
        return {k: _strip_hashes(v) for k, v in value.items() if k != "hash"}
    if isinstance(value, list):
        return [_strip_hashes(v) for v in value]
    return value


def _state(item: Data) -> str:
    if item.get("disabled"):
        return "disabled"
    return "expired" if item.get("expired") else "active"


def _principal_table(items: List[Data]) -> str:
    rows = [
        [
            p.get("name"),
            p.get("kind"),
            bool(p.get("admin")),
            _state(p),
            len(p.get("tokens") or []),
            p.get("description"),
        ]
        for p in items
    ]
    return _table(["NAME", "KIND", "ADMIN", "STATE", "TOKENS", "DESCRIPTION"], rows)


def _token_table(items: List[Data]) -> str:
    rows = [
        [t.get("id"), t.get("created"), t.get("expires") or "never", _state(t), t.get("description")] for t in items
    ]
    return _table(["ID", "CREATED", "EXPIRES", "STATE", "DESCRIPTION"], rows)


def _selector(grant: Data) -> str:
    return f"key:{grant['key']}" if grant.get("key") is not None else f"tag:{grant.get('tag')}"


def _grant_table(items: List[Data]) -> str:
    rows = [
        [
            g.get("id"),
            g.get("principal"),
            _selector(g),
            ",".join(str(a) for a in g.get("actions") or []),
            g.get("expires") or "never",
            _state(g),
            g.get("description"),
        ]
        for g in items
    ]
    return _table(["ID", "PRINCIPAL", "SELECTOR", "ACTIONS", "EXPIRES", "STATE", "DESCRIPTION"], rows)


_LOG_COLUMNS = ("ts", "principal", "kind", "action", "key", "decision", "reason", "client", "status")


def _log_table(records: List[Data]) -> str:
    return _table([c.upper() for c in _LOG_COLUMNS], [[r.get(c) for c in _LOG_COLUMNS] for r in records])


# ---------------------------------------------------------------------------
# The handler
# ---------------------------------------------------------------------------


def _open_output(path: str) -> int:
    """Create ``path`` exclusively with mode 0600 (refuses to touch an existing file, symlinks included)."""
    try:
        return os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        raise AdminError(f"refusing to overwrite an existing file: {path}") from None


def _split_actions(text: str) -> List[str]:
    actions = [part.strip() for part in text.split(",") if part.strip()]
    unknown = [a for a in actions if a not in ACTIONS]
    if not actions or unknown:
        what = ", ".join(repr(a) for a in unknown) if unknown else "none given"
        raise AdminError(f"--actions must be a comma-separated subset of {', '.join(ACTIONS)} ({what})")
    return list(dict.fromkeys(actions))


class AdminHandler(BaseHandler):
    """Handler for ``mattstash admin ...``."""

    # ---- dispatch ---------------------------------------------------------

    def handle(self, args: argparse.Namespace) -> int:
        op = str(getattr(args, "admin_op", ""))
        client: Any = None
        try:
            if op == "migrate-keys":
                return self._migrate_keys(args)
            backend, client = self._backend(args, op)
            if backend is None:
                return exit_codes.ERROR
            method = getattr(self, "_op_" + op.replace(".", "_"))
            return int(method(backend, args))
        except AdminError as exc:
            self.error(str(exc))
            return exc.code
        except ServerError as exc:
            self.error(str(exc))
            return exit_codes.NOT_FOUND if exc.status_code == 404 else exit_codes.ERROR
        except (PolicyError, InputError) as exc:
            self.error(str(exc))
            return exit_codes.ERROR
        finally:
            if client is not None:
                client.close()

    def _backend(self, args: argparse.Namespace, op: str) -> "tuple[Optional[_Backend], Any]":
        policy_file = self._policy_file(args)
        if self.is_server_mode(args):
            if self.opt(args, "policy_file", str) is not None:
                self.warning("both a server URL and --policy-file are set: using the server (local mode ignored)")
            client = self.get_server_client(args)
            return (None, None) if client is None else (_ServerBackend(client), client)
        log_file = self._log_file(args)
        if policy_file is None and not (op == "log" and log_file is not None):
            raise AdminError(
                "admin commands need a server (--server-url or MATTSTASH_SERVER_URL, with an admin token) or, "
                f"for local mode, a policy file (--policy-file or {POLICY_FILE_ENV})"
            )
        return _LocalBackend(policy_file, log_file), None

    def _policy_file(self, args: argparse.Namespace) -> Optional[str]:
        explicit = self.opt(args, "policy_file", str)
        if explicit is not None:
            if not explicit.strip():
                raise AdminError("--policy-file was given an empty path")
            return explicit
        return (os.environ.get(POLICY_FILE_ENV) or "").strip() or None

    def _log_file(self, args: argparse.Namespace) -> Optional[str]:
        explicit = self.opt(args, "log_file", str)
        if explicit is not None:
            if not explicit.strip():
                raise AdminError("--log-file was given an empty path")
            return explicit
        return (os.environ.get(ACCESS_LOG_FILE_ENV) or "").strip() or None

    def _print_json(self, value: Any) -> None:
        self.say(json.dumps(_strip_hashes(value), indent=2))

    def _output(self, args: argparse.Namespace, data: Any, table: str) -> None:
        if self.flag(args, "json"):
            self._print_json(data)
        else:
            self.say(table if data else "(none)")

    # ---- principals -------------------------------------------------------

    def _op_principal_list(self, backend: _Backend, args: argparse.Namespace) -> int:
        items = backend.principals()
        self._output(args, items, _principal_table(items))
        return exit_codes.OK

    def _op_principal_show(self, backend: _Backend, args: argparse.Namespace) -> int:
        item = backend.principal(args.name)
        if self.flag(args, "json"):
            self._print_json(item)
            return exit_codes.OK
        lines = [
            f"name:        {_clean(item.get('name'))}",
            f"kind:        {_clean(item.get('kind'))}",
            f"admin:       {_clean(bool(item.get('admin')))}",
            f"state:       {_state(item)}",
            f"created:     {_clean(item.get('created'))}",
            f"description: {_clean(item.get('description'))}",
        ]
        if item.get("legacy"):
            lines.append("legacy:      yes (configured outside the policy file)")
        tokens = item.get("tokens") or []
        grants = item.get("grants") or []
        lines += ["", "tokens:", _token_table(tokens) if tokens else "  (none)", "", "grants:"]
        lines.append(_grant_table(grants) if grants else "  (none)")
        self.say("\n".join(lines))
        return exit_codes.OK

    def _op_principal_add(self, backend: _Backend, args: argparse.Namespace) -> int:
        item = backend.principal_add(args.name, args.kind, args.description or "", bool(args.admin))
        self.say(f"created principal {_clean(item.get('name'))} ({_clean(item.get('kind'))})")
        return exit_codes.OK

    def _set_disabled(self, backend: _Backend, args: argparse.Namespace, disabled: bool) -> int:
        item = backend.principal_set_disabled(args.name, disabled)
        self.say(f"{_clean(item.get('name'))}: {'disabled' if disabled else 'enabled'}")
        return exit_codes.OK

    def _op_principal_disable(self, backend: _Backend, args: argparse.Namespace) -> int:
        return self._set_disabled(backend, args, True)

    def _op_principal_enable(self, backend: _Backend, args: argparse.Namespace) -> int:
        return self._set_disabled(backend, args, False)

    def _confirm(self, question: str) -> bool:
        try:
            answer = input(f"{question} [y/N] ")
        except EOFError:
            return False
        return answer.strip().lower() in ("y", "yes")

    def _op_principal_remove(self, backend: _Backend, args: argparse.Namespace) -> int:
        if not self.flag(args, "yes"):
            if not sys.stdin.isatty():
                raise AdminError("refusing to remove a principal without --yes when stdin is not a terminal")
            if not self._confirm(f"Remove principal {args.name!r} and all of its grants and tokens?"):
                self.say("not removed", err=True)
                return exit_codes.ERROR
        result = backend.principal_remove(args.name)
        removed = result.get("grants_removed")
        suffix = f" ({removed} grant{'' if removed == 1 else 's'} removed)" if isinstance(removed, int) else ""
        self.say(f"removed principal {args.name}{suffix}")
        return exit_codes.OK

    # ---- tokens -----------------------------------------------------------

    def _deliver_token(self, args: argparse.Namespace, issue: "Any") -> int:
        """Run ``issue()`` (which returns the contract answer with a plaintext ``token``) and hand the token over.

        With ``--output-file`` the file is created first, so a path problem is found before a token exists that
        nobody could receive.
        """
        path = self.opt(args, "output_file", str)
        descriptor: Optional[int] = None
        if path is not None:
            if not path.strip():
                raise AdminError("--output-file was given an empty path")
            descriptor = _open_output(path)
        try:
            result: Data = issue()
        except BaseException:
            if descriptor is not None:
                os.close(descriptor)
                with contextlib.suppress(OSError):
                    os.unlink(path)  # type: ignore[arg-type]
            raise
        token = str(result["token"])
        expires = result.get("expires")
        if descriptor is not None:
            try:
                with os.fdopen(descriptor, "w", encoding="ascii") as handle:
                    handle.write(token + "\n")
            except (OSError, UnicodeEncodeError) as exc:
                with contextlib.suppress(OSError):
                    os.unlink(path)  # type: ignore[arg-type]
                raise AdminError(
                    f"the token (id {result['id']}) was issued but could not be written to {path}: "
                    f"{getattr(exc, 'strerror', None) or type(exc).__name__}; revoke it and issue another"
                ) from None
        else:
            self.say(token)
        where = f", written to {path}" if path else ""
        self.say(
            f"token id {result['id']}, expires {_clean(expires) if expires else 'never'}{where}. "
            "Shown once; store it now.",
            err=True,
        )
        old = result.get("old_token_expires")
        if "old_token_expires" in result:
            self.say(
                f"the old token {args.token_id} " + (f"stays valid until {old}" if old else "is revoked"), err=True
            )
        return exit_codes.OK

    def _op_token_issue(self, backend: _Backend, args: argparse.Namespace) -> int:
        self._check_expiry(args.expires)
        return self._deliver_token(
            args, lambda: backend.token_issue(args.principal, args.expires, args.description or "")
        )

    def _op_token_rotate(self, backend: _Backend, args: argparse.Namespace) -> int:
        self._check_expiry(args.expires)
        self._check_expiry(args.grace)
        return self._deliver_token(
            args,
            lambda: backend.token_rotate(
                args.principal, args.token_id, args.grace, args.expires, args.description or ""
            ),
        )

    def _op_token_list(self, backend: _Backend, args: argparse.Namespace) -> int:
        items = backend.tokens(args.principal)
        self._output(args, items, _token_table(items))
        return exit_codes.OK

    def _op_token_revoke(self, backend: _Backend, args: argparse.Namespace) -> int:
        backend.token_revoke(args.principal, args.token_id)
        self.say(f"revoked token {args.token_id} of {args.principal}")
        return exit_codes.OK

    @staticmethod
    def _check_expiry(text: Optional[str]) -> None:
        """Reject an unreadable duration or date here, with the library's message, in both modes."""
        if text is not None:
            parse_duration_or_time(text, _now())

    # ---- grants -----------------------------------------------------------

    def _op_grant_list(self, backend: _Backend, args: argparse.Namespace) -> int:
        items = backend.grants(self.opt(args, "principal", str))
        self._output(args, items, _grant_table(items))
        return exit_codes.OK

    def _op_grant_add(self, backend: _Backend, args: argparse.Namespace) -> int:
        key = self.opt(args, "key", str)
        tag = self.opt(args, "tag", str)
        if key is not None:
            validate_pattern(key)
        if tag is not None:
            validate_tag(tag)
        actions = _split_actions(args.actions)
        self._check_expiry(args.expires)
        if key == "*":
            kind: Any = None
            with contextlib.suppress(
                AdminError, ServerError
            ):  # the warning is best effort; the add reports real errors
                kind = backend.principal(args.principal).get("kind")
            if kind == "agent":
                self.say(
                    f"warning: granting '*' (every secret) to the agent {args.principal}; "
                    "prefer a narrower pattern such as 'service.*'",
                    err=True,
                )
        grant = backend.grant_add(args.principal, key, tag, actions, args.expires, args.description or "")
        self.say(str(grant["id"]))
        return exit_codes.OK

    def _op_grant_remove(self, backend: _Backend, args: argparse.Namespace) -> int:
        backend.grant_remove(args.grant_id)
        self.say(f"removed grant {args.grant_id}")
        return exit_codes.OK

    # ---- check and log ----------------------------------------------------

    def _op_check(self, backend: _Backend, args: argparse.Namespace) -> int:
        result = backend.check(args.principal, args.action, args.name, list(args.tags or []))
        if result.get("allowed") is True:
            grant = result.get("grant")
            self.say(f"allowed (grant {_clean(grant)})" if grant else "allowed")
            return exit_codes.OK
        self.say(f"denied ({_clean(result.get('reason') or 'no reason given')})")
        return exit_codes.ERROR

    def _op_log(self, backend: _Backend, args: argparse.Namespace) -> int:
        since = self.opt(args, "since", str)
        if since is not None:
            _since(since, _now())  # reject an unreadable value here, with the library's message, in both modes
        records = backend.log(self.opt(args, "principal", str), self.opt(args, "decision", str), since, args.limit)
        if self.flag(args, "json"):
            for record in records:
                self.say(json.dumps(record, separators=(",", ":")))
        else:
            self.say(_log_table(records) if records else "(none)")
        return exit_codes.OK

    # ---- migrate-keys (local only) ---------------------------------------

    def _migrate_keys(self, args: argparse.Namespace) -> int:
        policy_file = self._policy_file(args)
        if policy_file is None:
            raise AdminError(
                f"migrate-keys edits a policy file (local mode): use --policy-file or set {POLICY_FILE_ENV}"
            )
        source = Path(args.source)
        with open(source, "rb") as handle:
            raw = handle.read(_MAX_MIGRATION_FILE + 1)
        if len(raw) > _MAX_MIGRATION_FILE:
            raise AdminError(f"{source} is too large to be a key policy")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise AdminError(f"{source} is not valid UTF-8") from None
        with edit_policy(policy_file, create=True) as editor:
            names = editor.import_v1(text, args.min_length)
        for name in names:
            self.say(name)
        self.say(
            f"migrated {len(names)} key{'' if len(names) == 1 else 's'}; each keeps its old key (stored as sha256). "
            "Issue new tokens later to move to the salted scheme.",
            err=True,
        )
        return exit_codes.OK


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def _limit(text: str) -> int:
    try:
        number = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid integer: {text!r}") from None
    if not 1 <= number <= MAX_LOG_LIMIT:
        raise argparse.ArgumentTypeError(f"must be between 1 and {MAX_LOG_LIMIT}")
    return number


def _min_length(text: str) -> int:
    try:
        number = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid integer: {text!r}") from None
    if number < 1:
        raise argparse.ArgumentTypeError("must be 1 or greater")
    return number


def add_admin_parser(subparsers: Any, global_opts: argparse.ArgumentParser) -> None:
    """Register ``mattstash admin ...`` on the top-level subparsers (``global_opts``: the shared options parent)."""
    admin = subparsers.add_parser(
        "admin",
        help="Manage principals, tokens, grants and the access log",
        description="Manage who may use the server. With --server-url (and an admin token) the commands call the "
        "server's admin API; with --policy-file (or MATTSTASH_POLICY_FILE) they edit the policy file directly, "
        "which is also how the first admin is created.",
        parents=[global_opts],
    )
    admin.add_argument(
        "--policy-file",
        dest="policy_file",
        default=None,
        metavar="PATH",
        help=f"Local mode: the policy file to edit (default: ${POLICY_FILE_ENV}); ignored when a server URL is set",
    )
    # After the sub-sub-command the option is accepted too; its default must not clobber the value parsed before.
    after = argparse.ArgumentParser(add_help=False)
    after.add_argument("--policy-file", dest="policy_file", default=argparse.SUPPRESS, metavar="PATH", help="As above")
    leaf_parents = [global_opts, after]

    areas = admin.add_subparsers(dest="admin_area", required=True, metavar="AREA")

    def leaf(parent: Any, name: str, op: str, help_text: str, **kwargs: Any) -> argparse.ArgumentParser:
        parser: argparse.ArgumentParser = parent.add_parser(name, help=help_text, parents=leaf_parents, **kwargs)
        parser.set_defaults(admin_op=op)
        return parser

    def as_json(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--json", action="store_true", help="Output JSON")

    # principal
    principal = areas.add_parser("principal", help="Manage principals").add_subparsers(
        dest="admin_principal_cmd", required=True, metavar="COMMAND"
    )
    as_json(leaf(principal, "list", "principal.list", "List principals"))
    p_add = leaf(principal, "add", "principal.add", "Create a principal")
    p_add.add_argument("name", help="Principal name (letters, digits, '_', '.', '-')")
    p_add.add_argument("--kind", required=True, choices=KINDS, help="human-device, agent or runner")
    p_add.add_argument("--description", help="Free-text description")
    p_add.add_argument("--admin", action="store_true", help="May manage the policy (human-device only)")
    p_show = leaf(principal, "show", "principal.show", "Show a principal, its tokens and grants")
    p_show.add_argument("name")
    as_json(p_show)
    leaf(principal, "disable", "principal.disable", "Reject all tokens of a principal (grants are kept)").add_argument(
        "name"
    )
    leaf(principal, "enable", "principal.enable", "Undo disable").add_argument("name")
    p_remove = leaf(principal, "remove", "principal.remove", "Remove a principal with its grants and tokens")
    p_remove.add_argument("name")
    p_remove.add_argument("--yes", action="store_true", help="Do not ask for confirmation")

    # token
    token = areas.add_parser("token", help="Issue, list, revoke and rotate tokens").add_subparsers(
        dest="admin_token_cmd", required=True, metavar="COMMAND"
    )
    output_help = "Write the token to this new file (mode 0600; refuses to overwrite) instead of printing it"
    t_issue = leaf(
        token,
        "issue",
        "token.issue",
        "Issue a token (printed once, alone on stdout)",
        description="Issue a token. The plaintext is the only thing printed on stdout (or the only content of "
        "--output-file); it is shown once and never stored.",
    )
    t_issue.add_argument("principal")
    t_issue.add_argument("--expires", metavar="WHEN", help="90d, 24h, 2w or a date such as 2027-01-01")
    t_issue.add_argument("--description", help="Free-text description")
    t_issue.add_argument("--output-file", metavar="PATH", help=output_help)
    t_list = leaf(token, "list", "token.list", "List a principal's tokens (ids and expiry, never secrets)")
    t_list.add_argument("principal")
    as_json(t_list)
    t_revoke = leaf(token, "revoke", "token.revoke", "Revoke a token now")
    t_revoke.add_argument("principal")
    t_revoke.add_argument("token_id")
    t_rotate = leaf(
        token,
        "rotate",
        "token.rotate",
        "Issue a replacement token and retire the old one (printed once, alone on stdout)",
    )
    t_rotate.add_argument("principal")
    t_rotate.add_argument("token_id")
    t_rotate.add_argument(
        "--grace", metavar="DURATION", help="Keep the old token valid this long (default: revoke now)"
    )
    t_rotate.add_argument("--expires", metavar="WHEN", help="Expiry of the new token")
    t_rotate.add_argument("--description", help="Free-text description of the new token")
    t_rotate.add_argument("--output-file", metavar="PATH", help=output_help)

    # grant
    grant = areas.add_parser("grant", help="Manage grants").add_subparsers(
        dest="admin_grant_cmd", required=True, metavar="COMMAND"
    )
    g_list = leaf(grant, "list", "grant.list", "List grants")
    g_list.add_argument("--principal", metavar="NAME", help="Only the grants of this principal")
    as_json(g_list)
    g_add = leaf(grant, "add", "grant.add", "Grant a principal access to a key pattern or a tag")
    g_add.add_argument("principal")
    selector = g_add.add_mutually_exclusive_group(required=True)
    selector.add_argument("--key", metavar="PATTERN", help="Name or prefix pattern: 'db', 'firefly.*' or '*'")
    selector.add_argument("--tag", metavar="TAG", help="A KeePass entry tag (list and read only)")
    g_add.add_argument("--actions", default="list,read", metavar="LIST", help="Comma-separated: list,read,write,delete")
    g_add.add_argument("--expires", metavar="WHEN", help="90d, 24h, 2w or a date")
    g_add.add_argument("--description", help="Free-text description")
    leaf(grant, "remove", "grant.remove", "Remove a grant").add_argument("grant_id")

    # check
    check = leaf(areas, "check", "check", "Would this be allowed? Exit 0 if allowed, 1 if denied")
    check.add_argument("principal")
    check.add_argument("action", choices=ACTIONS)
    check.add_argument("name", help="Credential name")
    check.add_argument("--tag", action="append", dest="tags", metavar="T", help="Entry tag (repeatable)")

    # log
    log = leaf(areas, "log", "log", "Show the access log")
    log.add_argument("--principal", metavar="NAME")
    log.add_argument("--decision", choices=["allowed", "denied"])
    log.add_argument("--since", metavar="WHEN", help="24h, 7d or a date: only newer records")
    log.add_argument("--limit", type=_limit, default=100, metavar="N", help="At most N records (default 100)")
    log.add_argument("--json", action="store_true", help="Print the raw JSON lines")
    log.add_argument(
        "--log-file", metavar="PATH", help=f"Local mode: the access log to read (default: ${ACCESS_LOG_FILE_ENV})"
    )

    # migrate-keys
    migrate = leaf(areas, "migrate-keys", "migrate-keys", "Convert a v1 JSON key policy (local mode only)")
    migrate.add_argument("--from", dest="source", required=True, metavar="KEYS_JSON", help="The v1 key policy file")
    migrate.add_argument(
        "--min-length",
        type=_min_length,
        default=DEFAULT_MIN_KEY_LENGTH,
        metavar="N",
        help=f"Shortest key to accept (default {DEFAULT_MIN_KEY_LENGTH}, the server's minimum)",
    )
