"""Reading a v1 JSON key policy, for ``mattstash admin migrate-keys`` (the only thing left of the v1 key sources).

The server no longer accepts ``MATTSTASH_API_KEY``, ``MATTSTASH_API_KEYS_FILE`` or a v1 key policy as credentials
(``docs/upgrading-to-0.3.md``). What remains is the parser of the v1 JSON format and :func:`migrate_v1`, which turns
its entries into principals and grants. Validation rules and error messages are kept as they were; every error is a
:class:`PolicyError`.
"""

import hashlib
import json
import re
import secrets
from collections.abc import Iterable
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any, Optional

from .errors import PolicyError
from .models import KINDS, Grant, Policy, Principal, Token
from .store import validate_name, validate_policy
from .tokens import generate_token

VALID_OPS = frozenset({"read", "write", "delete", "admin"})
_ID_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}", re.ASCII)
_PREFIX_RE = re.compile(r"[A-Za-z0-9_.-]{1,255}", re.ASCII)
_SHA256_HEX_RE = re.compile(r"[0-9a-fA-F]{64}", re.ASCII)


@dataclass(frozen=True)
class _V1Entry:
    """One parsed entry of a v1 JSON policy."""

    key_id: str
    digest: bytes
    ops: frozenset[str]
    prefixes: Optional[tuple[str, ...]]  # None: every credential name


def _digest(key: str, where: str) -> bytes:
    try:
        return hashlib.sha256(key.encode("utf-8")).digest()
    except UnicodeEncodeError:  # a lone surrogate, e.g. from a malformed JSON escape or an undecodable env byte
        raise PolicyError(f"API key {where} contains a character that cannot be encoded as UTF-8") from None


def _check_length(key: str, where: str, min_length: int) -> None:
    if len(key) < min_length:
        raise PolicyError(
            f"API key {where} is shorter than {min_length} characters; generate one with `openssl rand -base64 32`"
        )


def _actions_for_ops(ops: frozenset[str]) -> frozenset[str]:
    """v1 ``read`` covered listing too; ``write`` and ``delete`` are kept as they were; ``admin`` is a flag."""
    actions = set(ops - {"admin", "read"})
    if "read" in ops:
        actions |= {"list", "read"}
    return frozenset(actions)


def _entry_grants(entry: _V1Entry) -> list[tuple[str, frozenset[str]]]:
    """``[(pattern, actions)]`` for a v1 entry: each prefix ``p`` becomes ``p*`` (the old ``startswith`` meaning)."""
    actions = _actions_for_ops(entry.ops)
    if not actions:
        return []
    patterns = ["*"] if entry.prefixes is None else [f"{prefix}*" for prefix in entry.prefixes]
    return [(pattern, actions) for pattern in patterns]


def _parse_v1_entry(entry: Any, index: int, min_length: int) -> _V1Entry:
    if not isinstance(entry, dict):
        raise PolicyError(f"API key policy entry #{index} must be an object")
    key_id = entry.get("id")
    if not isinstance(key_id, str) or not _ID_RE.fullmatch(key_id):
        raise PolicyError(f"API key policy entry #{index}: 'id' must match [A-Za-z0-9_.-]{{1,64}}")
    where = f"'{key_id}'"

    plaintext, hashed = entry.get("key"), entry.get("key_sha256")
    if (plaintext is None) == (hashed is None):
        raise PolicyError(f"API key {where}: provide exactly one of 'key' or 'key_sha256'")
    if plaintext is not None:
        if not isinstance(plaintext, str):
            raise PolicyError(f"API key {where}: 'key' must be a string")
        _check_length(plaintext, where, min_length)
        digest = _digest(plaintext, where)
    else:
        if not isinstance(hashed, str) or not _SHA256_HEX_RE.fullmatch(hashed):
            raise PolicyError(f"API key {where}: 'key_sha256' must be 64 hex characters")
        digest = bytes.fromhex(hashed)

    ops = entry.get("ops", ["read"])
    if not isinstance(ops, list) or not ops or not all(isinstance(o, str) for o in ops):
        raise PolicyError(f"API key {where}: 'ops' must be a non-empty list of strings")
    unknown = sorted(set(ops) - VALID_OPS)
    if unknown:
        raise PolicyError(f"API key {where}: unknown ops {unknown}; valid: {sorted(VALID_OPS)}")

    prefixes = entry.get("prefixes")
    scoped: Optional[tuple[str, ...]]
    if prefixes is None or prefixes == ["*"]:
        scoped = None
    else:
        if not isinstance(prefixes, list) or not prefixes:
            raise PolicyError(f"API key {where}: 'prefixes' must be a non-empty list (or omit it / use [\"*\"])")
        for prefix in prefixes:
            if not isinstance(prefix, str) or not _PREFIX_RE.fullmatch(prefix):
                raise PolicyError(f"API key {where}: invalid prefix; allowed characters are [A-Za-z0-9_.-]")
        scoped = tuple(prefixes)

    return _V1Entry(key_id, digest, frozenset(ops), scoped)


def _reject_duplicate_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    for field, value in pairs:
        if field in seen:
            raise PolicyError(f"API key policy contains the duplicate field '{field}'")
        seen[field] = value
    return seen


def _parse_v1_json(text: str, min_length: int) -> list[_V1Entry]:
    try:
        document = json.loads(text, object_pairs_hook=_reject_duplicate_fields)
    except json.JSONDecodeError as exc:
        raise PolicyError(f"API keys file is not valid JSON (line {exc.lineno}, column {exc.colno})") from None
    except RecursionError:
        raise PolicyError("API keys file is nested too deeply") from None
    except PolicyError:  # a duplicate field, from the hook (PolicyError is a ValueError)
        raise
    except ValueError:  # an integer with more digits than Python converts
        raise PolicyError("API keys file contains a number that is too large") from None
    entries = document.get("keys") if isinstance(document, dict) else document
    if not isinstance(entries, list) or not entries:
        raise PolicyError("API key policy must contain a non-empty 'keys' list")
    parsed = [_parse_v1_entry(entry, i, min_length) for i, entry in enumerate(entries, start=1)]
    ids = [e.key_id for e in parsed]
    if len(set(ids)) != len(ids):
        raise PolicyError("API key policy contains duplicate ids")
    if len({e.digest for e in parsed}) != len(parsed):
        raise PolicyError("The same API key is configured more than once")
    return parsed


def _first_content_character(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            return stripped[0]
    return ""


def _strip_comments(text: str) -> str:
    """'#' comment lines are allowed in a JSON policy file too (they are not JSON, so drop them first)."""
    return "\n".join(line for line in text.splitlines() if not line.strip().startswith("#"))


def v1_admin_ids(text: str, min_length: int, only: Iterable[str]) -> list[str]:
    """The ids among ``only`` whose v1 entry had the ``admin`` op, in file order (for the migration's notes)."""
    wanted = set(only)
    entries = _parse_v1_json(_strip_comments(text.removeprefix("\ufeff")), min_length)
    return [entry.key_id for entry in entries if entry.key_id in wanted and "admin" in entry.ops]


def migrate_v1(text: str, into: Policy, min_length: int, now: datetime, kind: str = "agent") -> Policy:
    """Add the keys of a v1 JSON policy to ``into`` as v2 principals of ``kind``, keeping each key working.

    The principals are never admins: v1 ``admin`` meant only "reload", and a v2 admin manages the whole policy. A key
    without prefixes (every name) needs the ``*`` grant, which only ``human-device`` principals may hold, so it is an
    error for any other ``kind``. Each stored hash is the v1 digest (``sha256:<hex>``) so existing callers keep their
    key; re-issue tokens later to get the salted scheme. A plain list has no names to migrate, so it is refused with
    a hint.
    """
    if kind not in KINDS:
        raise PolicyError(f"kind must be one of {', '.join(KINDS)}")
    text = text.removeprefix("\ufeff")
    if _first_content_character(text) not in ("{", "["):
        raise PolicyError(
            "only a JSON key policy can be migrated: a plain list of keys has no names. "
            "Create principals with `mattstash admin principal add`, then give each client's existing key to "
            "`mattstash admin token import`"
        )
    entries = _parse_v1_json(_strip_comments(text), min_length)
    needs_star: list[str] = []
    taken = {p.name.casefold() for p in into.principals}
    used_token_ids = {t.id for p in into.principals for t in p.tokens}
    used_grant_ids = {g.id for g in into.grants}
    existing = {t.hash for p in into.principals for t in p.tokens}
    principals = list(into.principals)
    grants = list(into.grants)
    for entry in entries:
        validate_name(entry.key_id)
        if entry.key_id.casefold() in taken:
            raise PolicyError(f"cannot migrate key {entry.key_id!r}: a principal with that name already exists")
        taken.add(entry.key_id.casefold())
        entry_grants = _entry_grants(entry)
        if kind != "human-device" and any(pattern == "*" for pattern, _ in entry_grants):
            needs_star.append(entry.key_id)
        stored = f"sha256:{entry.digest.hex()}"
        if stored in existing:
            raise PolicyError(f"cannot migrate key {entry.key_id!r}: The same API key is configured more than once")
        existing.add(stored)
        while True:
            token_id, _ = generate_token()
            if token_id not in used_token_ids:
                break
        used_token_ids.add(token_id)
        token = Token(token_id, stored, now, None, "migrated from a v1 key policy")
        principals.append(Principal(entry.key_id, kind, "migrated from a v1 key policy", False, False, now, (token,)))
        for pattern, actions in entry_grants:
            while True:
                grant_id = f"g_{secrets.token_hex(4)}"
                if grant_id not in used_grant_ids:
                    break
            used_grant_ids.add(grant_id)
            grants.append(
                Grant(grant_id, entry.key_id, pattern, None, actions, None, "migrated from a v1 key policy", now)
            )
    if needs_star:  # every offender is listed (and nothing is migrated), after the name checks above
        raise PolicyError(
            f"cannot migrate as {kind}: {len(needs_star)} key{'' if len(needs_star) == 1 else 's'} without "
            f"prefixes can read every secret and would need the '*' grant, which only human-device principals "
            f"may hold: {', '.join(needs_star)}. Either narrow those keys' prefixes in the source file (or "
            "leave them out of it) and run again, or run with --kind human-device, which makes EVERY migrated "
            "key a human-device principal"
        )
    migrated = replace(into, principals=tuple(principals), grants=tuple(grants))
    validate_policy(migrated)
    return migrated
