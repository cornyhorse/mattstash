"""The v1 key sources (``MATTSTASH_API_KEY``, a plain keys file, a v1 JSON key policy) expressed as principals.

This is a copy of the parsing in ``server/app/security/api_keys.py`` that returns principals and synthetic grants
instead of the v1 ``Principal``/``KeyPolicy``, so the server can evaluate legacy and v2 principals with one function
(:func:`mattstash.authz.evaluate`). Validation rules and error messages are kept as they were; every error is a
:class:`PolicyError`, which is a ``ValueError`` like before.

Legacy principals live in memory only and are never written to a policy file. Keys are held as SHA-256 digests.
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
from .models import KINDS, LEGACY_KIND, Grant, Policy, Principal, Token
from .store import validate_name, validate_policy
from .tokens import generate_token

VALID_OPS = frozenset({"read", "write", "delete", "admin"})
_ALL_ACTIONS = frozenset({"list", "read", "write", "delete"})
_ID_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}", re.ASCII)
_PREFIX_RE = re.compile(r"[A-Za-z0-9_.-]{1,255}", re.ASCII)
_SHA256_HEX_RE = re.compile(r"[0-9a-fA-F]{64}", re.ASCII)


@dataclass(frozen=True)
class LegacyKey:
    """A legacy credential: the SHA-256 digest of the key and the principal that owns it."""

    digest: bytes
    principal: Principal


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
            f"API key {where} is shorter than {min_length} characters; "
            "generate one with `python -m app.keytool` or `openssl rand -base64 32`"
        )


def _synthetic_grant(principal: str, pattern: str, actions: frozenset[str], suffix: str = "") -> Grant:
    return Grant(
        id=f"legacy:{principal}{suffix}",
        principal=principal,
        key=pattern,
        tag=None,
        actions=actions,
        description="implicit grant of a legacy key",
    )


def _full_access(key: str, name: str, where: str) -> tuple[LegacyKey, tuple[Grant, ...]]:
    """A legacy full-access key: admin, with the implicit grant ``*`` on every action. The name is positional
    (``legacy-env``, ``legacy-1``...), never derived from the key."""
    principal = Principal(name=name, kind=LEGACY_KIND, description="legacy full-access API key", admin=True)
    return LegacyKey(_digest(key, where), principal), (_synthetic_grant(name, "*", _ALL_ACTIONS),)


def legacy_from_env_key(key: str, min_length: int) -> tuple[LegacyKey, tuple[Grant, ...]]:
    """``MATTSTASH_API_KEY``: principal ``legacy-env``, admin, grant ``*`` with every action."""
    _check_length(key, "from MATTSTASH_API_KEY", min_length)
    return _full_access(key, "legacy-env", "from MATTSTASH_API_KEY")


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


def check_duplicate_keys(keys: list[LegacyKey]) -> None:
    """Raise if the same key (digest) appears twice. Call it on the combined list when several sources are used."""
    digests = [k.digest for k in keys]
    if len(set(digests)) != len(digests):
        raise PolicyError("The same API key is configured more than once")


def legacy_from_keys_file_text(text: str, min_length: int) -> tuple[list[LegacyKey], list[Grant], bool]:
    """Parse a keys file: a plain list (one key per line) or a v1 JSON policy.

    Returns the keys, their synthetic grants, and whether any key is a plain full-access key. That flag is what
    ``MATTSTASH_REQUIRE_SCOPED_KEYS`` refuses, exactly as v1 did: a JSON key without prefixes counts as scoped
    (its ``ops`` limit it), a plain-list key does not.
    """
    text = text.removeprefix("﻿")  # tolerate a BOM written by some editors
    keys: list[LegacyKey] = []
    grants: list[Grant] = []
    if _first_content_character(text) in ("{", "["):
        for entry in _parse_v1_json(_strip_comments(text), min_length):
            principal = Principal(
                name=entry.key_id,
                kind=LEGACY_KIND,
                description="legacy scoped API key",
                admin="admin" in entry.ops,
            )
            keys.append(LegacyKey(entry.digest, principal))
            for n, (pattern, actions) in enumerate(_entry_grants(entry), start=1):
                suffix = "" if entry.prefixes is None else f":{n}"
                grants.append(_synthetic_grant(entry.key_id, pattern, actions, suffix))
        check_duplicate_keys(keys)
        return keys, grants, False

    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if re.search(r"\s", line):
            raise PolicyError(f"API key on line {number} of the API keys file contains whitespace; one key per line")
        _check_length(line, f"on line {number} of the API keys file", min_length)
        key, key_grants = _full_access(line, f"legacy-{len(keys) + 1}", f"on line {number} of the API keys file")
        keys.append(key)
        grants.extend(key_grants)
    check_duplicate_keys(keys)
    return keys, grants, bool(keys)


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
            raise PolicyError(
                f"cannot migrate key {entry.key_id!r} as {kind}: it has no prefixes, so it can read every secret, "
                "and the '*' grant is only for human-device principals. Re-run with --kind human-device, or "
                "narrow the key's prefixes first"
            )
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
    migrated = replace(into, principals=tuple(principals), grants=tuple(grants))
    validate_policy(migrated)
    return migrated
