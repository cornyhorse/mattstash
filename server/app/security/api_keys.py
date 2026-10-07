"""API key management: scoped key policy, hashed storage, constant-time verification.

Key sources
-----------
* ``MATTSTASH_API_KEY`` -- a single *legacy* key (full access).
* ``MATTSTASH_API_KEYS_FILE`` -- either
    - a plain list, one key per line (``#`` comments allowed): *legacy* keys with full access, or
    - a JSON policy document with scoped keys::

        {"keys": [
          {"id": "billing", "key_sha256": "<hex sha256 of the key>", "ops": ["read"], "prefixes": ["billing-"]},
          {"id": "deploy",  "key": "<plaintext key>",                "ops": ["read", "write"]}
        ]}

  ``ops`` is any of ``read``, ``write``, ``delete``, ``admin`` (default ``["read"]``); ``prefixes`` limits the
  credential names a key may touch (omit or ``["*"]`` for all names). Generate keys with ``python -m app.keytool``.

Keys are only ever held in memory as SHA-256 digests and compared in constant time over *all* records
(no early exit), so neither timing nor non-ASCII header values leak or break anything.
"""

import hashlib
import hmac
import json
import logging
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from ..config import config

logger = logging.getLogger("mattstash.api")

VALID_OPS = frozenset({"read", "write", "delete", "admin"})
_ID_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}", re.ASCII)
_PREFIX_RE = re.compile(r"[A-Za-z0-9_.-]{1,255}", re.ASCII)
_SHA256_HEX_RE = re.compile(r"[0-9a-fA-F]{64}", re.ASCII)

# Cache the policy with a TTL so rotated keys are picked up without restart
_CACHE_TTL_SECONDS: float = 300.0
_policy: "Optional[KeyPolicy]" = None
_policy_loaded_at: float = 0.0
_cache_lock = threading.Lock()


@dataclass(frozen=True)
class Principal:
    """An authenticated API client."""

    id: str
    ops: frozenset[str]
    prefixes: Optional[tuple[str, ...]] = None  # None => any credential name
    legacy: bool = False

    def can(self, op: str) -> bool:
        return op in self.ops

    def allows_name(self, name: str) -> bool:
        return self.prefixes is None or any(name.startswith(p) for p in self.prefixes)


@dataclass(frozen=True)
class _KeyRecord:
    digest: bytes
    principal: Principal


class KeyPolicy:
    """The set of valid keys and what each may do."""

    def __init__(self, records: list[_KeyRecord]) -> None:
        self._records = list(records)

    @property
    def legacy_count(self) -> int:
        return sum(1 for r in self._records if r.principal.legacy)

    def __len__(self) -> int:
        return len(self._records)

    def authenticate(self, api_key: str) -> Optional[Principal]:
        """Return the principal for ``api_key`` or None. Never raises on odd input."""
        presented = hashlib.sha256(api_key.encode("utf-8", "surrogatepass")).digest()
        match: Optional[Principal] = None
        for record in self._records:  # deliberately no early exit
            if hmac.compare_digest(presented, record.digest):
                match = record.principal
        return match


def _digest(key: str) -> bytes:
    return hashlib.sha256(key.encode("utf-8")).digest()


def _legacy_record(key: str) -> _KeyRecord:
    digest = _digest(key)
    return _KeyRecord(
        digest,
        Principal(id=f"legacy-{digest.hex()[:8]}", ops=VALID_OPS, prefixes=None, legacy=True),
    )


def _check_length(key: str, where: str) -> None:
    if len(key) < config.MIN_KEY_LENGTH:
        raise ValueError(
            f"API key {where} is shorter than {config.MIN_KEY_LENGTH} characters; "
            "generate one with `python -m app.keytool` or `openssl rand -base64 32`"
        )


def _parse_policy_entry(entry: Any, index: int) -> _KeyRecord:
    if not isinstance(entry, dict):
        raise ValueError(f"API key policy entry #{index} must be an object")
    key_id = entry.get("id")
    if not isinstance(key_id, str) or not _ID_RE.fullmatch(key_id):
        raise ValueError(f"API key policy entry #{index}: 'id' must match [A-Za-z0-9_.-]{{1,64}}")
    where = f"'{key_id}'"

    plaintext, hashed = entry.get("key"), entry.get("key_sha256")
    if (plaintext is None) == (hashed is None):
        raise ValueError(f"API key {where}: provide exactly one of 'key' or 'key_sha256'")
    if plaintext is not None:
        if not isinstance(plaintext, str):
            raise ValueError(f"API key {where}: 'key' must be a string")
        _check_length(plaintext, where)
        digest = _digest(plaintext)
    else:
        if not isinstance(hashed, str) or not _SHA256_HEX_RE.fullmatch(hashed):
            raise ValueError(f"API key {where}: 'key_sha256' must be 64 hex characters")
        digest = bytes.fromhex(hashed)

    ops = entry.get("ops", ["read"])
    if not isinstance(ops, list) or not ops or not all(isinstance(o, str) for o in ops):
        raise ValueError(f"API key {where}: 'ops' must be a non-empty list of strings")
    unknown = sorted(set(ops) - VALID_OPS)
    if unknown:
        raise ValueError(f"API key {where}: unknown ops {unknown}; valid: {sorted(VALID_OPS)}")

    prefixes = entry.get("prefixes")
    scoped: Optional[tuple[str, ...]]
    if prefixes is None or prefixes == ["*"]:
        scoped = None
    else:
        if not isinstance(prefixes, list) or not prefixes:
            raise ValueError(f"API key {where}: 'prefixes' must be a non-empty list (or omit it / use [\"*\"])")
        for prefix in prefixes:
            if not isinstance(prefix, str) or not _PREFIX_RE.fullmatch(prefix):
                raise ValueError(f"API key {where}: invalid prefix; allowed characters are [A-Za-z0-9_.-]")
        scoped = tuple(prefixes)

    return _KeyRecord(digest, Principal(id=key_id, ops=frozenset(ops), prefixes=scoped, legacy=False))


def _parse_policy_json(text: str) -> list[_KeyRecord]:
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"API keys file is not valid JSON (line {exc.lineno}, column {exc.colno})") from None
    entries = document.get("keys") if isinstance(document, dict) else document
    if not isinstance(entries, list) or not entries:
        raise ValueError("API key policy must contain a non-empty 'keys' list")
    records = [_parse_policy_entry(entry, i) for i, entry in enumerate(entries, start=1)]
    ids = [r.principal.id for r in records]
    if len(set(ids)) != len(ids):
        raise ValueError("API key policy contains duplicate ids")
    return records


def _parse_legacy_lines(text: str, source: str) -> list[_KeyRecord]:
    records = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if line and not line.startswith("#"):
            _check_length(line, f"on line {number} of {source}")
            records.append(_legacy_record(line))
    return records


def load_key_policy() -> KeyPolicy:
    """Build the key policy from the configured sources. Raises ValueError/FileNotFoundError if unusable."""
    records: list[_KeyRecord] = []

    if config.API_KEY:
        _check_length(config.API_KEY, "from MATTSTASH_API_KEY")
        records.append(_legacy_record(config.API_KEY))

    if config.API_KEYS_FILE:
        path = Path(config.API_KEYS_FILE)
        if not path.is_file():
            raise FileNotFoundError(f"API keys file not found: {config.API_KEYS_FILE}")
        text = path.read_text()
        if text.lstrip()[:1] in ("{", "["):
            records.extend(_parse_policy_json(text))
        else:
            records.extend(_parse_legacy_lines(text, "the API keys file"))

    if not records:
        raise ValueError("At least one API key must be provided via MATTSTASH_API_KEY or MATTSTASH_API_KEYS_FILE")

    digests = [r.digest for r in records]
    if len(set(digests)) != len(digests):
        raise ValueError("The same API key is configured more than once")

    policy = KeyPolicy(records)
    if config.REQUIRE_SCOPED_KEYS and policy.legacy_count:
        raise ValueError(
            "Legacy (unscoped, full-access) API keys are configured but MATTSTASH_REQUIRE_SCOPED_KEYS is set; "
            "use a JSON key policy file"
        )
    return policy


def get_key_policy(*, force: bool = False) -> KeyPolicy:
    """Return the cached policy, reloading after the TTL.

    If a *reload* fails (file briefly unreadable, bad edit) the previous policy keeps serving and the
    reload is retried on the next request; the failure is logged. The first load must succeed.
    """
    global _policy, _policy_loaded_at

    with _cache_lock:
        now = time.monotonic()
        stale = _policy is None or force or (now - _policy_loaded_at) >= _CACHE_TTL_SECONDS
        if stale:
            try:
                _policy = load_key_policy()
                _policy_loaded_at = now
            except Exception as exc:
                if _policy is None:
                    raise
                logger.error("API key policy reload failed (%s); keeping the previous policy", type(exc).__name__)
        assert _policy is not None
        return _policy


def invalidate_api_key_cache() -> None:
    """Mark the cached policy stale so it is re-read on the next request.

    The previous policy is kept as a fallback: if the new file is broken the old keys keep working (and the
    error is logged) instead of every request failing.
    """
    global _policy_loaded_at
    with _cache_lock:
        _policy_loaded_at = 0.0


def authenticate(api_key: str) -> Optional[Principal]:
    """Return the principal owning ``api_key`` (or None)."""
    return get_key_policy().authenticate(api_key)


def verify_api_key(api_key: str) -> bool:
    """Return True if ``api_key`` is valid (constant-time; safe for any input)."""
    return authenticate(api_key) is not None
