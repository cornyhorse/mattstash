"""Authentication: who is calling, from a token or a legacy key.

Credential sources (any combination)
------------------------------------
* ``MATTSTASH_POLICY_FILE`` -- principals with ``mst_<id>_<secret>`` tokens and grants (the normal way; see
  ``docs/design/principals-and-grants.md``). Only salted hashes are stored.
* ``MATTSTASH_API_KEY`` -- one *legacy* key: principal ``legacy-env``, admin, grant ``*`` on every action.
* ``MATTSTASH_API_KEYS_FILE`` -- legacy keys: a plain list (full access) or a v1 JSON policy (``ops``/``prefixes``,
  converted to principals and synthetic grants by the library).

Everything is merged into one immutable :class:`AuthState`, which is swapped atomically when the sources are reloaded,
so a request always sees one consistent policy. A name clash between any two sources is a load error: grants are
looked up by principal name, so a clash would let one principal inherit another's access.

Verification of a presented key never branches on secret material. A key in ``mst_`` format is looked up by its public
id (an unknown id is verified against a dummy hash so it costs the same) and checked with a constant-time HMAC
compare. Anything else is compared by SHA-256 digest against *all* legacy digests, with no early exit: the env/keys-file
keys and any file token stored with the unsalted ``sha256:`` scheme (what ``admin migrate-keys`` writes).
"""

import hashlib
import hmac
import logging
import os
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from mattstash.authz import (
    DUMMY_HASH,
    LegacyKey,
    Policy,
    PolicyError,
    Principal,
    Token,
    can_admin,
    check_duplicate_keys,
    is_legacy_hash,
    legacy_from_env_key,
    legacy_from_keys_file_text,
    load_policy,
    parse_token,
    verify_token_hash,
)
from mattstash.authz.models import utcnow

from ..config import config

logger = logging.getLogger("mattstash.api")

# Cache the state with a TTL so rotated keys are picked up without restart
_CACHE_TTL_SECONDS: float = 300.0
_RETRY_SECONDS: float = 5.0  # after a failed reload, try again after this long (not on every request)
_NEVER = float("-inf")  # time.monotonic() counts from boot, so 0.0 would look "recently loaded" on a young host

Signature = tuple[int, int, int]


@dataclass(frozen=True)
class _Digest:
    """A SHA-256 digest that identifies a key, its principal and (for a migrated file token) the token."""

    digest: bytes
    principal: Principal
    token: Optional[Token] = None


@dataclass(frozen=True)
class AuthState:
    """Everything needed to authenticate and authorise, built once per (re)load and never mutated."""

    policy: Policy  # file principals + legacy principals, file grants + synthetic legacy grants
    tokens: Mapping[str, tuple[Principal, Token]]  # token id -> owner, for salted (mst_) file tokens
    digests: tuple[_Digest, ...]  # legacy keys and sha256: file tokens
    legacy_sources: tuple[str, ...]
    legacy_admin: bool  # a legacy key can administer, so the last file admin may be removed
    unscoped: frozenset[str]  # names of the legacy keys that always had full access (env key, plain-list keys)
    sha256_tokens: int  # file tokens that use the deprecated unsalted scheme
    file_signature: Optional[Signature]

    @property
    def credential_count(self) -> int:
        return len(self.tokens) + len(self.digests)


@dataclass(frozen=True)
class AuthResult:
    """Outcome of :func:`authenticate`. ``reason`` is ``ok`` or one of the access-log denial reasons."""

    principal: Optional[Principal]
    token_id: Optional[str]
    reason: str
    policy: Optional[Policy] = None
    unscoped: bool = False  # a legacy key with full access (not a v1 scoped key); False for every token


_state: Optional[AuthState] = None
_state_loaded_at: float = _NEVER
_failed_signature: Optional[Signature] = None  # a file version that failed to load; not retried until it changes
_cache_lock = threading.Lock()


def _signature(path: Optional[str]) -> Optional[Signature]:
    if not path:
        return None
    try:
        info = os.stat(path)
    except OSError:
        return None
    return info.st_mtime_ns, info.st_size, info.st_ino


def load_auth_state() -> AuthState:
    """Build the state from the configured sources. Raises ValueError/FileNotFoundError if unusable."""
    file_policy = Policy()
    signature = _signature(config.POLICY_FILE)  # taken before reading: a change while loading is seen next time
    if config.POLICY_FILE:
        try:
            file_policy = load_policy(config.POLICY_FILE)
        except FileNotFoundError:
            raise FileNotFoundError(f"Policy file not found: {config.POLICY_FILE}") from None

    legacy_keys: list[LegacyKey] = []
    legacy_grants = []
    sources: list[str] = []
    unscoped = False
    unscoped_names: set[str] = set()

    if config.API_KEY:
        key, grants = legacy_from_env_key(config.API_KEY, config.MIN_KEY_LENGTH)
        legacy_keys.append(key)
        legacy_grants.extend(grants)
        sources.append("MATTSTASH_API_KEY")
        unscoped = True
        unscoped_names.add(key.principal.name)

    if config.API_KEYS_FILE:
        path = Path(config.API_KEYS_FILE)
        if not path.is_file():
            raise FileNotFoundError(f"API keys file not found: {config.API_KEYS_FILE}")
        text = path.read_text(encoding="utf-8-sig")  # tolerate a BOM written by some editors
        keys, grants_from_file, has_unscoped = legacy_from_keys_file_text(text, config.MIN_KEY_LENGTH)
        legacy_keys.extend(keys)
        legacy_grants.extend(grants_from_file)
        sources.append("MATTSTASH_API_KEYS_FILE")
        unscoped = unscoped or has_unscoped
        if has_unscoped:  # a plain list: every key in it is full-access (a v1 JSON policy has none)
            unscoped_names.update(k.principal.name for k in keys)

    # Grants are found by principal name, so ANY clash (case-insensitive) between sources would let one principal
    # inherit another's access, e.g. a scoped v1 key with id "legacy-env" taking the env key's "*" grant.
    seen: set[str] = set()
    for principal in (*file_policy.principals, *(key.principal for key in legacy_keys)):
        folded = principal.name.casefold()
        if folded in seen:
            raise PolicyError(f"the principal name {principal.name!r} is used more than once across the key sources")
        seen.add(folded)

    tokens: dict[str, tuple[Principal, Token]] = {}
    sha256_digests: list[_Digest] = []
    for principal in file_policy.principals:
        for token in principal.tokens:
            if is_legacy_hash(token.hash):
                sha256_digests.append(_Digest(bytes.fromhex(token.hash.split(":", 1)[1]), principal, token))
            else:
                tokens[token.id] = (principal, token)
    digests = [_Digest(key.digest, key.principal) for key in legacy_keys] + sha256_digests

    # the same key in two places (env key and a migrated token, say) is ambiguous
    check_duplicate_keys([LegacyKey(entry.digest, entry.principal) for entry in digests])

    if not tokens and not digests:
        raise ValueError(
            "At least one API key must be provided via MATTSTASH_POLICY_FILE (a token), MATTSTASH_API_KEY "
            "or MATTSTASH_API_KEYS_FILE"
        )
    if config.REQUIRE_SCOPED_KEYS and unscoped:
        raise ValueError(
            "Legacy (unscoped, full-access) API keys are configured but MATTSTASH_REQUIRE_SCOPED_KEYS is set; "
            "use a policy file (MATTSTASH_POLICY_FILE) or a JSON key policy"
        )

    merged = Policy(
        version=file_policy.version,
        revision=file_policy.revision,
        principals=(*file_policy.principals, *(key.principal for key in legacy_keys)),
        grants=(*file_policy.grants, *legacy_grants),
    )
    return AuthState(
        policy=merged,
        tokens=tokens,
        digests=tuple(digests),
        legacy_sources=tuple(sources),
        legacy_admin=any(can_admin(key.principal) for key in legacy_keys),
        unscoped=frozenset(unscoped_names),
        sha256_tokens=len(sha256_digests),
        file_signature=signature,
    )


def get_auth_state(*, force: bool = False) -> AuthState:
    """Return the cached state, reloading after the TTL or when the policy file changed on disk.

    The file is ``stat``-ed on every call (mtime, size and inode), so an edit by the CLI or an admin request on another
    replica takes effect at once. If a *reload* fails (file briefly unreadable, bad edit) the previous state keeps
    serving and the failure is logged; the broken file version is not retried until it changes again (or the short
    backoff has passed). The first load must succeed.
    """
    global _state, _state_loaded_at, _failed_signature

    with _cache_lock:
        now = time.monotonic()
        current = _signature(config.POLICY_FILE)
        changed = _state is not None and current != _state.file_signature and current != _failed_signature
        stale = _state is None or force or changed or (now - _state_loaded_at) >= _CACHE_TTL_SECONDS
        if stale:
            try:
                _state = load_auth_state()
                _state_loaded_at = now
                _failed_signature = None
            except Exception as exc:
                if _state is None:
                    raise
                logger.error("API key policy reload failed (%s); keeping the previous policy", type(exc).__name__)
                _state_loaded_at = now - _CACHE_TTL_SECONDS + _RETRY_SECONDS  # retry soon, not on every request
                _failed_signature = current
        assert _state is not None
        return _state


def invalidate_api_key_cache() -> None:
    """Mark the cached state stale so it is re-read on the next request.

    The previous state is kept as a fallback: if the new sources are broken the old keys keep working (and the
    error is logged) instead of every request failing. Use :func:`reload_key_policy_now` when the caller needs to
    *know* whether the new policy took effect (for example when revoking a key).
    """
    global _state_loaded_at
    with _cache_lock:
        _state_loaded_at = _NEVER


def reload_key_policy_now() -> AuthState:
    """Re-read the sources immediately and make the result the active state.

    Raises (and leaves the previous state untouched) if the sources cannot be loaded, so the caller can report
    that a revocation did NOT take effect.
    """
    global _state, _state_loaded_at, _failed_signature
    with _cache_lock:
        state = load_auth_state()
        _state, _state_loaded_at, _failed_signature = state, time.monotonic(), None
        return state


def _match_digest(state: AuthState, api_key: str) -> Optional[_Digest]:
    presented = hashlib.sha256(api_key.encode("utf-8", "surrogatepass")).digest()
    match: Optional[_Digest] = None
    for entry in state.digests:  # deliberately no early exit
        if hmac.compare_digest(presented, entry.digest):
            match = entry
    return match


def _check_token(state: AuthState, principal: Principal, token: Token) -> AuthResult:
    if token.is_expired(utcnow()):
        return AuthResult(None, token.id, "expired-token")
    if principal.disabled:
        return AuthResult(None, token.id, "disabled")
    return AuthResult(principal, token.id, "ok", state.policy)


def authenticate(api_key: Optional[str]) -> AuthResult:
    """Identify the caller from the ``X-API-Key`` value (raises only if the key store itself is unusable)."""
    if not api_key:
        return AuthResult(None, None, "no-token")
    state = get_auth_state()
    parsed = parse_token(api_key)  # the id is logged only when the token parsed
    token_id = parsed[0] if parsed else None

    if parsed is not None and parsed[0] in state.tokens:
        principal, token = state.tokens[parsed[0]]
        if not verify_token_hash(token.hash, api_key):
            return AuthResult(None, token_id, "bad-token")
        return _check_token(state, principal, token)

    if parsed is not None:
        verify_token_hash(DUMMY_HASH, api_key)  # an unknown id costs the same HMAC as a wrong secret

    match = _match_digest(state, api_key)
    if match is None:
        return AuthResult(None, token_id, "unknown-token" if parsed else "bad-token")
    if match.token is None:  # a legacy key: no id, no expiry, never disabled
        return AuthResult(match.principal, None, "ok", state.policy, match.principal.name in state.unscoped)
    return _check_token(state, match.principal, match.token)


def verify_api_key(api_key: str) -> bool:
    """Return True if ``api_key`` is valid (constant-time; safe for any input)."""
    return authenticate(api_key).principal is not None
