"""Authentication: who is calling, from a token in the policy file.

Credential source
-----------------
``MATTSTASH_POLICY_FILE`` -- principals with tokens and grants (``docs/design/principals-and-grants.md``). It is
required. ``MATTSTASH_API_KEY``, ``MATTSTASH_API_KEYS_FILE`` and ``MATTSTASH_REQUIRE_SCOPED_KEYS`` were removed in 0.3;
the server refuses to start while one of them is set (``docs/upgrading-to-0.3.md``).

The loaded file is one immutable :class:`AuthState`, swapped atomically when the file is reloaded, so a request always
sees one consistent policy.

Verification of a presented key never branches on secret material. A key in ``mst_`` format is looked up by its public
id (an unknown id is verified against a dummy hash so it costs the same) and checked with a constant-time HMAC
compare. Anything else is compared by SHA-256 digest against *all* file tokens stored with the unsalted ``sha256:``
scheme (what ``token import`` and ``admin migrate-keys`` write), with no early exit.
"""

import hashlib
import hmac
import logging
import os
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from mattstash.authz import (
    DUMMY_HASH,
    Policy,
    Principal,
    Token,
    admin_expiry_warning,
    is_legacy_hash,
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

UPGRADE_DOC = "docs/upgrading-to-0.3.md"


@dataclass(frozen=True)
class _Digest:
    """The SHA-256 digest of a key stored with the unsalted ``sha256:`` scheme, and the token it belongs to."""

    digest: bytes
    principal: Principal
    token: Token


@dataclass(frozen=True)
class AuthState:
    """Everything needed to authenticate and authorise, built once per (re)load and never mutated."""

    policy: Policy
    tokens: Mapping[str, tuple[Principal, Token]]  # token id -> owner, for salted (mst_) file tokens
    digests: tuple[_Digest, ...]  # file tokens that use the unsalted sha256: scheme
    file_signature: Optional[Signature]

    @property
    def credential_count(self) -> int:
        return len(self.tokens) + len(self.digests)

    @property
    def sha256_tokens(self) -> int:
        """How many tokens use the unsalted scheme (imported or migrated keys): each is logged at startup."""
        return len(self.digests)


@dataclass(frozen=True)
class AuthResult:
    """Outcome of :func:`authenticate`. ``reason`` is ``ok`` or one of the access-log denial reasons."""

    principal: Optional[Principal]
    token_id: Optional[str]
    reason: str
    policy: Optional[Policy] = None


_state: Optional[AuthState] = None
_state_loaded_at: float = _NEVER
_failed_signature: Optional[Signature] = None  # a file version that failed to load; not retried until it changes
_cache_lock = threading.Lock()
_last_expiry_warning: Optional[str] = None  # what was last logged, so a periodic reload does not repeat it


def _signature(path: Optional[str]) -> Optional[Signature]:
    if not path:
        return None
    try:
        info = os.stat(path)
    except OSError:
        return None
    return info.st_mtime_ns, info.st_size, info.st_ino


def check_removed_settings() -> None:
    """Refuse to start while a removed setting is present (the names only; a value is never read into a message)."""
    found = config.removed_settings_in_use()
    if found:
        raise ValueError(
            f"{', '.join(found)} {'is' if len(found) == 1 else 'are'} set, but the server no longer accepts API keys "
            "from the environment or a keys file (removed in 0.3). Put the keys in a policy file and set "
            f"MATTSTASH_POLICY_FILE instead; {UPGRADE_DOC} shows how to move over without downtime."
        )


def _usable(principal: Principal, token: Token, now: datetime) -> bool:
    return not principal.disabled and not token.is_expired(now)


def build_auth_state(file_policy: Policy, signature: Optional[Signature]) -> AuthState:
    """The state the server runs on, from an already parsed (hence validated) policy.

    The one place that decides whether a policy can be served: the loader calls it, and so does the admin API on a
    policy it is about to save, so an edit can never produce a file the server refuses to load. Raises ValueError
    (the message is safe to show) when no principal has a usable token.
    """
    tokens: dict[str, tuple[Principal, Token]] = {}
    digests: list[_Digest] = []
    now = utcnow()
    usable = False
    for principal in file_policy.principals:
        for token in principal.tokens:
            usable = usable or _usable(principal, token, now)
            if is_legacy_hash(token.hash):
                digests.append(_Digest(bytes.fromhex(token.hash.split(":", 1)[1]), principal, token))
            else:
                tokens[token.id] = (principal, token)
    if not usable:
        raise ValueError(
            "The policy file has no usable credential: no enabled principal holds a token that has not expired. "
            "Issue one with `mattstash admin --policy-file <policy file> token issue <principal>`"
        )
    return AuthState(file_policy, tokens, tuple(digests), signature)


def load_auth_state() -> AuthState:
    """Build the state from the policy file. Raises ValueError/FileNotFoundError if unusable."""
    if not config.POLICY_FILE:
        raise ValueError(
            "MATTSTASH_POLICY_FILE is not set. The server needs a policy file with principals, tokens and grants; "
            f"see {UPGRADE_DOC} (bootstrap one with `mattstash admin --policy-file <path> principal add ...`)"
        )
    signature = _signature(config.POLICY_FILE)  # taken before reading: a change while loading is seen next time
    try:
        file_policy = load_policy(config.POLICY_FILE)
    except FileNotFoundError:
        raise FileNotFoundError(f"Policy file not found: {config.POLICY_FILE}") from None
    return build_auth_state(file_policy, signature)


def warn_expiring_admins(state: AuthState, *, always: bool = False) -> None:
    """Log the early warning about the last admin token expiring (decision: 14 days ahead), if there is one.

    Called after every successful policy load. A warning that is unchanged since it was last logged is not repeated
    on the periodic reload (``always`` logs it regardless: startup).
    """
    global _last_expiry_warning
    text = admin_expiry_warning(state.policy, utcnow())
    if text is not None and (always or text != _last_expiry_warning):
        logger.warning("Admin tokens: %s", text)
    _last_expiry_warning = text


def warn_sha256_tokens(state: AuthState) -> None:
    """One warning per token that uses the unsalted scheme: name the token so it can be rotated."""
    for entry in state.digests:
        logger.warning(
            "Token %s of principal %s uses the unsalted 'sha256:' scheme (an imported or migrated key). "
            "Rotate it to an mst_ token: mattstash admin token rotate %s %s",
            entry.token.id,
            entry.principal.name,
            entry.principal.name,
            entry.token.id,
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
                first = _state is None
                _state = load_auth_state()
                _state_loaded_at = now
                _failed_signature = None
                warn_expiring_admins(_state, always=first)
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

    The previous state is kept as a fallback: if the new file is broken the old keys keep working (and the
    error is logged) instead of every request failing. Use :func:`reload_key_policy_now` when the caller needs to
    *know* whether the new policy took effect (for example when revoking a key).
    """
    global _state_loaded_at
    with _cache_lock:
        _state_loaded_at = _NEVER


def reload_key_policy_now() -> AuthState:
    """Re-read the policy file immediately and make the result the active state.

    Raises (and leaves the previous state untouched) if the file cannot be loaded, so the caller can report
    that a revocation did NOT take effect.
    """
    global _state, _state_loaded_at, _failed_signature
    with _cache_lock:
        state = load_auth_state()
        _state, _state_loaded_at, _failed_signature = state, time.monotonic(), None
        warn_expiring_admins(state)
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
    return _check_token(state, match.principal, match.token)


def verify_api_key(api_key: str) -> bool:
    """Return True if ``api_key`` is valid (constant-time; safe for any input)."""
    return authenticate(api_key).principal is not None
