"""Token format, generation and hashing (design section 3).

``mst_<token_id>_<secret>``: ``token_id`` is a public 12-character lowercase base32 handle (like Vault's accessor),
``secret`` is 256 random bits. Only a salted HMAC of the whole token is stored. A slow KDF would defend against
guessing low-entropy inputs; these tokens have 256 random bits, and a slow hash would cost CPU on every request.
"""

import hashlib
import hmac
import re
import secrets
from typing import Optional

from .errors import PolicyError

PREFIX = "mst_"
_ID_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"
_ID_RE = re.compile(r"[a-z2-7]{12}", re.ASCII)
_SECRET_RE = re.compile(r"[A-Za-z0-9_-]{1,200}", re.ASCII)
_SALT_HEX_RE = re.compile(r"[0-9a-f]{32}", re.ASCII)
_DIGEST_HEX_RE = re.compile(r"[0-9a-f]{64}", re.ASCII)

HMAC_SCHEME = "hmac-sha256"
LEGACY_SCHEME = "sha256"

#: A well-formed hash that no token matches. Verifying an unknown token id against it costs the same HMAC as a
#: known id, so unknown and wrong-secret answers take the same time.
DUMMY_HASH = f"{HMAC_SCHEME}:{'00' * 16}:{'00' * 32}"


def is_valid_token_id(token_id: object) -> bool:
    return isinstance(token_id, str) and _ID_RE.fullmatch(token_id) is not None


def generate_token() -> tuple[str, str]:
    """Return ``(token_id, plaintext)``. The plaintext must be shown once and never stored."""
    token_id = "".join(secrets.choice(_ID_ALPHABET) for _ in range(12))
    return token_id, f"{PREFIX}{token_id}_{secrets.token_urlsafe(32)}"


def parse_token(s: object) -> Optional[tuple[str, str]]:
    """Split ``mst_<id>_<secret>`` into ``(token_id, secret)``, or None. Never raises, whatever the input.

    The secret may itself contain ``_``, so only the first two underscores separate fields.
    """
    if not isinstance(s, str) or not s.startswith(PREFIX):
        return None
    token_id, separator, secret = s[len(PREFIX) :].partition("_")
    if not separator or not _ID_RE.fullmatch(token_id) or not _SECRET_RE.fullmatch(secret):
        return None
    return token_id, secret


def _digest(salt: bytes, plaintext: str) -> str:
    # surrogatepass: a header value may hold lone surrogates; hashing must never raise on odd input
    return hmac.new(salt, plaintext.encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()


def hash_token(plaintext: str) -> str:
    """``hmac-sha256:<salt-hex>:<digest-hex>``, with a fresh random salt per call."""
    salt = secrets.token_bytes(16)
    return f"{HMAC_SCHEME}:{salt.hex()}:{_digest(salt, plaintext)}"


def _split_hash(stored: object) -> Optional[tuple[str, str, str]]:
    """``(scheme, salt_hex, digest_hex)`` for a well-formed stored hash (salt is empty for the legacy scheme)."""
    if not isinstance(stored, str):
        return None
    parts = stored.split(":")
    if len(parts) == 3 and parts[0] == HMAC_SCHEME:
        if _SALT_HEX_RE.fullmatch(parts[1]) and _DIGEST_HEX_RE.fullmatch(parts[2]):
            return parts[0], parts[1], parts[2]
    elif len(parts) == 2 and parts[0] == LEGACY_SCHEME and _DIGEST_HEX_RE.fullmatch(parts[1]):
        return parts[0], "", parts[1]
    return None


def verify_token_hash(stored: str, plaintext: str) -> bool:
    """Constant-time check of ``plaintext`` against a stored hash. False, never an exception, for a malformed hash
    or a ``plaintext`` that is not a string."""
    parts = _split_hash(stored)
    if parts is None or not isinstance(plaintext, str):
        return False
    scheme, salt_hex, digest = parts
    if scheme == HMAC_SCHEME:
        presented = _digest(bytes.fromhex(salt_hex), plaintext)
    else:
        presented = hashlib.sha256(plaintext.encode("utf-8", "surrogatepass")).hexdigest()
    return hmac.compare_digest(presented, digest)


def validate_token_hash(stored: object) -> None:
    """Raise :class:`PolicyError` if ``stored`` is not a supported hash. The message never repeats the value."""
    if _split_hash(stored) is None:
        raise PolicyError(
            f"token hash is malformed; expected '{HMAC_SCHEME}:<32 hex>:<64 hex>' or '{LEGACY_SCHEME}:<64 hex>'"
        )


def is_legacy_hash(stored: object) -> bool:
    """True for the unsalted ``sha256:`` scheme that only migrated v1 keys use."""
    return isinstance(stored, str) and stored.startswith(f"{LEGACY_SCHEME}:")
