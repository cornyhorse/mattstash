"""Plain data types for principals, tokens, grants and decisions.

Everything is a frozen dataclass holding tuples and frozensets, so a ``Policy`` that the server has loaded can be
shared between threads and swapped atomically without anyone being able to mutate it half way. Datetimes are
timezone-aware (UTC); the store rejects naive ones when it loads a file.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Optional

KINDS = ("human-device", "agent", "runner")
ACTIONS = ("list", "read", "write", "delete")
#: Tag grants may not write: whoever can write an entry can retag it, so a tag-based write grant would let a
#: principal widen its own reach (design section 4.3).
TAG_ACTIONS = ("list", "read")

POLICY_VERSION = 2


def utcnow() -> datetime:
    """The current time as an aware UTC datetime (one place, so tests and callers can pass ``now`` instead)."""
    return datetime.now(UTC)


@dataclass(frozen=True)
class Token:
    """A credential of a principal. Only its salted hash is kept; ``id`` is the public, loggable handle."""

    id: str
    hash: str = field(repr=False)  # never in a repr: reprs end up in logs and tracebacks
    created: datetime
    expires: Optional[datetime] = None
    description: str = ""

    def is_expired(self, now: datetime) -> bool:
        """``now >= expires`` counts as expired: a token is valid strictly before its expiry instant."""
        return self.expires is not None and now >= self.expires


@dataclass(frozen=True)
class Principal:
    """A named identity that presents tokens."""

    name: str
    kind: str
    description: str = ""
    admin: bool = False
    disabled: bool = False
    created: Optional[datetime] = None
    tokens: tuple[Token, ...] = ()


@dataclass(frozen=True)
class Grant:
    """Permission for one principal on a key pattern or a KeePass tag. Exactly one of ``key`` and ``tag`` is set."""

    id: str
    principal: str
    key: Optional[str]
    tag: Optional[str]
    actions: frozenset[str]
    expires: Optional[datetime] = None
    description: str = ""
    created: Optional[datetime] = None

    def is_expired(self, now: datetime) -> bool:
        return self.expires is not None and now >= self.expires


@dataclass(frozen=True)
class Policy:
    """The whole policy document."""

    version: int = POLICY_VERSION
    revision: int = 0
    principals: tuple[Principal, ...] = ()
    grants: tuple[Grant, ...] = ()

    def principal(self, name: str) -> Optional[Principal]:
        """Look a principal up by name, ignoring case (names are unique without regard to case)."""
        wanted = name.casefold()
        for candidate in self.principals:
            if candidate.name.casefold() == wanted:
                return candidate
        return None

    def grants_for(self, name: str) -> tuple[Grant, ...]:
        """The grants whose ``principal`` is exactly ``name``.

        Exact on purpose: two principals must never share each other's grants.
        """
        return tuple(grant for grant in self.grants if grant.principal == name)


@dataclass(frozen=True)
class Decision:
    """The outcome of an authorisation check. ``reason`` is one of ``granted``, ``no-grant``,
    ``disabled`` or ``not-admin``; ``grant_id`` names the grant that allowed the request."""

    allowed: bool
    reason: str
    grant_id: Optional[str] = None
