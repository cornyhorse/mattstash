"""The JSON policy file: strict parsing, stable dumping, atomic saving and locked editing (design section 5).

The file is written by tools (CLI and admin API) and read by the server, so it is JSON rather than YAML: comments
would not survive the first write, and each record has a ``description`` instead. It holds token *hashes* only.

Parsing is deliberately strict. Unknown fields are an error at every level: a policy written for a newer server
(say, a token bound to a device) must not load on an older one that would silently ignore the restriction. Duplicate
JSON keys are an error too, because "last one wins" would let a stray line override an earlier restriction.
"""

import contextlib
import json
import os
import re
import secrets
import stat
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Optional, Union

from ..utils.filelock import FileLock
from ..utils.fileops import match_owner
from .errors import PolicyError
from .evaluate import can_admin
from .models import (
    ACTIONS,
    KINDS,
    POLICY_VERSION,
    TAG_ACTIONS,
    Grant,
    Policy,
    Principal,
    Token,
    utcnow,
)
from .patterns import validate_pattern, validate_tag
from .tokens import generate_token, hash_token, is_valid_token_id, validate_token_hash

PathLike = Union[str, "os.PathLike[str]"]

_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", re.ASCII)
_GRANT_ID_RE = re.compile(r"g_[0-9a-f]{8}", re.ASCII)
RESERVED_PREFIX = "legacy-"
MAX_DESCRIPTION_LENGTH = 500
#: Largest revision accepted: keeps ``revision + 1`` and its JSON text far from any integer-size limit.
MAX_REVISION = 2**63 - 1
#: A change is refused when it leaves every admin token expiring within this long, having had one that outlasts it.
LOCKOUT_HORIZON = timedelta(hours=1)


def empty_policy() -> Policy:
    return Policy()


# ---------------------------------------------------------------------------
# Validation of a Policy object (shared by parsing, editing and migration)
# ---------------------------------------------------------------------------


def validate_name(name: object) -> None:
    """Raise :class:`PolicyError` unless ``name`` is a legal principal name."""
    if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
        raise PolicyError("principal name must match [A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
    if name.casefold().startswith(RESERVED_PREFIX):
        raise PolicyError(
            f"principal name {name!r} is reserved: names starting with '{RESERVED_PREFIX}' are for legacy keys"
        )


def _check_description(text: object, where: str) -> None:
    if not isinstance(text, str) or len(text) > MAX_DESCRIPTION_LENGTH or not text.isprintable():
        # control characters would let a description forge terminal output or log lines
        raise PolicyError(f"{where}: description must be printable text of at most {MAX_DESCRIPTION_LENGTH} characters")


def _check_aware(value: object, where: str) -> None:
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise PolicyError(f"{where} must be a timezone-aware datetime")


def _hash_identity(stored: str) -> str:
    """What makes two stored hashes "the same credential": the hex digest for the unsalted ``sha256:`` scheme (so
    case or formatting can't hide a duplicate), the whole string for the salted scheme (salts never repeat)."""
    return stored.split(":", 1)[1] if stored.startswith("sha256:") else stored


def _validate_token(token: Token, owner: str, seen_ids: set[str], seen_hashes: set[str]) -> None:
    where = f"principal {owner!r}, token {token.id!r}"
    if not is_valid_token_id(token.id):
        raise PolicyError(f"principal {owner!r}: token id must be 12 characters of [a-z2-7]")
    if token.id in seen_ids:
        raise PolicyError(f"{where}: duplicate token id")
    seen_ids.add(token.id)
    validate_token_hash(token.hash)
    identity = _hash_identity(token.hash)
    if identity in seen_hashes:
        # two tokens with one hash: the same secret would authenticate as two principals (message: no hash in it)
        raise PolicyError(f"{where}: the same token secret is already used by another token")
    seen_hashes.add(identity)
    _check_aware(token.created, f"{where}: 'created'")
    if token.expires is not None:
        _check_aware(token.expires, f"{where}: 'expires'")
    _check_description(token.description, where)


def _validate_principal(
    principal: Principal, seen_names: set[str], seen_token_ids: set[str], seen_hashes: set[str]
) -> None:
    validate_name(principal.name)
    folded = principal.name.casefold()
    if folded in seen_names:
        raise PolicyError(f"duplicate principal name {principal.name!r} (names are unique without regard to case)")
    seen_names.add(folded)
    where = f"principal {principal.name!r}"
    if principal.kind not in KINDS:
        raise PolicyError(f"{where}: kind must be one of {', '.join(KINDS)}")
    if principal.admin and principal.kind != "human-device":
        raise PolicyError(f"{where}: only human-device principals may be admins")
    _check_description(principal.description, where)
    if principal.created is not None:
        _check_aware(principal.created, f"{where}: 'created'")
    for token in principal.tokens:
        _validate_token(token, principal.name, seen_token_ids, seen_hashes)


def _validate_grant(grant: Grant, kinds: Mapping[str, str], seen_ids: set[str]) -> None:
    if not isinstance(grant.id, str) or not _GRANT_ID_RE.fullmatch(grant.id):
        raise PolicyError("grant id must be 'g_' followed by 8 lowercase hex digits")
    if grant.id in seen_ids:
        raise PolicyError(f"duplicate grant id {grant.id!r}")
    seen_ids.add(grant.id)
    where = f"grant {grant.id}"
    if grant.principal not in kinds:
        raise PolicyError(f"{where}: unknown principal {grant.principal!r}")
    if (grant.key is None) == (grant.tag is None):
        raise PolicyError(f"{where}: provide exactly one of 'key' and 'tag'")
    if grant.key is not None:
        validate_pattern(grant.key)
        if grant.key == "*" and kinds[grant.principal] != "human-device":
            raise PolicyError(
                f"{where}: the '*' grant (every secret) is only for human-device principals, not "
                f"{kinds[grant.principal]}s; use a narrower pattern such as 'service.*'"
            )
    if grant.tag is not None:
        validate_tag(grant.tag)
    if not grant.actions:
        raise PolicyError(f"{where}: at least one action is required")
    unknown = sorted(set(grant.actions) - set(ACTIONS))
    if unknown:
        raise PolicyError(f"{where}: unknown actions {unknown}; valid: {list(ACTIONS)}")
    if grant.tag is not None and not set(grant.actions) <= set(TAG_ACTIONS):
        raise PolicyError(f"{where}: tag grants may only allow {' and '.join(TAG_ACTIONS)}")
    if grant.expires is not None:
        _check_aware(grant.expires, f"{where}: 'expires'")
    if grant.created is not None:
        _check_aware(grant.created, f"{where}: 'created'")
    _check_description(grant.description, where)


def validate_policy(policy: Policy) -> None:
    """Raise :class:`PolicyError` unless the whole document is consistent."""
    if policy.version != POLICY_VERSION:
        raise PolicyError(f"unsupported policy version {policy.version!r}; this build reads version {POLICY_VERSION}")
    if type(policy.revision) is not int or not 0 <= policy.revision <= MAX_REVISION:
        raise PolicyError(f"revision must be an integer from 0 to {MAX_REVISION}")
    names: set[str] = set()
    token_ids: set[str] = set()
    token_hashes: set[str] = set()
    for principal in policy.principals:
        _validate_principal(principal, names, token_ids, token_hashes)
    kinds = {principal.name: principal.kind for principal in policy.principals}
    grant_ids: set[str] = set()
    for grant in policy.grants:
        _validate_grant(grant, kinds, grant_ids)


# ---------------------------------------------------------------------------
# JSON <-> Policy
# ---------------------------------------------------------------------------


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    for field, value in pairs:
        if field in seen:
            raise PolicyError(f"policy contains the duplicate field {field!r}")
        seen[field] = value
    return seen


def _object(value: Any, where: str, required: Iterable[str], optional: Iterable[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PolicyError(f"{where} must be an object")
    allowed = set(required) | set(optional)
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise PolicyError(f"{where}: unknown field(s) {unknown}")
    missing = sorted(set(required) - set(value))
    if missing:
        raise PolicyError(f"{where}: missing field(s) {missing}")
    return value


def _string(value: Any, where: str) -> str:
    if not isinstance(value, str):
        raise PolicyError(f"{where} must be a string")
    return value


def _optional_string(value: Any, where: str) -> Optional[str]:
    return None if value is None else _string(value, where)


def _boolean(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise PolicyError(f"{where} must be true or false")
    return value


def _array(value: Any, where: str) -> list[Any]:
    if not isinstance(value, list):
        raise PolicyError(f"{where} must be a list")
    return value


def _datetime(value: Any, where: str) -> datetime:
    text = _string(value, where)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        raise PolicyError(f"{where} is not an RFC 3339 timestamp") from None
    if parsed.utcoffset() is None:
        raise PolicyError(f"{where} has no timezone; write it in UTC with a trailing 'Z'")
    try:
        return parsed.astimezone(UTC)
    except (OverflowError, ValueError):  # 0001-01-01T00:00:00+05:00 has no UTC equivalent
        raise PolicyError(f"{where} is outside the range of supported dates") from None


def _optional_datetime(value: Any, where: str) -> Optional[datetime]:
    return None if value is None else _datetime(value, where)


def _parse_token(raw: Any, owner: str) -> Token:
    where = f"principal {owner!r}, token"
    data = _object(raw, where, ("id", "hash", "created"), ("expires", "description"))
    return Token(
        id=_string(data["id"], f"{where} id"),
        hash=_string(data["hash"], f"{where} hash"),
        created=_datetime(data["created"], f"{where} 'created'"),
        expires=_optional_datetime(data.get("expires"), f"{where} 'expires'"),
        description=_string(data.get("description", ""), f"{where} description"),
    )


def _parse_principal(raw: Any, index: int) -> Principal:
    where = f"principal #{index}"
    data = _object(raw, where, ("name", "kind"), ("description", "admin", "disabled", "created", "tokens"))
    name = _string(data["name"], f"{where} name")
    where = f"principal {name!r}"
    return Principal(
        name=name,
        kind=_string(data["kind"], f"{where} kind"),
        description=_string(data.get("description", ""), f"{where} description"),
        admin=_boolean(data.get("admin", False), f"{where} 'admin'"),
        disabled=_boolean(data.get("disabled", False), f"{where} 'disabled'"),
        created=_optional_datetime(data.get("created"), f"{where} 'created'"),
        tokens=tuple(_parse_token(token, name) for token in _array(data.get("tokens", []), f"{where} tokens")),
    )


def _parse_grant(raw: Any, index: int) -> Grant:
    where = f"grant #{index}"
    data = _object(raw, where, ("id", "principal", "actions"), ("key", "tag", "expires", "description", "created"))
    grant_id = _string(data["id"], f"{where} id")
    where = f"grant {grant_id!r}"
    actions = [_string(action, f"{where} action") for action in _array(data["actions"], f"{where} actions")]
    if len(set(actions)) != len(actions):
        raise PolicyError(f"{where}: duplicate action")
    return Grant(
        id=grant_id,
        principal=_string(data["principal"], f"{where} principal"),
        key=_optional_string(data.get("key"), f"{where} key"),
        tag=_optional_string(data.get("tag"), f"{where} tag"),
        actions=frozenset(actions),
        expires=_optional_datetime(data.get("expires"), f"{where} 'expires'"),
        description=_string(data.get("description", ""), f"{where} description"),
        created=_optional_datetime(data.get("created"), f"{where} 'created'"),
    )


def parse_policy(text: str) -> Policy:
    """Parse and fully validate a policy document. Raises :class:`PolicyError`; messages never include hashes."""
    try:
        document = json.loads(text, object_pairs_hook=_no_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise PolicyError(f"policy file is not valid JSON (line {exc.lineno}, column {exc.colno})") from None
    except RecursionError:
        raise PolicyError("policy file is nested too deeply") from None
    except PolicyError:  # a duplicate field, from the hook (PolicyError is a ValueError)
        raise
    except ValueError:  # an integer with more digits than Python converts (sys.int_info.default_max_str_digits)
        raise PolicyError("policy file contains a number that is too large") from None
    data = _object(document, "policy", ("version", "principals", "grants"), ("revision",))
    version, revision = data["version"], data.get("revision", 0)
    if type(version) is not int:
        raise PolicyError("policy 'version' must be an integer")
    if not 0 <= version <= MAX_REVISION:
        raise PolicyError(f"unsupported policy version; this build reads version {POLICY_VERSION}")
    if type(revision) is not int:
        raise PolicyError("policy 'revision' must be an integer")
    policy = Policy(
        version=version,
        revision=revision,
        principals=tuple(_parse_principal(p, i) for i, p in enumerate(_array(data["principals"], "principals"), 1)),
        grants=tuple(_parse_grant(g, i) for i, g in enumerate(_array(data["grants"], "grants"), 1)),
    )
    validate_policy(policy)
    return policy


def _format_datetime(value: datetime) -> str:
    utc = value.astimezone(UTC)
    stamp = utc.isoformat(timespec="seconds" if utc.microsecond == 0 else "microseconds")
    return stamp.removesuffix("+00:00") + "Z"


def _token_to_json(token: Token) -> dict[str, Any]:
    record: dict[str, Any] = {"id": token.id, "hash": token.hash, "created": _format_datetime(token.created)}
    if token.expires is not None:
        record["expires"] = _format_datetime(token.expires)
    if token.description:
        record["description"] = token.description
    return record


def _principal_to_json(principal: Principal) -> dict[str, Any]:
    record: dict[str, Any] = {"name": principal.name, "kind": principal.kind}
    if principal.description:
        record["description"] = principal.description
    record["admin"] = principal.admin
    record["disabled"] = principal.disabled
    if principal.created is not None:
        record["created"] = _format_datetime(principal.created)
    record["tokens"] = [_token_to_json(token) for token in principal.tokens]
    return record


def _grant_to_json(grant: Grant) -> dict[str, Any]:
    record: dict[str, Any] = {"id": grant.id, "principal": grant.principal}
    if grant.key is not None:
        record["key"] = grant.key
    if grant.tag is not None:
        record["tag"] = grant.tag
    record["actions"] = [action for action in ACTIONS if action in grant.actions]
    if grant.expires is not None:
        record["expires"] = _format_datetime(grant.expires)
    if grant.description:
        record["description"] = grant.description
    if grant.created is not None:
        record["created"] = _format_datetime(grant.created)
    return record


def dump_policy(policy: Policy) -> str:
    """Serialise to stable, indented JSON with a trailing newline. ``parse_policy(dump_policy(p)) == p``."""
    document = {
        "version": policy.version,
        "revision": policy.revision,
        "principals": [_principal_to_json(principal) for principal in policy.principals],
        "grants": [_grant_to_json(grant) for grant in policy.grants],
    }
    return json.dumps(document, indent=2) + "\n"


# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------


def load_policy(path: PathLike) -> Policy:
    """Read and parse the policy file. ``FileNotFoundError`` if missing; a BOM written by an editor is tolerated."""
    try:
        text = Path(path).read_text(encoding="utf-8-sig")
    except UnicodeDecodeError:
        raise PolicyError("policy file is not valid UTF-8") from None
    return parse_policy(text)


def _write_atomic(path: Path, text: str) -> None:
    """Replace ``path`` with ``text``: temp file in the same directory, fsync, rename over.

    * A symlink is followed (``os.path.realpath``), so the link survives and the target is what is replaced.
    * An existing file keeps its permission bits, masked with ``0o640`` (never world-accessible, never executable;
      group read stays so a service account in the group can read what an admin writes), and its owner and group
      when we may set them (root: both; others: the group, best effort). A new file is 0600.
    * The temp file starts 0600, so the content is never readable by more than the final mode allows, even briefly.
    """
    target = Path(os.path.realpath(path))
    try:
        reference: Optional[os.stat_result] = os.stat(target)
    except OSError:
        reference = None
    mode = 0o600 if reference is None else stat.S_IMODE(reference.st_mode) & 0o640
    temporary = target.with_name(f".{target.name}.{secrets.token_hex(6)}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(text.encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        if reference is not None:
            match_owner(reference, str(temporary))
        os.replace(temporary, target)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise
    with contextlib.suppress(OSError):  # best effort: not possible on every platform or filesystem
        directory = os.open(target.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def save_policy(path: PathLike, policy: Policy) -> None:
    """Validate and atomically replace the policy file (see :func:`_write_atomic` for mode and owner). Does not lock:
    use :func:`edit_policy`."""
    text = dump_policy(policy)
    parse_policy(text)  # never write what we could not read back
    _write_atomic(Path(path), text)


# ---------------------------------------------------------------------------
# Lockout protection and editing
# ---------------------------------------------------------------------------


def has_usable_admin(policy: Policy, now: datetime) -> bool:
    """True if some principal can administer and holds at least one token that has not expired."""
    return any(can_admin(p) and any(not t.is_expired(now) for t in p.tokens) for p in policy.principals)


def _outlasts(policy: Policy, now: datetime, horizon: datetime) -> bool:
    """True if some admin holds a token that is valid now and is still valid at ``horizon`` (or never expires)."""
    return any(
        can_admin(p) and any(not t.is_expired(now) and (t.expires is None or t.expires > horizon) for t in p.tokens)
        for p in policy.principals
    )


def check_lockout(policy: Policy, now: datetime, legacy_admin_available: bool) -> None:
    """Refuse a policy that nobody could administer, unless a legacy admin key (outside the file) still can."""
    if legacy_admin_available or has_usable_admin(policy, now):
        return
    raise PolicyError(
        "this change would leave no admin principal with a valid token, so nobody could manage the policy; "
        "add or enable another admin (or issue it a token) first"
    )


def check_lockout_change(before: Policy, after: Policy, now: datetime, legacy_admin_available: bool) -> None:
    """Refuse a change that locks the admins out now or within the hour. A legacy admin key waives both rules.

    1. If ``before`` had an enabled admin with a valid token, ``after`` must still have one (:func:`check_lockout`).
    2. If ``before`` had an admin token that never expires or outlasts ``now + LOCKOUT_HORIZON`` (one hour), then
       ``after`` must still have one. Otherwise every remaining admin token would expire within the hour: rotating
       the only admin token with ``--grace 1h`` to a replacement that expires in a minute is such a change.

    A policy that was already within the hour of lockout is not blocked from changing: it is how you repair it.
    """
    if legacy_admin_available:
        return
    if has_usable_admin(before, now):
        check_lockout(after, now, legacy_admin_available)
    horizon = now + LOCKOUT_HORIZON
    if _outlasts(before, now, horizon) and not _outlasts(after, now, horizon):
        raise PolicyError(
            "this change would leave every admin token expiring within the hour, so nobody could manage the policy "
            "soon; give the admin token a later expiry (or add another admin) first"
        )


class PolicyEditor:
    """Mutations of one policy document, validated after every step. Obtain one from :func:`edit_policy`."""

    def __init__(self, policy: Policy, now: datetime) -> None:
        self._policy = policy
        self.now = now.replace(microsecond=0)

    @property
    def policy(self) -> Policy:
        return self._policy

    # -- helpers ----------------------------------------------------------

    def _set(self, policy: Policy) -> None:
        validate_policy(policy)
        self._policy = policy

    def _principal(self, name: str) -> Principal:
        found = self._policy.principal(name)
        if found is None:
            raise PolicyError(f"no such principal {name!r}")
        return found

    def _update(self, old: Principal, new: Principal, grants: Optional[tuple[Grant, ...]] = None) -> None:
        principals = tuple(new if candidate is old else candidate for candidate in self._policy.principals)
        self._set(
            replace(self._policy, principals=principals, grants=self._policy.grants if grants is None else grants)
        )

    def _new_token(self, expires: Optional[datetime], description: str) -> tuple[Token, str]:
        if expires is not None:
            _check_aware(expires, "token expiry")
            if expires <= self.now:
                raise PolicyError("a new token's expiry must be in the future")
        used = {token.id for principal in self._policy.principals for token in principal.tokens}
        while True:
            token_id, plaintext = generate_token()
            if token_id not in used:
                break
        token = Token(token_id, hash_token(plaintext), self.now, expires, description)
        return token, plaintext

    # -- principals -------------------------------------------------------

    def add_principal(self, name: str, kind: str, description: str = "", admin: bool = False) -> Principal:
        validate_name(name)
        if self._policy.principal(name) is not None:
            raise PolicyError(f"principal {name!r} already exists (names are unique without regard to case)")
        principal = Principal(name, kind, description, admin, False, self.now, ())
        self._set(replace(self._policy, principals=(*self._policy.principals, principal)))
        return principal

    def remove_principal(self, name: str) -> int:
        """Remove a principal and its grants; returns how many grants went with it."""
        principal = self._principal(name)
        kept = tuple(g for g in self._policy.grants if g.principal != principal.name)
        removed = len(self._policy.grants) - len(kept)
        principals = tuple(p for p in self._policy.principals if p is not principal)
        self._set(replace(self._policy, principals=principals, grants=kept))
        return removed

    def set_disabled(self, name: str, disabled: bool) -> None:
        principal = self._principal(name)
        self._update(principal, replace(principal, disabled=disabled))

    def set_admin(self, name: str, admin: bool) -> None:
        principal = self._principal(name)
        self._update(principal, replace(principal, admin=admin))

    def set_description(self, name: str, text: str) -> None:
        principal = self._principal(name)
        self._update(principal, replace(principal, description=text))

    # -- tokens -----------------------------------------------------------

    def issue_token(
        self, principal: str, expires: Optional[datetime] = None, description: str = ""
    ) -> tuple[Token, str]:
        """Add a token. The plaintext is returned here and nowhere else: show it once."""
        owner = self._principal(principal)
        token, plaintext = self._new_token(expires, description)
        self._update(owner, replace(owner, tokens=(*owner.tokens, token)))
        return token, plaintext

    def _token(self, owner: Principal, token_id: str) -> Token:
        for token in owner.tokens:
            if token.id == token_id:
                return token
        raise PolicyError(f"principal {owner.name!r} has no token {token_id!r}")

    def revoke_token(self, principal: str, token_id: str) -> None:
        owner = self._principal(principal)
        doomed = self._token(owner, token_id)
        self._update(owner, replace(owner, tokens=tuple(t for t in owner.tokens if t is not doomed)))

    def rotate_token(
        self,
        principal: str,
        token_id: str,
        grace: timedelta = timedelta(0),
        expires: Optional[datetime] = None,
        description: str = "",
    ) -> tuple[Token, str]:
        """Issue a replacement and retire ``token_id``: removed now, or expiring after ``grace`` (never extended:
        its new expiry is the earlier of its current one and now + grace)."""
        owner = self._principal(principal)
        old = self._token(owner, token_id)
        if grace < timedelta(0):
            raise PolicyError("grace period must not be negative")
        token, plaintext = self._new_token(expires, description)
        if grace == timedelta(0):
            tokens = tuple(t for t in owner.tokens if t is not old)
        else:
            cutoff = self.now + grace
            retired = replace(old, expires=cutoff if old.expires is None else min(old.expires, cutoff))
            tokens = tuple(retired if t is old else t for t in owner.tokens)
        self._update(owner, replace(owner, tokens=(*tokens, token)))
        return token, plaintext

    # -- grants -----------------------------------------------------------

    def add_grant(
        self,
        principal: str,
        key: Optional[str] = None,
        tag: Optional[str] = None,
        actions: Iterable[str] = ("list", "read"),
        expires: Optional[datetime] = None,
        description: str = "",
    ) -> Grant:
        owner = self._principal(principal)
        if expires is not None:
            _check_aware(expires, "grant expiry")
            if expires <= self.now:
                raise PolicyError("a new grant's expiry must be in the future")
        used = {grant.id for grant in self._policy.grants}
        while True:
            grant_id = f"g_{secrets.token_hex(4)}"
            if grant_id not in used:
                break
        grant = Grant(grant_id, owner.name, key, tag, frozenset(actions), expires, description, self.now)
        self._set(replace(self._policy, grants=(*self._policy.grants, grant)))
        return grant

    def remove_grant(self, grant_id: str) -> None:
        kept = tuple(g for g in self._policy.grants if g.id != grant_id)
        if len(kept) == len(self._policy.grants):
            raise PolicyError(f"no such grant {grant_id!r}")
        self._set(replace(self._policy, grants=kept))

    # -- import -----------------------------------------------------------

    def import_v1(self, text: str, min_length: int, kind: str = "agent") -> tuple[str, ...]:
        """Convert a v1 JSON key policy into non-admin principals of ``kind`` and their grants (see
        ``legacy.migrate_v1``); returns the names."""
        from .legacy import migrate_v1  # local import: legacy builds on this module

        before = {p.name for p in self._policy.principals}
        self._set(migrate_v1(text, self._policy, min_length, self.now, kind))
        return tuple(p.name for p in self._policy.principals if p.name not in before)


@contextmanager
def edit_policy(
    path: PathLike,
    *,
    now: Optional[datetime] = None,
    legacy_admin_available: bool = False,
    create: bool = False,
) -> Iterator[PolicyEditor]:
    """Edit the policy file under an exclusive lock: re-read from disk, yield an editor, validate and save.

    On a clean exit the new document is validated by a round trip through the parser, checked for lockout, given
    ``revision + 1`` and saved atomically. If the body raises, nothing is saved.

    The lockout check (:func:`check_lockout_change`; waived by ``legacy_admin_available``) refuses a change that
    leaves no enabled admin with an unexpired token, and one that leaves only admin tokens expiring within the
    hour when the policy before had a token that lasts longer. It applies only when the policy *before* the edit
    had such an admin. That is what makes bootstrapping work: on an empty file you add an admin principal, then
    issue its token, as separate edits; neither is refused, though the first leaves no usable admin yet.

    ``create=True`` starts from an empty policy when the file does not exist; otherwise ``FileNotFoundError``.
    """
    target = Path(path)
    moment = utcnow() if now is None else now
    if create:
        target.parent.mkdir(parents=True, exist_ok=True)
    target = Path(os.path.realpath(target))  # the file is replaced at its real path, so the lock lives there too
    with FileLock(str(target.with_name(target.name + ".lock")), reference=str(target)):
        try:
            before = load_policy(target)
        except FileNotFoundError:
            if not create:
                raise
            before = empty_policy()
        editor = PolicyEditor(before, moment)
        yield editor
        after = replace(editor.policy, revision=before.revision + 1)
        text = dump_policy(after)
        parse_policy(text)
        check_lockout_change(before, after, moment, legacy_admin_available)
        _write_atomic(target, text)


# ---------------------------------------------------------------------------
# Durations for the CLI
# ---------------------------------------------------------------------------

_DURATION_RE = re.compile(r"(\d{1,6})([mhdw])", re.ASCII)
_UNITS: Mapping[str, Callable[[int], timedelta]] = {
    "m": lambda n: timedelta(minutes=n),
    "h": lambda n: timedelta(hours=n),
    "d": lambda n: timedelta(days=n),
    "w": lambda n: timedelta(weeks=n),
}
_DATE_RANGE = "outside the range of supported dates"


def parse_duration(text: str) -> timedelta:
    """``30m``, ``24h``, ``7d`` or ``2w`` (up to six digits) as a ``timedelta``; :class:`PolicyError` otherwise."""
    match = _DURATION_RE.fullmatch(text.strip())
    if match is None:
        raise PolicyError(f"cannot read {text!r} as a duration (30m, 24h, 7d, 2w)")
    return _UNITS[match.group(2)](int(match.group(1)))


def parse_duration_or_time(text: str, now: datetime) -> datetime:
    """``90d``, ``24h``, ``30m``, ``2w`` (from ``now``) or an ISO date/datetime (UTC unless it says otherwise).

    Raises :class:`PolicyError` for anything unreadable or outside the range of dates (``999999w``, year 0001 with
    a positive offset).
    """
    cleaned = text.strip()
    if _DURATION_RE.fullmatch(cleaned):
        try:
            return now + parse_duration(cleaned)
        except OverflowError:
            raise PolicyError(f"{text!r} is {_DATE_RANGE}") from None
    try:
        parsed = datetime.fromisoformat(cleaned)
    except ValueError:
        raise PolicyError(f"cannot read {text!r} as a duration (90d, 24h, 30m, 2w) or a date (2027-01-01)") from None
    if parsed.utcoffset() is None:
        parsed = parsed.replace(tzinfo=UTC)
    try:
        return parsed.astimezone(UTC)
    except (OverflowError, ValueError):
        raise PolicyError(f"{text!r} is {_DATE_RANGE}") from None
