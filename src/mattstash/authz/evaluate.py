"""Authorisation decisions (design section 4.1).

Default deny. A request is allowed when at least one unexpired grant of the (enabled) principal includes the action
and matches the name or one of the entry's tags. There are no deny rules, so the order of grants never matters.
Legacy principals are evaluated the same way: they come with synthetic grants (``legacy.py``), and only the reason
differs, so audit logs can show which requests still use a v1 key.
"""

from collections.abc import Iterable
from datetime import datetime
from typing import Optional

from .errors import PolicyError
from .models import ACTIONS, LEGACY_KIND, Decision, Grant, Policy, Principal, utcnow
from .patterns import pattern_matches

_ADMIN_KINDS = ("human-device", LEGACY_KIND)


def can_admin(principal: Principal) -> bool:
    """Admin flag set, not disabled, and a kind that may administer (an agent or runner never can)."""
    return principal.admin and not principal.disabled and principal.kind in _ADMIN_KINDS


def admin_decision(principal: Principal) -> Decision:
    """Like :func:`can_admin` but says why not, for the access log."""
    if principal.disabled:
        return Decision(False, "disabled")
    if not can_admin(principal):
        return Decision(False, "not-admin")
    return Decision(True, "legacy" if principal.kind == LEGACY_KIND else "granted")


def _decide(
    grants: Iterable[Grant], principal: Principal, action: str, name: str, tags: frozenset[str], now: datetime
) -> Decision:
    for grant in grants:
        if grant.is_expired(now) or action not in grant.actions:
            continue
        matched = grant.key is not None and pattern_matches(grant.key, name)
        matched = matched or (grant.tag is not None and grant.tag in tags)
        if matched:
            return Decision(True, "legacy" if principal.kind == LEGACY_KIND else "granted", grant.id)
    return Decision(False, "no-grant")


def _check_action(action: str) -> None:
    if action not in ACTIONS:
        # a typo in calling code would otherwise silently deny everything; fail loudly instead
        raise PolicyError(f"unknown action {action!r}; expected one of {', '.join(ACTIONS)}")


def evaluate(
    policy: Policy,
    principal: Principal,
    action: str,
    name: str,
    tags: Iterable[str] = (),
    now: Optional[datetime] = None,
) -> Decision:
    """May ``principal`` do ``action`` on the entry ``name`` carrying ``tags``?"""
    _check_action(action)
    if principal.disabled:
        return Decision(False, "disabled")
    moment = utcnow() if now is None else now
    return _decide(policy.grants_for(principal.name), principal, action, name, frozenset(tags), moment)


def visible(
    policy: Policy,
    principal: Principal,
    action: str,
    items: Iterable[tuple[str, Iterable[str]]],
    now: Optional[datetime] = None,
) -> list[str]:
    """The names from ``(name, tags)`` pairs the principal may do ``action`` on, in input order (list/search filter)."""
    _check_action(action)
    if principal.disabled:
        return []
    moment = utcnow() if now is None else now
    grants = policy.grants_for(principal.name)
    return [name for name, tags in items if _decide(grants, principal, action, name, frozenset(tags), moment).allowed]


def explain(
    policy: Policy,
    principal: Principal,
    action: str,
    name: str,
    tags: Iterable[str] = (),
    now: Optional[datetime] = None,
) -> str:
    """A one-line human explanation for ``mattstash admin check``."""
    decision = evaluate(policy, principal, action, name, tags, now)
    subject = f"{principal.name} ({principal.kind}) {action} {name!r}"
    if decision.allowed:
        return f"allowed: {subject} by grant {decision.grant_id}" + (
            " (legacy key)" if decision.reason == "legacy" else ""
        )
    return f"denied: {subject}: {decision.reason}"
