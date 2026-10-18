"""Authorisation decisions: default deny, expiry, disabled principals, key and tag grants."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from mattstash.authz import (
    Decision,
    Grant,
    Policy,
    PolicyError,
    Principal,
    admin_decision,
    can_admin,
    evaluate,
    explain,
    visible,
)

NOW = datetime(2026, 10, 18, 12, 0, tzinfo=UTC)


def grant(gid: str = "g_00000001", principal: str = "bot", key: str | None = "app.*", tag: str | None = None, **kw):
    actions = kw.pop("actions", frozenset({"list", "read"}))
    return Grant(gid, principal, key, tag, actions, **kw)


def make(*grants: Grant, **principal_kw) -> tuple[Policy, Principal]:
    principal = Principal("bot", "agent", **principal_kw)
    return Policy(principals=(principal,), grants=grants), principal


def test_default_deny() -> None:
    policy, bot = make()
    assert evaluate(policy, bot, "read", "app.x", now=NOW) == Decision(False, "no-grant")


def test_key_grant_allows_with_its_id() -> None:
    policy, bot = make(grant())
    assert evaluate(policy, bot, "read", "app.x", now=NOW) == Decision(True, "granted", "g_00000001")
    assert evaluate(policy, bot, "list", "app.x", now=NOW).allowed
    assert not evaluate(policy, bot, "read", "app", now=NOW).allowed
    assert not evaluate(policy, bot, "read", "other", now=NOW).allowed


def test_action_must_be_in_the_grant() -> None:
    policy, bot = make(grant())
    assert not evaluate(policy, bot, "write", "app.x", now=NOW).allowed
    assert not evaluate(policy, bot, "delete", "app.x", now=NOW).allowed


def test_unknown_action_is_a_programming_error() -> None:
    policy, bot = make(grant())
    with pytest.raises(PolicyError, match="unknown action"):
        evaluate(policy, bot, "admin", "app.x", now=NOW)
    with pytest.raises(PolicyError):
        visible(policy, bot, "READ", [], NOW)


def test_expiry_is_exclusive() -> None:
    policy, bot = make(grant(expires=NOW))
    assert not evaluate(policy, bot, "read", "app.x", now=NOW).allowed  # exactly at expiry: expired
    assert evaluate(policy, bot, "read", "app.x", now=NOW - timedelta(microseconds=1)).allowed
    assert not evaluate(policy, bot, "read", "app.x", now=NOW + timedelta(days=1)).allowed


def test_another_valid_grant_still_applies_when_one_expired() -> None:
    policy, bot = make(grant("g_00000001", expires=NOW), grant("g_00000002", key="app.*"))
    assert evaluate(policy, bot, "read", "app.x", now=NOW).grant_id == "g_00000002"


def test_default_now_is_the_clock() -> None:
    policy, bot = make(grant(expires=datetime(2000, 1, 1, tzinfo=UTC)))
    assert not evaluate(policy, bot, "read", "app.x").allowed
    policy, bot = make(grant())
    assert evaluate(policy, bot, "read", "app.x").allowed
    assert visible(policy, bot, "read", [("app.x", ())]) == ["app.x"]


def test_disabled_principal_is_denied_everything() -> None:
    policy, bot = make(grant(), disabled=True)
    assert evaluate(policy, bot, "read", "app.x", now=NOW) == Decision(False, "disabled")
    assert visible(policy, bot, "read", [("app.x", ())], NOW) == []


def test_grants_of_another_principal_do_not_count() -> None:
    other = Principal("other", "agent")
    bot = Principal("bot", "agent")
    policy = Policy(principals=(bot, other), grants=(grant(principal="other"),))
    assert not evaluate(policy, bot, "read", "app.x", now=NOW).allowed
    assert evaluate(policy, other, "read", "app.x", now=NOW).allowed


def test_grant_lookup_is_exact_not_case_insensitive() -> None:
    policy, bot = make(grant(principal="BOT"))
    assert not evaluate(policy, bot, "read", "app.x", now=NOW).allowed


def test_tag_grant() -> None:
    policy, bot = make(grant(key=None, tag="ops"))
    assert evaluate(policy, bot, "read", "anything", ["ops", "x"], NOW) == Decision(True, "granted", "g_00000001")
    assert not evaluate(policy, bot, "read", "anything", ["Ops"], NOW).allowed  # case sensitive
    assert not evaluate(policy, bot, "read", "anything", [], NOW).allowed
    assert not evaluate(policy, bot, "read", "anything", iter(["x"]), NOW).allowed


def test_visible_filters_in_order() -> None:
    policy, bot = make(grant(), grant("g_00000002", key=None, tag="ops"))
    items = [("app.a", []), ("zzz", ["ops"]), ("zzz2", []), ("app.b", ["x"])]
    assert visible(policy, bot, "list", items, NOW) == ["app.a", "zzz", "app.b"]
    assert visible(policy, bot, "write", items, NOW) == []


def test_legacy_principal_uses_synthetic_grants_and_reason() -> None:
    legacy = Principal("legacy-env", "legacy", admin=True)
    synthetic = Grant("legacy:legacy-env", "legacy-env", "*", None, frozenset({"list", "read", "write", "delete"}))
    policy = Policy(grants=(synthetic,))
    assert evaluate(policy, legacy, "delete", "x", now=NOW) == Decision(True, "legacy", "legacy:legacy-env")
    assert admin_decision(legacy) == Decision(True, "legacy")


def test_can_admin_and_admin_decision() -> None:
    human = Principal("m", "human-device", admin=True)
    assert can_admin(human) and admin_decision(human) == Decision(True, "granted")
    assert not can_admin(replace(human, disabled=True))
    assert admin_decision(replace(human, disabled=True)) == Decision(False, "disabled")
    assert not can_admin(replace(human, admin=False))
    assert admin_decision(replace(human, admin=False)) == Decision(False, "not-admin")
    # an agent or runner never administers, even if the flag were set on the object
    for kind in ("agent", "runner"):
        assert not can_admin(Principal("x", kind, admin=True))
        assert admin_decision(Principal("x", kind, admin=True)).reason == "not-admin"


def test_explain() -> None:
    policy, bot = make(grant())
    assert "allowed" in explain(policy, bot, "read", "app.x", now=NOW) and "g_00000001" in explain(
        policy, bot, "read", "app.x", now=NOW
    )
    assert explain(policy, bot, "read", "nope", now=NOW).startswith("denied: bot (agent) read 'nope': no-grant")
    legacy = Principal("legacy-1", "legacy")
    lpolicy = Policy(grants=(Grant("legacy:legacy-1", "legacy-1", "*", None, frozenset({"read"})),))
    assert "(legacy key)" in explain(lpolicy, legacy, "read", "x", now=NOW)
