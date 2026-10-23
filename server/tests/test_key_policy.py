"""Credentials and verification: the policy file as the only source, tokens, imported keys, reloading."""

import hashlib
import logging
import os
from datetime import timedelta
from pathlib import Path

import pytest
from mattstash.authz import edit_policy, generate_token
from mattstash.authz.models import utcnow

from app.config import Config
from app.security import api_keys
from app.security.api_keys import (
    authenticate,
    check_removed_settings,
    get_auth_state,
    invalidate_api_key_cache,
    load_auth_state,
    reload_key_policy_now,
    verify_api_key,
)

from .conftest import ADMIN_KEY, APP_KEY, FULL_KEY, READ_KEY, import_plain_key

STRONG = "s" * 40


def sha(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def who(key: str):
    return authenticate(key).principal


# ---------------------------------------------------------------------------
# the policy file is the only credential source
# ---------------------------------------------------------------------------


def test_the_policy_file_is_required(monkeypatch):
    monkeypatch.setattr(Config, "POLICY_FILE", None)
    with pytest.raises(ValueError, match="MATTSTASH_POLICY_FILE is not set") as info:
        load_auth_state()
    assert "docs/upgrading-to-0.3.md" in str(info.value)


def test_first_load_failure_is_raised(monkeypatch):
    monkeypatch.setattr(Config, "POLICY_FILE", None)
    with pytest.raises(ValueError):
        get_auth_state()


def test_a_missing_policy_file_is_an_error_that_names_the_path(monkeypatch, tmp_path):
    monkeypatch.setattr(Config, "POLICY_FILE", str(tmp_path / "nope.json"))
    with pytest.raises(FileNotFoundError, match="Policy file not found"):
        load_auth_state()


def _write_policy(tmp_path, **kwargs) -> str:
    path = tmp_path / "p.json"
    now = utcnow() - timedelta(hours=2)
    with edit_policy(path, now=now, create=True) as ed:
        ed.add_principal("bot", "agent")
        if kwargs.get("token", True):
            ed.issue_token("bot", utcnow() - timedelta(hours=1) if kwargs.get("expired") else None)
        ed.set_disabled("bot", kwargs.get("disabled", False))
    return str(path)


@pytest.mark.parametrize(
    "kwargs",
    [{"token": False}, {"disabled": True}, {"expired": True}],
    ids=["no-token", "disabled-principal", "expired-token"],
)
def test_a_policy_without_a_usable_credential_is_an_error(monkeypatch, tmp_path, kwargs):
    monkeypatch.setattr(Config, "POLICY_FILE", _write_policy(tmp_path, **kwargs))
    with pytest.raises(ValueError, match="no usable credential") as info:
        load_auth_state()
    assert "token issue" in str(info.value)


def test_the_state_counts_salted_and_unsalted_tokens(monkeypatch, default_policy, policy_path, policy_tokens):
    monkeypatch.setattr(Config, "POLICY_FILE", default_policy)
    state = load_auth_state()  # one imported key: the unsalted scheme
    assert (len(state.tokens), len(state.digests), state.sha256_tokens, state.credential_count) == (0, 1, 1, 1)
    monkeypatch.setattr(Config, "POLICY_FILE", policy_path)
    state = load_auth_state()  # eight salted tokens (``expired`` counts: it is checked per request)
    assert (len(state.tokens), state.sha256_tokens, state.credential_count) == (8, 0, 8)


@pytest.mark.parametrize(
    ("env", "names"),
    [
        ({"MATTSTASH_API_KEY": "k" * 40}, ["MATTSTASH_API_KEY"]),
        ({"MATTSTASH_API_KEYS_FILE": "/keys.json"}, ["MATTSTASH_API_KEYS_FILE"]),
        ({"MATTSTASH_REQUIRE_SCOPED_KEYS": "true"}, ["MATTSTASH_REQUIRE_SCOPED_KEYS"]),
    ],
)
def test_removed_settings_are_refused_by_name_and_never_by_value(monkeypatch, env, names):
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    with pytest.raises(ValueError) as info:
        check_removed_settings()
    message = str(info.value)
    assert names[0] in message and " is set" in message and "docs/upgrading-to-0.3.md" in message
    assert "meant for the mattstash CLI client in this shell, unset it for the server process" in message
    assert ("no longer used" in message) == (names == ["MATTSTASH_REQUIRE_SCOPED_KEYS"])
    assert ("no longer accepts API keys" in message) == (names != ["MATTSTASH_REQUIRE_SCOPED_KEYS"])
    assert not any(value in message for value in env.values())
    assert Config.removed_settings_in_use() == names


def test_nothing_is_refused_when_no_removed_setting_is_set():
    check_removed_settings()
    assert Config.removed_settings_in_use() == []


def test_the_loader_never_reads_the_removed_settings(monkeypatch, default_policy):
    """Not even as a credential: with the variables set, the keys they hold authenticate nobody."""
    monkeypatch.setenv("MATTSTASH_API_KEY", STRONG)
    monkeypatch.setattr(Config, "POLICY_FILE", default_policy)
    assert who(STRONG) is None and who(FULL_KEY).name == "full"


# ---------------------------------------------------------------------------
# tokens of the policy file
# ---------------------------------------------------------------------------


def test_tokens_authenticate_as_their_principal(monkeypatch, policy_path, policy_tokens):
    monkeypatch.setattr(Config, "POLICY_FILE", policy_path)
    result = authenticate(policy_tokens["hermes"])
    assert (result.principal.name, result.principal.kind, result.reason) == ("hermes", "agent", "ok")
    assert result.token_id == policy_tokens["hermes"].split("_")[1]
    assert result.policy.grants_for("hermes")
    assert authenticate(policy_tokens["matt"]).principal.admin


def test_token_failures_have_distinct_reasons_and_never_a_principal(monkeypatch, policy_path, policy_tokens):
    monkeypatch.setattr(Config, "POLICY_FILE", policy_path)
    hermes = policy_tokens["hermes"]
    _, unknown = generate_token()
    outcomes = {
        "no header": (authenticate(None), "no-token"),
        "empty": (authenticate(""), "no-token"),
        "unknown id": (authenticate(unknown), "unknown-token"),
        "wrong secret": (authenticate(hermes[:-3] + "xyz"), "bad-token"),
        "not a token": (authenticate("whatever-key-" + "z" * 30), "bad-token"),
        "malformed mst": (authenticate("mst_short_x"), "bad-token"),
        "expired": (authenticate(policy_tokens["expired"]), "expired-token"),
        "disabled": (authenticate(policy_tokens["off"]), "disabled"),
    }
    for label, (result, reason) in outcomes.items():
        assert result.principal is None and result.reason == reason, label
    # a token id is reported only when the token parsed, and never anything of the secret
    assert outcomes["unknown id"][0].token_id == unknown.split("_")[1]
    assert outcomes["expired"][0].token_id and outcomes["disabled"][0].token_id
    assert outcomes["malformed mst"][0].token_id is None and outcomes["not a token"][0].token_id is None
    for result, _ in outcomes.values():
        assert hermes.split("_", 2)[2] not in repr(result)


def test_token_expiry_is_checked_at_request_time(monkeypatch, tmp_path):
    with edit_policy(tmp_path / "p.json", create=True) as ed:
        ed.add_principal("matt", "human-device", admin=True)
        token = ed.issue_token("matt", utcnow() + timedelta(seconds=1))[1]
    monkeypatch.setattr(Config, "POLICY_FILE", str(tmp_path / "p.json"))
    assert authenticate(token).reason == "ok"
    monkeypatch.setattr(api_keys, "utcnow", lambda: utcnow() + timedelta(seconds=5))
    assert authenticate(token).reason == "expired-token"


def test_unknown_ids_still_pay_for_a_hash_verification(monkeypatch, policy_path):
    monkeypatch.setattr(Config, "POLICY_FILE", policy_path)
    calls = []
    real = api_keys.verify_token_hash
    monkeypatch.setattr(api_keys, "verify_token_hash", lambda stored, key: calls.append(stored) or real(stored, key))
    authenticate(generate_token()[1])
    assert calls == [api_keys.DUMMY_HASH]


def test_an_imported_key_authenticates_as_its_principal_with_its_token_id(monkeypatch, default_policy):
    monkeypatch.setattr(Config, "POLICY_FILE", default_policy)
    result = authenticate(FULL_KEY)
    (token,) = get_auth_state().policy.principal("full").tokens
    assert (result.principal.name, result.reason, result.token_id) == ("full", "ok", token.id)
    assert token.hash == f"sha256:{sha(FULL_KEY)}" and FULL_KEY not in repr(result)


def test_an_imported_key_respects_expiry_disabled_and_revocation(monkeypatch, default_policy):
    monkeypatch.setattr(Config, "POLICY_FILE", default_policy)
    with edit_policy(default_policy) as ed:
        import_plain_key(ed, "full", STRONG, expires=utcnow() + timedelta(seconds=1))
    assert authenticate(STRONG).reason == "ok"
    monkeypatch.setattr(api_keys, "utcnow", lambda: utcnow() + timedelta(seconds=5))
    result = authenticate(STRONG)
    assert (result.reason, result.principal, result.token_id) == ("expired-token", None, result.token_id)
    assert result.token_id and authenticate(FULL_KEY).reason == "ok"
    monkeypatch.undo()
    monkeypatch.setattr(Config, "POLICY_FILE", default_policy)
    with edit_policy(default_policy) as ed:  # an admin is needed to stay: add a second, then disable the first
        ed.add_principal("second", "human-device", admin=True)
        ed.issue_token("second")
        ed.set_disabled("full", True)
    assert authenticate(FULL_KEY).reason == "disabled"


# ---------------------------------------------------------------------------
# migrated v1 keys: file tokens with the unsalted sha256: scheme, presented as the old plain key
# ---------------------------------------------------------------------------


@pytest.fixture
def migrated(tmp_path, key_policy_file):
    from mattstash.authz import edit_policy

    with edit_policy(tmp_path / "migrated.json", create=True) as ed:
        ed.import_v1(key_policy_file.read_text(), 32, "human-device")
    return str(tmp_path / "migrated.json")


def test_a_migrated_policy_authenticates_the_old_plain_keys_and_enforces_the_converted_grants(monkeypatch, migrated):
    from mattstash.authz import evaluate

    monkeypatch.setattr(Config, "POLICY_FILE", migrated)
    state = get_auth_state()
    assert state.sha256_tokens == 4
    app = authenticate(APP_KEY)
    assert (app.principal.name, app.principal.kind, app.reason) == ("app", "human-device", "ok")
    assert app.token_id  # the migrated token's public id is reported
    assert evaluate(app.policy, app.principal, "write", "app-x").allowed
    assert not evaluate(app.policy, app.principal, "write", "other").allowed
    reader = authenticate(READ_KEY)
    assert evaluate(reader.policy, reader.principal, "read", "other").allowed
    assert not evaluate(reader.policy, reader.principal, "write", "other").allowed
    assert not authenticate(ADMIN_KEY).principal.admin  # the v1 'admin' op (reload only) is not carried over
    assert authenticate("n" * 40).principal is None


def test_migrated_tokens_respect_expiry_and_disabled(monkeypatch, migrated):
    monkeypatch.setattr(Config, "POLICY_FILE", migrated)
    token_id = authenticate(APP_KEY).token_id
    with edit_policy(migrated) as ed:
        ed.set_disabled("app", True)
    invalidate_api_key_cache()
    assert (authenticate(APP_KEY).reason, authenticate(APP_KEY).principal) == ("disabled", None)
    with edit_policy(migrated) as ed:
        ed.set_disabled("app", False)
        ed.revoke_token("app", token_id)
        ed.issue_token("app")
    invalidate_api_key_cache()
    assert authenticate(APP_KEY).reason == "bad-token"  # revoked: the old key no longer matches anything


def test_an_expired_migrated_token_is_rejected(monkeypatch, tmp_path):
    from dataclasses import replace

    from mattstash.authz import Principal, Token, dump_policy, empty_policy, hash_token

    policy = empty_policy()
    token = Token("abcdefghijkl", f"sha256:{sha(STRONG)}", utcnow() - timedelta(days=2), utcnow() - timedelta(days=1))
    other = Token("mnopqrstuvwx", hash_token("mst_mnopqrstuvwx_" + "a" * 43), utcnow())
    policy = replace(
        policy,
        principals=(
            Principal("old", "agent", tokens=(token,)),
            Principal("m", "human-device", admin=True, tokens=(other,)),
        ),
    )
    path = tmp_path / "p.json"
    path.write_text(dump_policy(policy))
    monkeypatch.setattr(Config, "POLICY_FILE", str(path))
    result = authenticate(STRONG)
    assert (result.principal, result.reason, result.token_id) == (None, "expired-token", "abcdefghijkl")


# ---------------------------------------------------------------------------
# verification
# ---------------------------------------------------------------------------


def test_verification_is_safe_for_any_input(monkeypatch, default_policy):
    monkeypatch.setattr(Config, "POLICY_FILE", default_policy)
    for odd in ["", " ", "café", "é" * 100, "\x00", "\udcff", FULL_KEY[:-1], FULL_KEY + "x", FULL_KEY.upper()]:
        assert authenticate(odd).principal is None  # never raises (non-ASCII used to crash compare_digest)
    assert authenticate(FULL_KEY).principal is not None


def test_verify_api_key_wrapper(monkeypatch, default_policy):
    monkeypatch.setattr(Config, "POLICY_FILE", default_policy)
    assert verify_api_key(FULL_KEY) is True
    assert verify_api_key("nope") is False


def test_only_digests_are_retained_in_memory(monkeypatch, default_policy):
    monkeypatch.setattr(Config, "POLICY_FILE", default_policy)
    state = load_auth_state()
    assert FULL_KEY not in repr(state) and FULL_KEY not in repr(state.digests)


def test_every_unsalted_digest_is_compared_without_an_early_exit(monkeypatch, default_policy):
    """The match is found by comparing against ALL ``sha256:`` tokens (no branch on which one matched)."""
    with edit_policy(default_policy) as ed:
        for n in range(3):
            import_plain_key(ed, "full", f"extra-key-{n}-" + "e" * 30)
    monkeypatch.setattr(Config, "POLICY_FILE", default_policy)
    compared = []
    real = api_keys.hmac.compare_digest
    monkeypatch.setattr(api_keys.hmac, "compare_digest", lambda a, b: compared.append(1) or real(a, b))
    assert authenticate(FULL_KEY).reason == "ok"  # the first of four
    assert len(compared) == 4


# ---------------------------------------------------------------------------
# caching, rotation, hot reload of the policy file
# ---------------------------------------------------------------------------


def test_state_is_cached_then_refreshed_after_the_ttl(monkeypatch, default_policy):
    monkeypatch.setattr(Config, "POLICY_FILE", default_policy)
    clock = {"now": 10_000.0}
    monkeypatch.setattr(api_keys.time, "monotonic", lambda: clock["now"])
    first = get_auth_state()
    assert get_auth_state() is first  # cached
    clock["now"] += api_keys._CACHE_TTL_SECONDS - 1
    assert get_auth_state() is first  # still within the TTL
    clock["now"] += 2
    assert get_auth_state() is not first  # reloaded though the file did not change


def test_invalidate_forces_a_reload_even_when_the_file_looks_unchanged(monkeypatch, default_policy):
    monkeypatch.setattr(Config, "POLICY_FILE", default_policy)
    first = get_auth_state()
    assert get_auth_state() is first
    invalidate_api_key_cache()
    assert get_auth_state() is not first


def test_policy_file_changes_are_picked_up_by_stat_without_waiting_for_the_ttl(monkeypatch, policy_path, policy_tokens):
    monkeypatch.setattr(Config, "POLICY_FILE", policy_path)
    assert authenticate(policy_tokens["hermes"]).reason == "ok"
    token_id = policy_tokens["hermes"].split("_")[1]
    with edit_policy(policy_path) as ed:  # another writer: the CLI, or an admin request on another replica
        ed.revoke_token("hermes", token_id)
    assert authenticate(policy_tokens["hermes"]).reason == "unknown-token"  # no invalidate call needed


def test_an_unchanged_policy_file_is_not_reloaded(monkeypatch, policy_path):
    monkeypatch.setattr(Config, "POLICY_FILE", policy_path)
    first = get_auth_state()
    assert get_auth_state() is first and get_auth_state() is first


def test_a_broken_policy_file_keeps_the_previous_policy_and_is_retried_only_when_it_changes(
    monkeypatch, policy_path, policy_tokens, caplog
):
    monkeypatch.setattr(Config, "POLICY_FILE", policy_path)
    assert authenticate(policy_tokens["hermes"]).reason == "ok"
    caplog.set_level(logging.ERROR, logger="mattstash.api")

    good = Path(policy_path).read_text()
    with open(policy_path, "w") as handle:
        handle.write(good.replace('"version": 2', '"version": 99'))
    assert authenticate(policy_tokens["hermes"]).reason == "ok"  # previous policy still serves
    assert caplog.text.count("reload failed") == 1
    assert authenticate(policy_tokens["hermes"]).reason == "ok"
    assert caplog.text.count("reload failed") == 1  # the same broken version is not parsed again per request

    with open(policy_path, "w") as handle:  # fixed (and revoked a token while at it): picked up at once
        handle.write(good.replace(policy_tokens["hermes"].split("_")[1], "zzzzzzzzzzzz"))
    assert authenticate(policy_tokens["hermes"]).reason == "unknown-token"
    assert authenticate(policy_tokens["matt"]).reason == "ok"


def test_a_vanished_policy_file_keeps_the_previous_policy(monkeypatch, policy_path, policy_tokens):
    monkeypatch.setattr(Config, "POLICY_FILE", policy_path)
    assert authenticate(policy_tokens["hermes"]).reason == "ok"
    os.unlink(policy_path)
    assert authenticate(policy_tokens["hermes"]).reason == "ok"


def test_failed_reload_keeps_the_previous_policy_and_retries_after_a_short_backoff(monkeypatch, default_policy, caplog):
    monkeypatch.setattr(Config, "POLICY_FILE", default_policy)
    clock = {"now": 10_000.0}
    monkeypatch.setattr(api_keys.time, "monotonic", lambda: clock["now"])
    assert verify_api_key(FULL_KEY)
    real_load, calls, broken = api_keys.load_auth_state, [], {"on": True}

    def flaky():
        calls.append(1)
        if broken["on"]:
            raise OSError("disk hiccup")
        return real_load()

    monkeypatch.setattr(api_keys, "load_auth_state", flaky)
    invalidate_api_key_cache()
    caplog.set_level(logging.ERROR, logger="mattstash.api")
    assert verify_api_key(FULL_KEY) is True  # the previous policy keeps working
    assert "reload failed (OSError)" in caplog.text and FULL_KEY not in caplog.text

    # no re-read (and no new error line) on every request during the backoff...
    caplog.clear()
    broken["on"] = False  # fixed, but we are still inside the backoff window
    assert verify_api_key(FULL_KEY) is True and not caplog.text and len(calls) == 1

    # ...and the fix is picked up as soon as the backoff has elapsed
    clock["now"] += api_keys._RETRY_SECONDS + 0.1
    assert verify_api_key(FULL_KEY) and len(calls) == 2


def test_reload_key_policy_now_replaces_the_state_atomically(monkeypatch, tmp_path):
    path = _write_policy(tmp_path)
    monkeypatch.setattr(Config, "POLICY_FILE", path)
    first = get_auth_state()
    with edit_policy(path) as ed:
        ed.set_disabled("bot", True)  # a policy the server cannot serve: no usable credential
    with pytest.raises(ValueError, match="no usable credential"):
        reload_key_policy_now()
    assert get_auth_state() is first  # a failed reload changes nothing
    with edit_policy(path) as ed:
        ed.set_disabled("bot", False)
        ed.issue_token("bot")
    assert reload_key_policy_now().credential_count == 2


# ---------------------------------------------------------------------------
# the early warning about the last admin token expiring
# ---------------------------------------------------------------------------


def _admin_policy(tmp_path, days):
    path = tmp_path / "admin.json"
    with edit_policy(path, create=True) as ed:
        ed.add_principal("matt", "human-device", admin=True)
        ed.issue_token("matt", utcnow() + timedelta(days=days))
    return str(path)


def test_the_expiry_warning_is_logged_at_the_first_load_and_not_repeated_by_reloads(monkeypatch, tmp_path, caplog):
    path = _admin_policy(tmp_path, 3)
    monkeypatch.setattr(Config, "POLICY_FILE", path)
    caplog.set_level(logging.WARNING, logger="mattstash.api")
    get_auth_state()
    invalidate_api_key_cache()
    get_auth_state()  # a periodic reload: same warning, not logged again
    reload_key_policy_now()
    assert caplog.text.count("every admin token expires within 14 days") == 1
    with edit_policy(path) as ed:  # a longer-lived admin token ends the warning...
        ed.issue_token("matt", utcnow() + timedelta(days=90))
    get_auth_state()
    caplog.clear()
    with edit_policy(path) as ed:  # ...and when it comes back it is logged again
        ed.revoke_token("matt", ed.policy.principal("matt").tokens[-1].id)
    get_auth_state()
    assert caplog.text.count("every admin token expires within 14 days") == 1


def test_the_expiry_warning_is_logged_again_after_a_restart(monkeypatch, tmp_path, caplog):
    monkeypatch.setattr(Config, "POLICY_FILE", _admin_policy(tmp_path, 3))
    caplog.set_level(logging.WARNING, logger="mattstash.api")
    get_auth_state()
    api_keys._state = None  # a new process
    get_auth_state()
    assert caplog.text.count("every admin token expires within 14 days") == 2
