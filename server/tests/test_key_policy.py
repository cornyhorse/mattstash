"""Credential sources and verification: legacy keys (H-2, H-3, M-5), policy-file tokens, merging, reloading."""

import hashlib
import json
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
    get_auth_state,
    invalidate_api_key_cache,
    load_auth_state,
    reload_key_policy_now,
    verify_api_key,
)

from .conftest import ADMIN_KEY, APP_KEY, FULL_KEY, READ_KEY, WRITE_KEY

STRONG = "s" * 40


def sha(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def write(tmp_path, content) -> str:
    path = tmp_path / "keys"
    path.write_text(content if isinstance(content, str) else json.dumps(content))
    return str(path)


def who(key: str):
    return authenticate(key).principal


# ---------------------------------------------------------------------------
# legacy sources
# ---------------------------------------------------------------------------


def test_legacy_env_key_gets_full_access(monkeypatch):
    monkeypatch.setattr(Config, "API_KEY", FULL_KEY)
    state = load_auth_state()
    result = authenticate(FULL_KEY)
    assert result.principal.kind == "legacy" and result.principal.admin and result.reason == "ok"
    assert result.token_id is None
    assert result.principal.name.startswith("legacy-") and FULL_KEY not in result.principal.name
    grants = state.policy.grants_for("legacy-env")
    assert len(grants) == 1 and grants[0].key == "*" and grants[0].actions == {"list", "read", "write", "delete"}
    assert state.legacy_sources == ("MATTSTASH_API_KEY",) and state.legacy_admin


def test_legacy_key_file_with_comments_and_blank_lines(monkeypatch, tmp_path):
    keys = [chr(97 + i) * 36 for i in range(3)]
    monkeypatch.setattr(Config, "API_KEYS_FILE", write(tmp_path, "# prod\n" + "\n\n".join(keys) + "\n# end\n"))
    assert load_auth_state().credential_count == 3 and all(who(k) for k in keys)


def test_env_and_file_keys_combine(monkeypatch, tmp_path):
    monkeypatch.setattr(Config, "API_KEY", FULL_KEY)
    monkeypatch.setattr(Config, "API_KEYS_FILE", write(tmp_path, STRONG + "\n"))
    state = load_auth_state()
    assert state.credential_count == 2 and state.legacy_sources == ("MATTSTASH_API_KEY", "MATTSTASH_API_KEYS_FILE")


@pytest.mark.parametrize("key", ["tiny-secret-7", "x" * 31])
def test_weak_legacy_keys_are_refused(monkeypatch, key):
    monkeypatch.setattr(Config, "API_KEY", key)
    with pytest.raises(ValueError, match="shorter than 32 characters") as excinfo:
        load_auth_state()
    assert key not in str(excinfo.value)  # the message must never echo key material


def test_min_key_length_is_configurable(monkeypatch):
    monkeypatch.setattr(Config, "API_KEY", "x" * 12)
    monkeypatch.setattr(Config, "MIN_KEY_LENGTH", 12)
    assert load_auth_state().credential_count == 1


def test_weak_key_in_file_reports_the_line_number_not_the_key(monkeypatch, tmp_path):
    monkeypatch.setattr(Config, "API_KEYS_FILE", write(tmp_path, f"{STRONG}\nweak-one\n"))
    with pytest.raises(ValueError, match="on line 2") as excinfo:
        load_auth_state()
    assert "weak-one" not in str(excinfo.value)


def test_missing_keys_file_is_an_error(monkeypatch):
    monkeypatch.setattr(Config, "API_KEY", FULL_KEY)
    monkeypatch.setattr(Config, "API_KEYS_FILE", "/does/not/exist")
    with pytest.raises(FileNotFoundError, match="API keys file not found"):
        load_auth_state()


def test_missing_policy_file_is_an_error(monkeypatch, tmp_path):
    monkeypatch.setattr(Config, "API_KEY", FULL_KEY)
    monkeypatch.setattr(Config, "POLICY_FILE", str(tmp_path / "nope.json"))
    with pytest.raises(FileNotFoundError, match="Policy file not found"):
        load_auth_state()


def test_no_credentials_at_all_is_an_error(monkeypatch, tmp_path):
    with pytest.raises(ValueError, match="At least one API key must be provided"):
        load_auth_state()
    # a policy file with principals but no token is not a usable credential either
    with edit_policy(tmp_path / "p.json", create=True) as ed:
        ed.add_principal("matt", "human-device", admin=True)
    monkeypatch.setattr(Config, "POLICY_FILE", str(tmp_path / "p.json"))
    with pytest.raises(ValueError, match="At least one API key must be provided"):
        load_auth_state()


def test_duplicate_keys_are_refused(monkeypatch, tmp_path):
    monkeypatch.setattr(Config, "API_KEY", STRONG)
    monkeypatch.setattr(Config, "API_KEYS_FILE", write(tmp_path, STRONG + "\n"))
    with pytest.raises(ValueError, match="more than once"):
        load_auth_state()


def test_require_scoped_keys_rejects_legacy(monkeypatch):
    monkeypatch.setattr(Config, "API_KEY", FULL_KEY)
    monkeypatch.setattr(Config, "REQUIRE_SCOPED_KEYS", True)
    with pytest.raises(ValueError, match="REQUIRE_SCOPED_KEYS"):
        load_auth_state()


def test_require_scoped_keys_accepts_tokens_and_scoped_v1_keys(monkeypatch, policy_path, key_policy_file):
    monkeypatch.setattr(Config, "REQUIRE_SCOPED_KEYS", True)
    monkeypatch.setattr(Config, "POLICY_FILE", policy_path)
    monkeypatch.setattr(Config, "API_KEYS_FILE", str(key_policy_file))
    assert load_auth_state().legacy_sources == ("MATTSTASH_API_KEYS_FILE",)


# ---------------------------------------------------------------------------
# v1 JSON policy, converted to principals and synthetic grants
# ---------------------------------------------------------------------------


def test_json_policy_becomes_principals_and_grants(monkeypatch, key_policy_file):
    monkeypatch.setattr(Config, "API_KEYS_FILE", str(key_policy_file))
    state = load_auth_state()

    reader = who(READ_KEY)
    assert (reader.name, reader.kind, reader.admin) == ("reader", "legacy", False)
    (grant,) = state.policy.grants_for("reader")
    assert (grant.key, grant.actions) == ("*", {"list", "read"})

    assert who(APP_KEY).name == "app"
    (app_grant,) = state.policy.grants_for("app")
    assert (app_grant.key, app_grant.actions) == ("app-*", {"list", "read", "write", "delete"})
    assert who(WRITE_KEY).name == "writer"
    ops = who(ADMIN_KEY)
    assert ops.admin and state.policy.grants_for("ops") == ()  # admin only: no data grants


def test_bare_list_form_and_default_ops_are_least_privilege(monkeypatch, tmp_path):
    monkeypatch.setattr(Config, "API_KEYS_FILE", write(tmp_path, [{"id": "a", "key": STRONG}]))
    state = load_auth_state()
    assert [g.actions for g in state.policy.grants_for("a")] == [{"list", "read"}]


def test_wildcard_prefix_means_all_names(monkeypatch, tmp_path):
    entry = {"id": "a", "key": STRONG, "prefixes": ["*"]}
    monkeypatch.setattr(Config, "API_KEYS_FILE", write(tmp_path, {"keys": [entry]}))
    assert [g.key for g in load_auth_state().policy.grants_for("a")] == ["*"]


@pytest.mark.parametrize(
    "entry, message",
    [
        ({"key": STRONG}, "'id' must match"),
        ({"id": "bad id!", "key": STRONG}, "'id' must match"),
        ({"id": "a"}, "exactly one of 'key' or 'key_sha256'"),
        ({"id": "a", "key": STRONG, "key_sha256": sha(STRONG)}, "exactly one of"),
        ({"id": "a", "key_sha256": "not-hex"}, "64 hex characters"),
        ({"id": "a", "key": 12345}, "must be a string"),
        ({"id": "a", "key": "weak"}, "shorter than 32"),
        ({"id": "a", "key": STRONG, "ops": []}, "non-empty list"),
        ({"id": "a", "key": STRONG, "ops": ["read", "root"]}, "unknown ops"),
        ({"id": "a", "key": STRONG, "ops": "read"}, "non-empty list"),
        ({"id": "a", "key": STRONG, "prefixes": []}, "non-empty list"),
        ({"id": "a", "key": STRONG, "prefixes": ["a b"]}, "invalid prefix"),
        ({"id": "a", "key": STRONG, "prefixes": ["../"]}, "invalid prefix"),
        ("not an object", "must be an object"),
    ],
)
def test_invalid_policy_entries_are_rejected_with_safe_messages(monkeypatch, tmp_path, entry, message):
    monkeypatch.setattr(Config, "API_KEYS_FILE", write(tmp_path, {"keys": [entry]}))
    with pytest.raises(ValueError, match=message) as excinfo:
        load_auth_state()
    assert STRONG not in str(excinfo.value)


def test_duplicate_ids_are_rejected(monkeypatch, tmp_path):
    entries = [{"id": "a", "key": STRONG}, {"id": "a", "key": "t" * 40}]
    monkeypatch.setattr(Config, "API_KEYS_FILE", write(tmp_path, {"keys": entries}))
    with pytest.raises(ValueError, match="duplicate ids"):
        load_auth_state()


@pytest.mark.parametrize("content", ["{not json", '{"keys": []}', '{"keys": "x"}', "[]"])
def test_malformed_policy_documents(monkeypatch, tmp_path, content):
    monkeypatch.setattr(Config, "API_KEYS_FILE", write(tmp_path, content))
    with pytest.raises(ValueError):
        load_auth_state()


def test_json_error_message_does_not_echo_the_document(monkeypatch, tmp_path):
    monkeypatch.setattr(Config, "API_KEYS_FILE", write(tmp_path, '{"keys": [{"id": "a", "key": "' + STRONG + '" oops'))
    with pytest.raises(ValueError, match="not valid JSON") as excinfo:
        load_auth_state()
    assert STRONG not in str(excinfo.value)


# ---------------------------------------------------------------------------
# name clashes between sources: grants are found by principal name
# ---------------------------------------------------------------------------


def test_scoped_v1_key_named_like_the_env_key_cannot_inherit_full_access(monkeypatch, tmp_path):
    """Grants are looked up by name: a v1 key with id 'legacy-env' must not pick up the env key's '*' grant."""
    monkeypatch.setattr(Config, "API_KEY", FULL_KEY)
    entry = {"id": "legacy-env", "key": STRONG, "ops": ["read"], "prefixes": ["x-"]}
    monkeypatch.setattr(Config, "API_KEYS_FILE", write(tmp_path, {"keys": [entry]}))
    with pytest.raises(ValueError, match="used more than once"):
        load_auth_state()


@pytest.mark.parametrize("name", ["matt", "MATT", "Matt"])
def test_v1_id_clashing_with_a_policy_principal_is_a_load_error_ignoring_case(monkeypatch, tmp_path, policy_path, name):
    monkeypatch.setattr(Config, "POLICY_FILE", policy_path)
    monkeypatch.setattr(Config, "API_KEYS_FILE", write(tmp_path, {"keys": [{"id": name, "key": STRONG}]}))
    with pytest.raises(ValueError, match="used more than once"):
        load_auth_state()


def test_v1_ids_that_differ_only_in_case_are_a_load_error(monkeypatch, tmp_path):
    entries = [{"id": "Ops", "key": STRONG}, {"id": "ops", "key": "t" * 40}]
    monkeypatch.setattr(Config, "API_KEYS_FILE", write(tmp_path, {"keys": entries}))
    with pytest.raises(ValueError, match="used more than once"):
        load_auth_state()


def test_v1_id_that_looks_like_a_positional_name_clashes_with_the_plain_list_key(monkeypatch, tmp_path):
    monkeypatch.setattr(Config, "API_KEY", FULL_KEY)
    monkeypatch.setattr(Config, "API_KEYS_FILE", write(tmp_path, {"keys": [{"id": "LEGACY-ENV", "key": STRONG}]}))
    with pytest.raises(ValueError, match="used more than once"):
        load_auth_state()


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


def test_tokens_and_legacy_keys_work_side_by_side(monkeypatch, policy_path, policy_tokens):
    monkeypatch.setattr(Config, "POLICY_FILE", policy_path)
    monkeypatch.setattr(Config, "API_KEY", FULL_KEY)
    assert who(FULL_KEY).name == "legacy-env" and who(policy_tokens["hermes"]).name == "hermes"
    policy = get_auth_state().policy
    assert {"legacy-env", "hermes"} <= {p.name for p in policy.principals}


# ---------------------------------------------------------------------------
# migrated v1 keys: file tokens with the unsalted sha256: scheme, presented as the old plain key
# ---------------------------------------------------------------------------


@pytest.fixture
def migrated(tmp_path, key_policy_file):
    from mattstash.authz import edit_policy

    with edit_policy(tmp_path / "migrated.json", create=True) as ed:
        ed.import_v1(key_policy_file.read_text(), 32)
    return str(tmp_path / "migrated.json")


def test_a_migrated_policy_authenticates_the_old_plain_keys_and_enforces_the_converted_grants(monkeypatch, migrated):
    from mattstash.authz import evaluate

    monkeypatch.setattr(Config, "POLICY_FILE", migrated)
    state = get_auth_state()
    assert state.sha256_tokens == 4 and state.legacy_sources == ()
    app = authenticate(APP_KEY)
    assert (app.principal.name, app.principal.kind, app.reason) == ("app", "agent", "ok")
    assert app.token_id  # the migrated token's public id is reported
    assert evaluate(app.policy, app.principal, "write", "app-x").allowed
    assert not evaluate(app.policy, app.principal, "write", "other").allowed
    reader = authenticate(READ_KEY)
    assert evaluate(reader.policy, reader.principal, "read", "other").allowed
    assert not evaluate(reader.policy, reader.principal, "write", "other").allowed
    assert authenticate(ADMIN_KEY).principal.admin
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
        ed.issue_token("app", utcnow() - timedelta(hours=1))
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


def test_the_same_key_in_the_env_and_a_migrated_token_is_a_load_error(monkeypatch, migrated):
    monkeypatch.setattr(Config, "POLICY_FILE", migrated)
    monkeypatch.setattr(Config, "API_KEY", APP_KEY)
    with pytest.raises(ValueError, match="more than once"):
        load_auth_state()


def test_startup_state_counts_sha256_tokens_for_the_deprecation_warning(monkeypatch, migrated):
    monkeypatch.setattr(Config, "POLICY_FILE", migrated)
    assert load_auth_state().sha256_tokens == 4


# ---------------------------------------------------------------------------
# verification
# ---------------------------------------------------------------------------


def test_verification_is_safe_for_any_input(monkeypatch):
    monkeypatch.setattr(Config, "API_KEY", FULL_KEY)
    for odd in ["", " ", "café", "é" * 100, "\x00", "\udcff", FULL_KEY[:-1], FULL_KEY + "x", FULL_KEY.upper()]:
        assert authenticate(odd).principal is None  # never raises (non-ASCII used to crash compare_digest)
    assert authenticate(FULL_KEY).principal is not None


def test_verify_api_key_wrapper(monkeypatch):
    monkeypatch.setattr(Config, "API_KEY", FULL_KEY)
    assert verify_api_key(FULL_KEY) is True
    assert verify_api_key("nope") is False


def test_only_digests_are_retained_in_memory(monkeypatch):
    monkeypatch.setattr(Config, "API_KEY", FULL_KEY)
    state = load_auth_state()
    assert FULL_KEY not in repr(state) and FULL_KEY not in repr(state.digests)


# ---------------------------------------------------------------------------
# caching, rotation, hot reload of the policy file
# ---------------------------------------------------------------------------


def test_state_is_cached_then_refreshed_after_ttl(monkeypatch, tmp_path):
    path = tmp_path / "keys"
    path.write_text(STRONG + "\n")
    monkeypatch.setattr(Config, "API_KEYS_FILE", str(path))
    first = get_auth_state()
    assert get_auth_state() is first  # cached

    path.write_text("t" * 40 + "\n")
    assert get_auth_state() is first  # still within TTL
    monkeypatch.setattr(api_keys, "_CACHE_TTL_SECONDS", 0.0)
    refreshed = get_auth_state()
    assert refreshed is not first and who("t" * 40) and not who(STRONG)


def test_invalidate_forces_a_reload_and_picks_up_rotation(monkeypatch, tmp_path):
    path = tmp_path / "keys"
    path.write_text(STRONG + "\n")
    monkeypatch.setattr(Config, "API_KEYS_FILE", str(path))
    assert verify_api_key(STRONG)
    path.write_text("t" * 40 + "\n")
    invalidate_api_key_cache()
    assert verify_api_key("t" * 40) and not verify_api_key(STRONG)


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


def test_failed_reload_keeps_the_previous_policy_and_retries_after_a_short_backoff(monkeypatch, tmp_path, caplog):
    path = tmp_path / "keys"
    path.write_text(STRONG + "\n")
    monkeypatch.setattr(Config, "API_KEYS_FILE", str(path))
    clock = {"now": 10_000.0}
    monkeypatch.setattr(api_keys.time, "monotonic", lambda: clock["now"])
    assert verify_api_key(STRONG)

    path.write_text("")  # broken edit: no keys
    invalidate_api_key_cache()
    caplog.set_level(logging.ERROR, logger="mattstash.api")
    assert verify_api_key(STRONG) is True  # old keys keep working
    assert "reload failed" in caplog.text and STRONG not in caplog.text

    # no re-read (and no new error line) on every request during the backoff...
    caplog.clear()
    path.write_text("t" * 40 + "\n")  # the file is fixed, but we are still inside the backoff window
    assert verify_api_key(STRONG) is True and not caplog.text

    # ...and the fix is picked up as soon as the backoff has elapsed
    clock["now"] += api_keys._RETRY_SECONDS + 0.1
    assert verify_api_key("t" * 40) and not verify_api_key(STRONG)


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


def test_reload_key_policy_now_replaces_the_state_atomically(monkeypatch, tmp_path):
    keys = tmp_path / "keys"
    keys.write_text("o" * 40 + "\n")
    monkeypatch.setattr(Config, "API_KEYS_FILE", str(keys))
    assert api_keys.verify_api_key("o" * 40)
    keys.write_text("")
    with pytest.raises(ValueError):
        reload_key_policy_now()
    assert api_keys.verify_api_key("o" * 40)  # a failed reload changes nothing
    keys.write_text("n" * 40 + "\n")
    assert reload_key_policy_now().credential_count == 1
    assert api_keys.verify_api_key("n" * 40) and not api_keys.verify_api_key("o" * 40)


def test_first_load_failure_is_raised(monkeypatch):
    monkeypatch.setattr(Config, "API_KEY", None)
    with pytest.raises(ValueError):
        get_auth_state()
