"""Key policy loading and verification (H-2 key strength, H-3 scopes, M-5 non-ASCII)."""

import hashlib
import json
import logging

import pytest

from app.config import Config
from app.security import api_keys
from app.security.api_keys import (
    KeyPolicy,
    Principal,
    authenticate,
    get_key_policy,
    invalidate_api_key_cache,
    load_key_policy,
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


# ---------------------------------------------------------------------------
# legacy sources
# ---------------------------------------------------------------------------


def test_legacy_env_key_gets_full_access(monkeypatch):
    monkeypatch.setattr(Config, "API_KEY", FULL_KEY)
    policy = load_key_policy()
    principal = policy.authenticate(FULL_KEY)
    assert principal is not None and principal.legacy
    assert principal.ops == {"read", "write", "delete", "admin"} and principal.prefixes is None
    assert principal.id.startswith("legacy-") and FULL_KEY not in principal.id
    assert policy.legacy_count == 1


def test_legacy_key_file_with_comments_and_blank_lines(monkeypatch, tmp_path):
    keys = [chr(97 + i) * 36 for i in range(3)]
    monkeypatch.setattr(Config, "API_KEYS_FILE", write(tmp_path, "# prod\n" + "\n\n".join(keys) + "\n# end\n"))
    policy = load_key_policy()
    assert len(policy) == 3 and all(policy.authenticate(k) for k in keys)


def test_env_and_file_keys_combine(monkeypatch, tmp_path):
    monkeypatch.setattr(Config, "API_KEY", FULL_KEY)
    monkeypatch.setattr(Config, "API_KEYS_FILE", write(tmp_path, STRONG + "\n"))
    assert len(load_key_policy()) == 2


@pytest.mark.parametrize("key", ["tiny-secret-7", "x" * 31])
def test_weak_legacy_keys_are_refused(monkeypatch, key):
    monkeypatch.setattr(Config, "API_KEY", key)
    with pytest.raises(ValueError, match="shorter than 32 characters") as excinfo:
        load_key_policy()
    assert key not in str(excinfo.value)  # the message must never echo key material


def test_min_key_length_is_configurable(monkeypatch):
    monkeypatch.setattr(Config, "API_KEY", "x" * 12)
    monkeypatch.setattr(Config, "MIN_KEY_LENGTH", 12)
    assert len(load_key_policy()) == 1


def test_weak_key_in_file_reports_the_line_number_not_the_key(monkeypatch, tmp_path):
    monkeypatch.setattr(Config, "API_KEYS_FILE", write(tmp_path, f"{STRONG}\nweak-one\n"))
    with pytest.raises(ValueError, match="on line 2") as excinfo:
        load_key_policy()
    assert "weak-one" not in str(excinfo.value)


def test_missing_keys_file_is_an_error(monkeypatch):
    monkeypatch.setattr(Config, "API_KEY", FULL_KEY)
    monkeypatch.setattr(Config, "API_KEYS_FILE", "/does/not/exist")
    with pytest.raises(FileNotFoundError, match="API keys file not found"):
        load_key_policy()


def test_no_keys_at_all_is_an_error():
    with pytest.raises(ValueError, match="At least one API key must be provided"):
        load_key_policy()


def test_duplicate_keys_are_refused(monkeypatch, tmp_path):
    monkeypatch.setattr(Config, "API_KEY", STRONG)
    monkeypatch.setattr(Config, "API_KEYS_FILE", write(tmp_path, STRONG + "\n"))
    with pytest.raises(ValueError, match="more than once"):
        load_key_policy()


def test_require_scoped_keys_rejects_legacy(monkeypatch):
    monkeypatch.setattr(Config, "API_KEY", FULL_KEY)
    monkeypatch.setattr(Config, "REQUIRE_SCOPED_KEYS", True)
    with pytest.raises(ValueError, match="REQUIRE_SCOPED_KEYS"):
        load_key_policy()


# ---------------------------------------------------------------------------
# JSON policy
# ---------------------------------------------------------------------------


def test_json_policy_scopes_and_hashed_keys(monkeypatch, key_policy_file):
    monkeypatch.setattr(Config, "API_KEYS_FILE", str(key_policy_file))
    monkeypatch.setattr(Config, "REQUIRE_SCOPED_KEYS", True)  # all entries are scoped: allowed
    policy = load_key_policy()

    reader = policy.authenticate(READ_KEY)
    assert (reader.id, reader.ops, reader.prefixes, reader.legacy) == ("reader", frozenset({"read"}), None, False)
    app = policy.authenticate(APP_KEY)
    assert (app.id, app.prefixes) == ("app", ("app-",)) and app.can("delete") and not app.can("admin")
    assert policy.authenticate(WRITE_KEY).can("write") and not policy.authenticate(WRITE_KEY).can("delete")
    assert policy.authenticate(ADMIN_KEY).ops == {"admin"}
    assert policy.legacy_count == 0


def test_principal_scope_checks():
    scoped = Principal("p", frozenset({"read"}), ("app-", "db."))
    assert scoped.allows_name("app-x") and scoped.allows_name("db.main") and not scoped.allows_name("other")
    assert not scoped.allows_name("APP-x")  # prefixes are case-sensitive
    assert Principal("p", frozenset({"read"})).allows_name("anything")


def test_bare_list_form_and_default_ops_are_least_privilege(monkeypatch, tmp_path):
    monkeypatch.setattr(Config, "API_KEYS_FILE", write(tmp_path, [{"id": "a", "key": STRONG}]))
    assert load_key_policy().authenticate(STRONG).ops == {"read"}


def test_wildcard_prefix_means_all_names(monkeypatch, tmp_path):
    entry = {"id": "a", "key": STRONG, "prefixes": ["*"]}
    monkeypatch.setattr(Config, "API_KEYS_FILE", write(tmp_path, {"keys": [entry]}))
    assert load_key_policy().authenticate(STRONG).prefixes is None


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
        load_key_policy()
    assert STRONG not in str(excinfo.value)


def test_duplicate_ids_are_rejected(monkeypatch, tmp_path):
    entries = [{"id": "a", "key": STRONG}, {"id": "a", "key": "t" * 40}]
    monkeypatch.setattr(Config, "API_KEYS_FILE", write(tmp_path, {"keys": entries}))
    with pytest.raises(ValueError, match="duplicate ids"):
        load_key_policy()


@pytest.mark.parametrize("content", ["{not json", '{"keys": []}', '{"keys": "x"}', "[]"])
def test_malformed_policy_documents(monkeypatch, tmp_path, content):
    monkeypatch.setattr(Config, "API_KEYS_FILE", write(tmp_path, content))
    with pytest.raises(ValueError):
        load_key_policy()


def test_json_error_message_does_not_echo_the_document(monkeypatch, tmp_path):
    monkeypatch.setattr(Config, "API_KEYS_FILE", write(tmp_path, '{"keys": [{"id": "a", "key": "' + STRONG + '" oops'))
    with pytest.raises(ValueError, match="not valid JSON") as excinfo:
        load_key_policy()
    assert STRONG not in str(excinfo.value)


# ---------------------------------------------------------------------------
# verification
# ---------------------------------------------------------------------------


def test_verification_is_safe_for_any_input(monkeypatch):
    monkeypatch.setattr(Config, "API_KEY", FULL_KEY)
    policy = load_key_policy()
    for odd in ["", " ", "café", "é" * 100, "\x00", "\udcff", FULL_KEY[:-1], FULL_KEY + "x", FULL_KEY.upper()]:
        assert policy.authenticate(odd) is None  # never raises (non-ASCII used to crash compare_digest)
    assert policy.authenticate(FULL_KEY) is not None


def test_verify_api_key_wrapper(monkeypatch):
    monkeypatch.setattr(Config, "API_KEY", FULL_KEY)
    assert verify_api_key(FULL_KEY) is True
    assert verify_api_key("nope") is False
    assert authenticate("nope") is None


def test_only_digests_are_retained_in_memory(monkeypatch):
    monkeypatch.setattr(Config, "API_KEY", FULL_KEY)
    policy = load_key_policy()
    assert FULL_KEY not in repr(vars(policy)) and FULL_KEY not in repr(policy._records)


# ---------------------------------------------------------------------------
# caching / rotation
# ---------------------------------------------------------------------------


def test_policy_is_cached_then_refreshed_after_ttl(monkeypatch, tmp_path):
    path = tmp_path / "keys"
    path.write_text(STRONG + "\n")
    monkeypatch.setattr(Config, "API_KEYS_FILE", str(path))
    first = get_key_policy()
    assert get_key_policy() is first  # cached

    path.write_text("t" * 40 + "\n")
    assert get_key_policy() is first  # still within TTL
    monkeypatch.setattr(api_keys, "_CACHE_TTL_SECONDS", 0.0)
    refreshed = get_key_policy()
    assert refreshed is not first and refreshed.authenticate("t" * 40) and not refreshed.authenticate(STRONG)


def test_invalidate_forces_a_reload_and_picks_up_rotation(monkeypatch, tmp_path):
    path = tmp_path / "keys"
    path.write_text(STRONG + "\n")
    monkeypatch.setattr(Config, "API_KEYS_FILE", str(path))
    assert verify_api_key(STRONG)
    path.write_text("t" * 40 + "\n")
    invalidate_api_key_cache()
    assert verify_api_key("t" * 40) and not verify_api_key(STRONG)


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


def test_first_load_failure_is_raised(monkeypatch):
    monkeypatch.setattr(Config, "API_KEY", None)
    with pytest.raises(ValueError):
        get_key_policy()


def test_empty_policy_object_rejects_everything():
    assert KeyPolicy([]).authenticate("anything") is None
