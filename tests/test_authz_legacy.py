"""The v1 key sources as principals and synthetic grants, and v1 -> v2 migration."""

import hashlib
import json
from datetime import UTC, datetime

import pytest

from mattstash.authz import (
    Policy,
    PolicyError,
    Principal,
    Token,
    check_duplicate_keys,
    edit_policy,
    evaluate,
    legacy_from_env_key,
    legacy_from_keys_file_text,
    load_policy,
    migrate_v1,
    verify_token_hash,
)

NOW = datetime(2026, 10, 18, 12, 0, tzinfo=UTC)
MIN = 16
K1 = "k1-" + "a" * 30
K2 = "k2-" + "b" * 30
K3 = "k3-" + "c" * 30


def sha(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def decide(keys, grants, index: int, action: str, name: str):
    policy = Policy(grants=tuple(grants))
    return evaluate(policy, keys[index].principal, action, name, now=NOW)


def test_env_key() -> None:
    key, grants = legacy_from_env_key(K1, MIN)
    assert key.digest == hashlib.sha256(K1.encode()).digest()
    assert (key.principal.name, key.principal.kind, key.principal.admin) == ("legacy-env", "legacy", True)
    assert len(grants) == 1 and grants[0].id == "legacy:legacy-env" and grants[0].key == "*"
    assert grants[0].actions == {"list", "read", "write", "delete"}
    policy = Policy(grants=grants)
    for action in ("list", "read", "write", "delete"):
        assert evaluate(policy, key.principal, action, "anything", now=NOW).reason == "legacy"


def test_env_key_too_short() -> None:
    with pytest.raises(PolicyError, match="API key from MATTSTASH_API_KEY is shorter than 16 characters; generate one"):
        legacy_from_env_key("short", MIN)
    assert isinstance(PolicyError("x"), ValueError)


def test_plain_list_with_comments_and_bom() -> None:
    text = f"\ufeff# my keys\n\n{K1}\n  {K2}  \n# trailing\n"
    keys, grants, unscoped = legacy_from_keys_file_text(text, MIN)
    assert [k.principal.name for k in keys] == ["legacy-1", "legacy-2"]
    assert all(k.principal.admin and k.principal.kind == "legacy" for k in keys)
    assert unscoped is True
    assert [g.id for g in grants] == ["legacy:legacy-1", "legacy:legacy-2"]
    assert keys[1].digest == hashlib.sha256(K2.encode()).digest()
    assert decide(keys, grants, 0, "delete", "x").allowed


def test_plain_list_errors() -> None:
    with pytest.raises(
        PolicyError, match="API key on line 2 of the API keys file contains whitespace; one key per line"
    ):
        legacy_from_keys_file_text(f"{K1}\n{K2} extra\n", MIN)
    with pytest.raises(PolicyError, match="API key on line 1 of the API keys file is shorter than 16 characters"):
        legacy_from_keys_file_text("tiny\n", MIN)
    with pytest.raises(PolicyError, match="configured more than once"):
        legacy_from_keys_file_text(f"{K1}\n{K1}\n", MIN)


def test_empty_plain_list_is_not_unscoped() -> None:
    assert legacy_from_keys_file_text("# nothing\n\n", MIN) == ([], [], False)


V1 = {
    "keys": [
        {"id": "billing", "key_sha256": sha(K1).upper(), "ops": ["read"], "prefixes": ["billing-", "inv."]},
        {"id": "deploy", "key": K2, "ops": ["read", "write", "delete"]},
        {"id": "root", "key": K3, "ops": ["admin"], "prefixes": ["*"]},
    ]
}


def v1_text() -> str:
    return "# comment line\n" + json.dumps(V1)


def test_v1_json_conversion() -> None:
    keys, grants, unscoped = legacy_from_keys_file_text(v1_text(), MIN)
    assert unscoped is False  # v1 counted JSON keys as scoped, whatever their prefixes
    assert [(k.principal.name, k.principal.kind, k.principal.admin) for k in keys] == [
        ("billing", "legacy", False),
        ("deploy", "legacy", False),
        ("root", "legacy", True),
    ]
    assert keys[0].digest == bytes.fromhex(sha(K1))
    by_principal = {}
    for grant in grants:
        by_principal.setdefault(grant.principal, []).append(grant)
    assert [(g.id, g.key, set(g.actions)) for g in by_principal["billing"]] == [
        ("legacy:billing:1", "billing-*", {"list", "read"}),
        ("legacy:billing:2", "inv.*", {"list", "read"}),
    ]
    assert [(g.id, g.key, set(g.actions)) for g in by_principal["deploy"]] == [
        ("legacy:deploy", "*", {"list", "read", "write", "delete"})
    ]
    assert "root" not in by_principal  # admin alone grants no data access, exactly as in v1


def test_prefix_matching_equals_startswith() -> None:
    keys, grants, _ = legacy_from_keys_file_text(v1_text(), MIN)
    for name in ["billing-x", "billing-", "billing", "billingx", "Billing-x", "inv.a", "inv", "invoice", "other"]:
        expected = name.startswith(("billing-", "inv."))
        assert decide(keys, grants, 0, "read", name).allowed is expected, name
    assert not decide(keys, grants, 0, "write", "billing-x").allowed  # read does not imply write
    assert decide(keys, grants, 1, "delete", "whatever").allowed


def test_v1_json_default_ops_and_bare_list() -> None:
    text = json.dumps([{"id": "a", "key": K1}])
    keys, grants, _ = legacy_from_keys_file_text(text, MIN)
    assert keys[0].principal.name == "a" and grants[0].actions == {"list", "read"}


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ({"keys": []}, "non-empty 'keys' list"),
        ({"keys": "x"}, "non-empty 'keys' list"),
        ({"keys": ["x"]}, "entry #1 must be an object"),
        ({"keys": [{"id": "bad id", "key": K1}]}, "'id' must match"),
        ({"keys": [{"key": K1}]}, "'id' must match"),
        ({"keys": [{"id": "a"}]}, "exactly one of 'key' or 'key_sha256'"),
        ({"keys": [{"id": "a", "key": K1, "key_sha256": sha(K1)}]}, "exactly one of"),
        ({"keys": [{"id": "a", "key": 5}]}, "'key' must be a string"),
        ({"keys": [{"id": "a", "key": "short"}]}, "API key 'a' is shorter than 16 characters"),
        ({"keys": [{"id": "a", "key_sha256": "zz"}]}, "'key_sha256' must be 64 hex characters"),
        ({"keys": [{"id": "a", "key_sha256": 5}]}, "'key_sha256' must be 64 hex characters"),
        ({"keys": [{"id": "a", "key": K1, "ops": []}]}, "'ops' must be a non-empty list"),
        ({"keys": [{"id": "a", "key": K1, "ops": "read"}]}, "'ops' must be a non-empty list"),
        ({"keys": [{"id": "a", "key": K1, "ops": [1]}]}, "'ops' must be a non-empty list"),
        ({"keys": [{"id": "a", "key": K1, "ops": ["root"]}]}, "unknown ops \\['root'\\]"),
        ({"keys": [{"id": "a", "key": K1, "prefixes": []}]}, "'prefixes' must be a non-empty list"),
        ({"keys": [{"id": "a", "key": K1, "prefixes": "x"}]}, "'prefixes' must be a non-empty list"),
        ({"keys": [{"id": "a", "key": K1, "prefixes": ["a b"]}]}, "invalid prefix"),
        ({"keys": [{"id": "a", "key": K1, "prefixes": [3]}]}, "invalid prefix"),
        ({"keys": [{"id": "a", "key": K1, "prefixes": ["x", "*"]}]}, "invalid prefix"),
        ({"keys": [{"id": "a", "key": K1}, {"id": "a", "key": K2}]}, "duplicate ids"),
        ({"keys": [{"id": "a", "key": K1}, {"id": "b", "key": K1}]}, "configured more than once"),
    ],
)
def test_v1_json_errors_are_unchanged(document: dict, message: str) -> None:
    with pytest.raises(PolicyError, match=message):
        legacy_from_keys_file_text(json.dumps(document), MIN)


def test_v1_json_syntax_and_duplicate_fields() -> None:
    with pytest.raises(PolicyError, match=r"not valid JSON \(line 1, column"):
        legacy_from_keys_file_text("{ nope", MIN)
    with pytest.raises(PolicyError, match="duplicate field 'id'"):
        legacy_from_keys_file_text('{"keys": [{"id": "a", "id": "b", "key": "' + K1 + '"}]}', MIN)


def test_check_duplicate_keys_across_sources() -> None:
    env, _ = legacy_from_env_key(K1, MIN)
    keys, _, _ = legacy_from_keys_file_text(K1 + "\n", MIN)
    check_duplicate_keys([env])
    with pytest.raises(PolicyError, match="more than once"):
        check_duplicate_keys([env, *keys])


# -- migration -------------------------------------------------------------


def test_migrate_converts_keys_into_principals_and_grants() -> None:
    migrated = migrate_v1(v1_text(), Policy(revision=4), MIN, NOW)
    assert migrated.revision == 4
    billing, deploy, root = migrated.principals
    assert (billing.kind, billing.admin) == ("agent", False)
    assert (root.kind, root.admin) == ("human-device", True)
    token = billing.tokens[0]
    assert token.hash == "sha256:" + sha(K1) and verify_token_hash(token.hash, K1)
    assert token.created == NOW and len(token.id) == 12
    assert len({t.id for p in migrated.principals for t in p.tokens}) == 3
    assert [(g.principal, g.key, set(g.actions)) for g in migrated.grants] == [
        ("billing", "billing-*", {"list", "read"}),
        ("billing", "inv.*", {"list", "read"}),
        ("deploy", "*", {"list", "read", "write", "delete"}),
    ]
    assert evaluate(migrated, billing, "read", "billing-x", now=NOW).allowed
    assert not evaluate(migrated, billing, "read", "billingx", now=NOW).allowed
    assert evaluate(migrated, deploy, "write", "x", now=NOW).allowed


def test_migrate_name_clashes_and_bad_names() -> None:
    into = Policy(principals=(Principal("Billing", "agent"),))
    with pytest.raises(PolicyError, match="already exists"):
        migrate_v1(v1_text(), into, MIN, NOW)
    for key_id in ["-lead", "_x", "legacy-1"]:
        text = json.dumps({"keys": [{"id": key_id, "key": K1}]})
        with pytest.raises(PolicyError):
            migrate_v1(text, Policy(), MIN, NOW)


def test_migrate_refuses_a_plain_list_with_a_hint() -> None:
    with pytest.raises(PolicyError, match=r"no names.*principal add"):
        migrate_v1(f"{K1}\n{K2}\n", Policy(), MIN, NOW)


def test_migrate_propagates_v1_errors_and_overlong_prefixes() -> None:
    with pytest.raises(PolicyError, match="entry #1 must be an object"):
        migrate_v1('{"keys": ["x"]}', Policy(), MIN, NOW)
    long = json.dumps({"keys": [{"id": "a", "key": K1, "prefixes": ["x" * 255]}]})
    with pytest.raises(PolicyError, match="longer than 255"):
        migrate_v1(long, Policy(), MIN, NOW)


def test_migrate_skips_a_bom_and_avoids_existing_ids() -> None:
    existing = Token("aaaaaaaaaaaa", "sha256:" + "0" * 64, NOW)
    into = Policy(principals=(Principal("other", "agent", tokens=(existing,)),))
    out = migrate_v1("\ufeff" + json.dumps({"keys": [{"id": "a", "key": K1}]}), into, MIN, NOW)
    assert [p.name for p in out.principals] == ["other", "a"]


def test_editor_import_v1_saves_and_reports_names(tmp_path) -> None:
    path = tmp_path / "policy.json"
    with edit_policy(path, now=NOW, create=True) as editor:
        assert editor.import_v1(v1_text(), MIN) == ("billing", "deploy", "root")
    policy = load_policy(path)
    assert policy.revision == 1 and policy.principal("root").admin  # type: ignore[union-attr]
    with pytest.raises(PolicyError, match="already exists"), edit_policy(path, now=NOW) as editor:
        editor.import_v1(v1_text(), MIN)
