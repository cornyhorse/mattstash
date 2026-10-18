"""Reading a v1 JSON key policy and converting it with ``migrate_v1`` (what is left of the v1 key sources)."""

import hashlib
import json
from datetime import UTC, datetime

import pytest

from mattstash.authz import (
    Policy,
    PolicyError,
    Principal,
    Token,
    edit_policy,
    evaluate,
    load_policy,
    migrate_v1,
    verify_token_hash,
)
from mattstash.authz.legacy import v1_admin_ids

NOW = datetime(2026, 10, 18, 12, 0, tzinfo=UTC)
MIN = 16
K1 = "k1-" + "a" * 30
K2 = "k2-" + "b" * 30
K3 = "k3-" + "c" * 30


def sha(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def convert(text: str, kind: str = "human-device") -> Policy:
    return migrate_v1(text, Policy(), MIN, NOW, kind)


V1 = {
    "keys": [
        {"id": "billing", "key_sha256": sha(K1).upper(), "ops": ["read"], "prefixes": ["billing-", "inv."]},
        {"id": "deploy", "key": K2, "ops": ["read", "write", "delete"]},
        {"id": "root", "key": K3, "ops": ["admin"], "prefixes": ["*"]},
    ]
}


def v1_text() -> str:
    return "# comment line\n" + json.dumps(V1)


def test_v1_json_conversion_keeps_ids_digests_and_prefix_grants() -> None:
    migrated = convert(v1_text())
    assert [(p.name, p.kind, p.admin) for p in migrated.principals] == [
        ("billing", "human-device", False),
        ("deploy", "human-device", False),
        ("root", "human-device", False),
    ]
    assert migrated.principals[0].tokens[0].hash == "sha256:" + sha(K1)
    by_principal: dict[str, list] = {}
    for grant in migrated.grants:
        by_principal.setdefault(grant.principal, []).append(grant)
    assert [(g.key, set(g.actions)) for g in by_principal["billing"]] == [
        ("billing-*", {"list", "read"}),
        ("inv.*", {"list", "read"}),
    ]
    assert [(g.key, set(g.actions)) for g in by_principal["deploy"]] == [("*", {"list", "read", "write", "delete"})]
    assert "root" not in by_principal  # admin alone grants no data access, exactly as in v1


def test_prefix_matching_equals_startswith() -> None:
    migrated = convert(v1_text())
    billing, deploy, _ = migrated.principals
    for name in ["billing-x", "billing-", "billing", "billingx", "Billing-x", "inv.a", "inv", "invoice", "other"]:
        expected = name.startswith(("billing-", "inv."))
        assert evaluate(migrated, billing, "read", name, now=NOW).allowed is expected, name
    assert not evaluate(migrated, billing, "write", "billing-x", now=NOW).allowed  # read does not imply write
    assert evaluate(migrated, deploy, "delete", "whatever", now=NOW).allowed


def test_v1_json_default_ops_and_bare_list() -> None:
    migrated = convert(json.dumps([{"id": "a", "key": K1}]))
    assert migrated.principals[0].name == "a" and migrated.grants[0].actions == {"list", "read"}


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
        convert(json.dumps(document))


def test_v1_json_syntax_and_duplicate_fields() -> None:
    with pytest.raises(PolicyError, match=r"not valid JSON \(line 1, column"):
        convert("{ nope")
    with pytest.raises(PolicyError, match="duplicate field 'id'"):
        convert('{"keys": [{"id": "a", "id": "b", "key": "' + K1 + '"}]}')


def test_comment_plus_minified_json_is_a_policy_not_one_key() -> None:
    """The whole JSON text used to be accepted as ONE full-access key (fail open) when a comment line preceded it."""
    text = "# generated for billing\n" + json.dumps({"keys": [{"id": "billing", "key": K1, "prefixes": ["bill-"]}]})
    migrated = convert(text, "agent")
    assert [p.name for p in migrated.principals] == ["billing"] and migrated.grants[0].key == "bill-*"
    assert not any(verify_token_hash(t.hash, text) for p in migrated.principals for t in p.tokens)


# -- migration -------------------------------------------------------------


def test_migrate_converts_keys_into_non_admin_principals_and_grants() -> None:
    migrated = migrate_v1(v1_text(), Policy(revision=4), MIN, NOW, "human-device")
    assert migrated.revision == 4
    billing, deploy, _root = migrated.principals
    assert [(p.kind, p.admin) for p in migrated.principals] == [("human-device", False)] * 3  # root's v1 admin op: gone
    token = billing.tokens[0]
    assert token.hash == "sha256:" + sha(K1) and verify_token_hash(token.hash, K1)
    assert token.created == NOW and len(token.id) == 12
    assert len({t.id for p in migrated.principals for t in p.tokens}) == 3
    assert [(g.principal, g.key, set(g.actions)) for g in migrated.grants] == [
        ("billing", "billing-*", {"list", "read"}),
        ("billing", "inv.*", {"list", "read"}),
        ("deploy", "*", {"list", "read", "write", "delete"}),
    ]  # root had only the v1 admin op: no grants
    assert evaluate(migrated, billing, "read", "billing-x", now=NOW).allowed
    assert not evaluate(migrated, billing, "read", "billingx", now=NOW).allowed
    assert evaluate(migrated, deploy, "write", "x", now=NOW).allowed


@pytest.mark.parametrize("kind", ["agent", "runner"])
def test_migrate_refuses_a_key_without_prefixes_unless_the_kind_is_human_device(kind: str) -> None:
    text = json.dumps({"keys": [{"id": "narrow", "key": K1, "prefixes": ["a."]}, {"id": "wide", "key": K2}]})
    with pytest.raises(PolicyError, match=rf"'wide' as {kind}.*every secret.*--kind human-device.*narrow") as info:
        migrate_v1(text, Policy(), MIN, NOW, kind)
    assert K2 not in str(info.value)
    narrow_only = json.dumps({"keys": [{"id": "narrow", "key": K1, "prefixes": ["a."]}]})
    assert [p.kind for p in migrate_v1(narrow_only, Policy(), MIN, NOW, kind).principals] == [kind]
    admin_only = json.dumps({"keys": [{"id": "ops", "key": K3, "ops": ["admin"]}]})  # no grants, so no '*' needed
    assert migrate_v1(admin_only, Policy(), MIN, NOW, kind).grants == ()


def test_migrate_defaults_to_agent_and_refuses_an_unknown_kind() -> None:
    narrow = json.dumps({"keys": [{"id": "n", "key": K1, "prefixes": ["a."]}]})
    assert migrate_v1(narrow, Policy(), MIN, NOW).principals[0].kind == "agent"
    with pytest.raises(PolicyError, match="kind must be one of"):
        migrate_v1(narrow, Policy(), MIN, NOW, "legacy")


def test_v1_admin_ids_lists_the_keys_that_had_the_admin_op() -> None:
    assert v1_admin_ids(v1_text(), MIN, ["billing", "root"]) == ["root"]
    assert v1_admin_ids("\ufeff" + v1_text(), MIN, ["billing"]) == []


def test_migrate_name_clashes_and_bad_names() -> None:
    into = Policy(principals=(Principal("Billing", "agent"),))
    with pytest.raises(PolicyError, match="already exists"):
        migrate_v1(v1_text(), into, MIN, NOW)
    for key_id in ["-lead", "_x", "legacy-1"]:
        text = json.dumps({"keys": [{"id": key_id, "key": K1}]})
        with pytest.raises(PolicyError):
            migrate_v1(text, Policy(), MIN, NOW)


def test_migrate_refuses_a_plain_list_with_a_hint() -> None:
    with pytest.raises(PolicyError, match=r"no names.*principal add.*token import"):
        migrate_v1(f"{K1}\n{K2}\n", Policy(), MIN, NOW)
    for nothing in ("", "\n\n", "# only a comment\n"):  # an empty or comment-only file is not a key policy either
        with pytest.raises(PolicyError, match="only a JSON key policy can be migrated"):
            migrate_v1(nothing, Policy(), MIN, NOW)


def test_migrate_propagates_v1_errors_and_overlong_prefixes() -> None:
    with pytest.raises(PolicyError, match="entry #1 must be an object"):
        migrate_v1('{"keys": ["x"]}', Policy(), MIN, NOW)
    long = json.dumps({"keys": [{"id": "a", "key": K1, "prefixes": ["x" * 255]}]})
    with pytest.raises(PolicyError, match="longer than 255"):
        migrate_v1(long, Policy(), MIN, NOW)


def test_migrate_skips_a_bom_and_avoids_existing_ids() -> None:
    existing = Token("aaaaaaaaaaaa", "sha256:" + "0" * 64, NOW)
    into = Policy(principals=(Principal("other", "agent", tokens=(existing,)),))
    out = migrate_v1("\ufeff" + json.dumps({"keys": [{"id": "a", "key": K1}]}), into, MIN, NOW, "human-device")
    assert [p.name for p in out.principals] == ["other", "a"]


def test_editor_import_v1_saves_and_reports_names(tmp_path) -> None:
    path = tmp_path / "policy.json"
    with edit_policy(path, now=NOW, create=True) as editor:
        assert editor.import_v1(v1_text(), MIN, "human-device") == ("billing", "deploy", "root")
    policy = load_policy(path)
    assert policy.revision == 1 and not policy.principal("root").admin  # type: ignore[union-attr]
    with pytest.raises(PolicyError, match="already exists"), edit_policy(path, now=NOW) as editor:
        editor.import_v1(v1_text(), MIN, "human-device")
