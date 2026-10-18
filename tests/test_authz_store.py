"""The policy file: strict parsing, round trips, atomic saves, locked editing and lockout protection."""

import copy
import hashlib
import json
import os
import re
import stat
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from mattstash.authz import (
    Grant,
    Policy,
    PolicyError,
    Principal,
    Token,
    admin_expiry_warning,
    dump_policy,
    edit_policy,
    empty_policy,
    generate_token,
    has_usable_admin,
    hash_token,
    load_policy,
    parse_duration_or_time,
    parse_policy,
    save_policy,
    validate_name,
    verify_token_hash,
)
from mattstash.authz import store as store_module
from mattstash.authz.store import check_lockout

NOW = datetime(2026, 10, 18, 12, 0, 0, tzinfo=UTC)
HASH = "hmac-sha256:" + "ab" * 16 + ":" + "cd" * 32


def good_document() -> dict[str, Any]:
    return {
        "version": 2,
        "revision": 3,
        "principals": [
            {
                "name": "matt-mac",
                "kind": "human-device",
                "description": "Matt's laptop",
                "admin": True,
                "created": "2026-10-18T12:00:00Z",
                "tokens": [
                    {
                        "id": "k7m2q7xw4h3a",
                        "hash": HASH,
                        "created": "2026-10-18T12:00:00Z",
                        "expires": "2027-01-01T00:00:00Z",
                    }
                ],
            },
            {"name": "hermes", "kind": "agent", "tokens": []},
        ],
        "grants": [
            {"id": "g_3fd9a1c2", "principal": "hermes", "key": "firefly.*", "actions": ["list", "read"]},
            {
                "id": "g_3fd9a1c3",
                "principal": "hermes",
                "tag": "ops",
                "actions": ["read"],
                "expires": "2027-01-01T00:00:00Z",
            },
        ],
    }


def text_of(document: dict[str, Any]) -> str:
    return json.dumps(document)


def expect_error(document: dict[str, Any], match: str) -> None:
    with pytest.raises(PolicyError, match=match):
        parse_policy(text_of(document))


# -- parsing ---------------------------------------------------------------


def test_parse_good_document() -> None:
    policy = parse_policy(text_of(good_document()))
    assert policy.version == 2 and policy.revision == 3
    admin = policy.principal("MATT-MAC")  # case-insensitive lookup
    assert admin is not None and admin.admin and admin.tokens[0].expires == datetime(2027, 1, 1, tzinfo=UTC)
    assert policy.principal("nobody") is None
    assert [g.id for g in policy.grants_for("hermes")] == ["g_3fd9a1c2", "g_3fd9a1c3"]
    assert policy.grants[1].tag == "ops" and policy.grants[1].key is None


def test_round_trip_is_exact_and_stable() -> None:
    policy = parse_policy(text_of(good_document()))
    dumped = dump_policy(policy)
    assert dumped.endswith("\n") and "\n  " in dumped
    assert parse_policy(dumped) == policy
    assert dump_policy(parse_policy(dumped)) == dumped


def test_round_trip_keeps_microseconds_and_other_offsets() -> None:
    created = datetime(2026, 1, 2, 3, 4, 5, 678901, tzinfo=UTC)
    zone = timezone(timedelta(hours=2))
    policy = Policy(
        principals=(
            Principal("p", "agent", "d", False, True, created, (Token("aaaaaaaaaaaa", HASH, created, created, "t"),)),
        ),
        grants=(
            Grant(
                "g_00000001",
                "p",
                None,
                "t",
                frozenset({"read", "list"}),
                datetime(2030, 1, 1, tzinfo=zone),
                "x",
                created,
            ),
        ),
    )
    dumped = dump_policy(policy)
    assert "2026-01-02T03:04:05.678901Z" in dumped and "2029-12-31T22:00:00Z" in dumped
    assert parse_policy(dumped) == policy


def test_missing_revision_defaults_to_zero() -> None:
    document = good_document()
    del document["revision"]
    assert parse_policy(text_of(document)).revision == 0


def test_dump_orders_actions_and_omits_empty_optionals() -> None:
    policy = parse_policy(
        text_of(
            {
                "version": 2,
                "principals": [{"name": "a", "kind": "agent"}],
                "grants": [
                    {"id": "g_00000001", "principal": "a", "key": "k", "actions": ["delete", "write", "read", "list"]}
                ],
            }
        )
    )
    document = json.loads(dump_policy(policy))
    assert document["grants"][0]["actions"] == ["list", "read", "write", "delete"]
    assert "description" not in document["principals"][0] and "created" not in document["principals"][0]


def test_invalid_json_and_shapes() -> None:
    for text in ["", "{", "[]", "null", '"x"', "[" * 100000]:
        with pytest.raises(PolicyError):
            parse_policy(text)


def test_duplicate_json_keys_are_rejected_at_any_depth() -> None:
    with pytest.raises(PolicyError, match="duplicate field 'version'"):
        parse_policy('{"version": 2, "version": 2, "principals": [], "grants": []}')
    with pytest.raises(PolicyError, match="duplicate field 'kind'"):
        parse_policy('{"version": 2, "principals": [{"name": "a", "kind": "agent", "kind": "runner"}], "grants": []}')


def test_unknown_field_at_each_level() -> None:
    for path in [(), ("principals", 0), ("principals", 0, "tokens", 0), ("grants", 0)]:
        document = good_document()
        node: Any = document
        for step in path:
            node = node[step]
        node["bind"] = {"tailscale": "x"}
        expect_error(document, "unknown field")


def test_missing_required_fields() -> None:
    for path, field in [
        ((), "grants"),
        (("principals", 0), "kind"),
        (("principals", 0, "tokens", 0), "hash"),
        (("grants", 0), "actions"),
    ]:
        document = good_document()
        node: Any = document
        for step in path:
            node = node[step]
        del node[field]
        expect_error(document, "missing field")


@pytest.mark.parametrize("version", [1, 3, 2.0, "2", True, None])
def test_version_must_be_2(version: object) -> None:
    document = good_document()
    document["version"] = version
    with pytest.raises(PolicyError):
        parse_policy(text_of(document))


@pytest.mark.parametrize("revision", [-1, 1.5, "1", True])
def test_revision_must_be_a_non_negative_integer(revision: object) -> None:
    document = good_document()
    document["revision"] = revision
    with pytest.raises(PolicyError):
        parse_policy(text_of(document))


@pytest.mark.parametrize("stamp", ["2026-10-18T12:00:00", "2026-10-18", "not a date", 5, ["x"]])
def test_naive_or_garbage_datetimes_are_rejected(stamp: object) -> None:
    for path in [("principals", 0, "created"), ("principals", 0, "tokens", 0, "expires"), ("grants", 0, "expires")]:
        document = good_document()
        node: Any = document
        for step in path[:-1]:
            node = node[step]
        node[path[-1]] = stamp
        with pytest.raises(PolicyError):
            parse_policy(text_of(document))


def test_offset_datetimes_are_accepted_and_normalised() -> None:
    document = good_document()
    document["principals"][0]["created"] = "2026-10-18T14:00:00+02:00"
    assert parse_policy(text_of(document)).principals[0].created == NOW


def test_a_name_starting_with_legacy_is_an_ordinary_name(policy_path: Path) -> None:
    bootstrap(policy_path)
    with edit_policy(policy_path, now=NOW) as editor:
        editor.add_principal("legacy-x", "agent")
        editor.add_principal("LEGACY-env", "agent")
    assert load_policy(policy_path).principal("legacy-x") is not None


@pytest.mark.parametrize("name", ["", "-a", ".a", "_a", "a b", "a/b", "a" * 65, "café", "a\n"])
def test_bad_principal_names(name: str) -> None:
    document = good_document()
    document["principals"][1]["name"] = name
    document["grants"] = []
    with pytest.raises(PolicyError):
        parse_policy(text_of(document))
    with pytest.raises(PolicyError):
        validate_name(name)


def test_name_edge_cases_that_are_fine() -> None:
    for name in ["a", "A1", "a" * 64, "matt.mac_2-x", "legacy", "legacyx"]:
        validate_name(name)


def test_names_are_unique_without_regard_to_case() -> None:
    document = good_document()
    document["principals"][1]["name"] = "MATT-mac"
    document["grants"] = []
    expect_error(document, "duplicate principal name")


def test_kind_must_be_known_and_legacy_is_not_allowed_in_files() -> None:
    for kind in ["legacy", "robot", "", "Agent"]:
        document = good_document()
        document["principals"][1]["kind"] = kind
        expect_error(document, "kind must be one of")


def test_only_human_devices_may_be_admins() -> None:
    for kind in ["agent", "runner"]:
        document = good_document()
        document["principals"][1].update(kind=kind, admin=True)
        expect_error(document, "only human-device principals may be admins")


def test_token_validation() -> None:
    document = good_document()
    document["principals"][0]["tokens"][0]["id"] = "K7M2Q9XW4H3A"
    expect_error(document, "token id")

    document = good_document()
    document["principals"][0]["tokens"][0]["hash"] = "sha256:short"
    with pytest.raises(PolicyError, match="malformed") as info:
        parse_policy(text_of(document))
    assert "short" not in str(info.value)

    document = good_document()
    document["principals"][1]["tokens"] = [copy.deepcopy(document["principals"][0]["tokens"][0])]
    expect_error(document, "duplicate token id")  # unique across the file, not just per principal


def test_grant_validation() -> None:
    def broken(**changes: Any) -> dict[str, Any]:
        document = good_document()
        document["grants"][0].update(changes)
        return document

    expect_error(broken(id="g_XYZ"), "grant id")
    expect_error(broken(id="g_3fd9a1c3"), "duplicate grant id")
    expect_error(broken(principal="ghost"), "unknown principal")
    expect_error(broken(principal="HERMES"), "unknown principal")  # grants name the exact principal
    expect_error(broken(tag="ops"), "exactly one of")
    document = broken()
    del document["grants"][0]["key"]
    expect_error(document, "exactly one of")
    expect_error(broken(key="firefly/"), "did you mean")
    expect_error(broken(key="a*b"), "'\\*' may appear only once")
    expect_error(broken(actions=[]), "at least one action")
    expect_error(broken(actions=["read", "read"]), "duplicate action")
    expect_error(broken(actions=["read", "admin"]), "unknown actions")
    expect_error(broken(actions="read"), "must be a list")
    expect_error(broken(actions=[1]), "must be a string")
    expect_error(broken(description="a\nb"), "description")
    expect_error(broken(description="x" * 501), "description")


def test_star_grants_are_only_for_human_devices() -> None:
    def with_star(kind: str, key: str = "*") -> dict[str, Any]:
        document = good_document()
        document["principals"][1]["kind"] = kind
        document["grants"][0]["key"] = key
        return document

    expect_error(with_star("agent"), "only for human-device principals, not agents")
    expect_error(with_star("runner"), "only for human-device principals, not runners")
    parse_policy(text_of(with_star("human-device")))
    for kind in ("agent", "runner", "human-device"):
        parse_policy(text_of(with_star(kind, "a*")))  # a raw prefix is still fine for everyone


def test_the_editor_refuses_a_star_grant_for_an_agent_or_runner(policy_path: Path) -> None:
    bootstrap(policy_path)
    before = policy_path.read_bytes()
    with edit_policy(policy_path, now=NOW) as editor:
        editor.add_principal("bot", "agent")
        editor.add_principal("ansible", "runner")
        editor.add_principal("mac-2", "human-device")
        for name in ("bot", "ansible"):
            with pytest.raises(PolicyError, match="only for human-device"):
                editor.add_grant(name, key="*")
        editor.add_grant("bot", key="svc*")
        editor.add_grant("mac-2", key="*", actions=["list", "read", "write", "delete"])
    assert policy_path.read_bytes() != before
    assert {(g.principal, g.key) for g in load_policy(policy_path).grants} == {("bot", "svc*"), ("mac-2", "*")}


def test_tag_grants_cannot_write_or_delete() -> None:
    for actions in (["write"], ["list", "delete"]):
        document = good_document()
        document["grants"][1]["actions"] = actions
        expect_error(document, "tag grants may only allow")
    document = good_document()
    document["grants"][1]["tag"] = "a;b"
    expect_error(document, "tag")


def test_field_type_errors() -> None:
    for path, value in [
        (("principals", 0, "name"), 5),
        (("principals", 0, "admin"), "yes"),
        (("principals", 0, "disabled"), 1),
        (("principals", 0, "tokens"), {}),
        (("principals", 0, "description"), None),
        (("principals", 0, "tokens", 0, "id"), 7),
        (("grants", 0, "key"), 7),
        (("grants", 0, "principal"), None),
        (("principals",), {}),
        (("principals", 0), []),
        (("grants", 0), "x"),
    ]:
        document = good_document()
        node: Any = document
        for step in path[:-1]:
            node = node[step]
        node[path[-1]] = value
        with pytest.raises(PolicyError):
            parse_policy(text_of(document))


def test_error_messages_never_contain_hashes() -> None:
    document = good_document()
    document["principals"][0]["tokens"][0]["bogus"] = 1
    with pytest.raises(PolicyError) as info:
        parse_policy(text_of(document))
    assert "abab" not in str(info.value)


def test_validate_policy_rejects_hand_built_nonsense() -> None:
    with pytest.raises(PolicyError, match="revision"):
        store_module.validate_policy(Policy(revision=-1))
    with pytest.raises(PolicyError, match="timezone-aware"):
        store_module.validate_policy(Policy(principals=(Principal("a", "agent", created=datetime(2026, 1, 1)),)))
    with pytest.raises(PolicyError, match="timezone-aware"):
        store_module.validate_policy(
            Policy(principals=(Principal("a", "agent", tokens=(Token("aaaaaaaaaaaa", HASH, datetime(2026, 1, 1)),)),))
        )
    with pytest.raises(PolicyError, match="timezone-aware"):
        store_module.validate_policy(
            Policy(
                principals=(Principal("a", "agent", tokens=(Token("aaaaaaaaaaaa", HASH, NOW, datetime(2026, 1, 1)),)),)
            )
        )
    base = Principal("a", "agent")
    naive = datetime(2026, 1, 1)
    for grant in (
        Grant("g_00000001", "a", "k", None, frozenset({"read"}), naive),
        Grant("g_00000001", "a", "k", None, frozenset({"read"}), None, "", naive),
    ):
        with pytest.raises(PolicyError, match="timezone-aware"):
            store_module.validate_policy(Policy(principals=(base,), grants=(grant,)))


# -- files -----------------------------------------------------------------


def test_save_and_load(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    policy = parse_policy(text_of(good_document()))
    save_policy(path, policy)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert load_policy(path) == policy
    assert [p.name for p in tmp_path.iterdir()] == ["policy.json"]  # no temp file left behind


def test_save_replaces_atomically_and_keeps_old_file_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "policy.json"
    save_policy(path, empty_policy())
    before = path.read_text()

    def explode(*_: object) -> None:
        raise OSError("disk on fire")

    monkeypatch.setattr(os, "fsync", explode)
    with pytest.raises(OSError, match="disk on fire"):
        save_policy(path, parse_policy(text_of(good_document())))
    monkeypatch.undo()
    assert path.read_text() == before
    assert [p.name for p in tmp_path.iterdir()] == ["policy.json"]


def test_save_refuses_an_invalid_policy(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    with pytest.raises(PolicyError):
        save_policy(path, Policy(version=7))
    assert not path.exists()


def test_save_tolerates_a_failing_directory_sync(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real_open = os.open

    def fake_open(file: Any, flags: int, *rest: Any) -> int:
        if flags == os.O_RDONLY and Path(file) == tmp_path:
            raise PermissionError("no directory handles here")
        return real_open(file, flags, *rest)

    monkeypatch.setattr(os, "open", fake_open)
    save_policy(tmp_path / "policy.json", empty_policy())
    assert (tmp_path / "policy.json").exists()


def test_load_tolerates_bom_and_reports_missing_and_bad_files(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_bytes(b"\xef\xbb\xbf" + dump_policy(empty_policy()).encode())
    assert load_policy(path) == empty_policy()
    with pytest.raises(FileNotFoundError):
        load_policy(tmp_path / "missing.json")
    path.write_bytes(b"\xff\xfe\x00")
    with pytest.raises(PolicyError, match="UTF-8"):
        load_policy(path)


# -- editing ---------------------------------------------------------------


@pytest.fixture
def policy_path(tmp_path: Path) -> Path:
    return tmp_path / "policy.json"


def bootstrap(path: Path) -> str:
    """An admin with one token; returns the token plaintext."""
    with edit_policy(path, now=NOW, create=True) as editor:
        editor.add_principal("matt-mac", "human-device", "laptop", admin=True)
    with edit_policy(path, now=NOW) as editor:
        _, plaintext = editor.issue_token("matt-mac", description="first")
    return plaintext


def test_edit_requires_the_file_unless_create(policy_path: Path) -> None:
    with pytest.raises(FileNotFoundError), edit_policy(policy_path):
        pass  # pragma: no cover
    assert not policy_path.exists()
    with edit_policy(policy_path, create=True):
        pass
    assert load_policy(policy_path).revision == 1


def test_create_makes_missing_parent_directories(tmp_path: Path) -> None:
    path = tmp_path / "a" / "b" / "policy.json"
    with edit_policy(path, create=True) as editor:
        editor.add_principal("x", "runner")
    assert load_policy(path).principal("x") is not None


def test_bootstrap_then_revision_bumps(policy_path: Path) -> None:
    plaintext = bootstrap(policy_path)
    policy = load_policy(policy_path)
    assert policy.revision == 2
    token = policy.principals[0].tokens[0]
    assert verify_token_hash(token.hash, plaintext) and plaintext not in policy_path.read_text()
    assert token.created == NOW and policy.principals[0].created == NOW
    assert stat.S_IMODE(policy_path.stat().st_mode) == 0o600
    assert (policy_path.parent / "policy.json.lock").exists()


def test_exception_in_the_body_saves_nothing(policy_path: Path) -> None:
    bootstrap(policy_path)
    before = policy_path.read_bytes()
    with pytest.raises(RuntimeError), edit_policy(policy_path, now=NOW) as editor:
        editor.add_principal("agent-1", "agent")
        raise RuntimeError("abort")
    assert policy_path.read_bytes() == before


def test_a_failed_validation_saves_nothing(policy_path: Path) -> None:
    bootstrap(policy_path)
    before = policy_path.read_bytes()
    with pytest.raises(PolicyError), edit_policy(policy_path, now=NOW) as editor:
        editor.add_principal("a1", "agent")
        editor.add_principal("A1", "agent")
    assert policy_path.read_bytes() == before


def test_editing_a_corrupt_file_is_refused(policy_path: Path) -> None:
    policy_path.write_text("{ nope")
    with pytest.raises(PolicyError), edit_policy(policy_path, create=True):
        pass  # pragma: no cover
    assert policy_path.read_text() == "{ nope"


def test_principal_management(policy_path: Path) -> None:
    bootstrap(policy_path)
    with edit_policy(policy_path, now=NOW) as editor:
        agent = editor.add_principal("hermes", "agent", "an agent")
        assert agent.created == NOW and agent.kind == "agent"
        editor.set_description("HERMES", "renamed description")
        editor.set_disabled("hermes", True)
        grant = editor.add_grant("Hermes", key="firefly.*")
        assert grant.principal == "hermes"  # the canonical spelling
        editor.add_grant("hermes", tag="ops", actions=["read"])
        assert re_match_grant_id(grant.id)
    policy = load_policy(policy_path)
    hermes = policy.principal("hermes")
    assert hermes is not None and hermes.disabled and hermes.description == "renamed description"
    with edit_policy(policy_path, now=NOW) as editor:
        editor.set_disabled("hermes", False)
        assert editor.remove_principal("hermes") == 2
    policy = load_policy(policy_path)
    assert policy.principal("hermes") is None and policy.grants == ()


def re_match_grant_id(value: str) -> bool:
    import re

    return re.fullmatch(r"g_[0-9a-f]{8}", value) is not None


def test_editor_errors(policy_path: Path) -> None:
    bootstrap(policy_path)
    with edit_policy(policy_path, now=NOW) as editor:
        for call in (
            lambda: editor.add_principal("matt-mac", "agent"),
            lambda: editor.add_principal("MATT-MAC", "agent"),
            lambda: editor.add_principal("bad name", "agent"),
            lambda: editor.add_principal("x", "robot"),
            lambda: editor.add_principal("x", "agent", admin=True),
            lambda: editor.remove_principal("ghost"),
            lambda: editor.set_disabled("ghost", True),
            lambda: editor.set_admin("ghost", True),
            lambda: editor.set_description("ghost", "x"),
            lambda: editor.issue_token("ghost"),
            lambda: editor.revoke_token("ghost", "aaaaaaaaaaaa"),
            lambda: editor.revoke_token("matt-mac", "aaaaaaaaaaaa"),
            lambda: editor.rotate_token("matt-mac", "aaaaaaaaaaaa"),
            lambda: editor.rotate_token("matt-mac", editor.policy.principals[0].tokens[0].id, timedelta(seconds=-1)),
            lambda: editor.add_grant("ghost", key="a"),
            lambda: editor.add_grant("matt-mac"),
            lambda: editor.add_grant("matt-mac", key="a", tag="b"),
            lambda: editor.add_grant("matt-mac", key="a/"),
            lambda: editor.add_grant("matt-mac", tag="t", actions=["write"]),
            lambda: editor.add_grant("matt-mac", key="a", actions=[]),
            lambda: editor.add_grant("matt-mac", key="a", expires=datetime(2030, 1, 1)),
            lambda: editor.issue_token("matt-mac", expires=datetime(2030, 1, 1)),
            lambda: editor.set_description("matt-mac", "bad\nline"),
            lambda: editor.remove_grant("g_00000000"),
        ):
            with pytest.raises(PolicyError):
                call()
        # failed attempts leave the editor's document unchanged
        assert [p.name for p in editor.policy.principals] == ["matt-mac"] and editor.policy.grants == ()


def test_set_admin_is_limited_to_human_devices(policy_path: Path) -> None:
    bootstrap(policy_path)
    with edit_policy(policy_path, now=NOW) as editor:
        editor.add_principal("runner-1", "runner")
        with pytest.raises(PolicyError, match="human-device"):
            editor.set_admin("runner-1", True)
        editor.add_principal("mac-2", "human-device")
        editor.set_admin("mac-2", True)
    assert load_policy(policy_path).principal("mac-2").admin  # type: ignore[union-attr]


def test_remove_grant(policy_path: Path) -> None:
    bootstrap(policy_path)
    with edit_policy(policy_path, now=NOW) as editor:
        grant = editor.add_grant("matt-mac", key="x")
        keep = editor.add_grant("matt-mac", key="y")
        editor.remove_grant(grant.id)
    assert [g.id for g in load_policy(policy_path).grants] == [keep.id]


def test_token_id_collision_is_retried(policy_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bootstrap(policy_path)
    existing = load_policy(policy_path).principals[0].tokens[0].id
    real = store_module.generate_token
    calls = iter([existing])

    def colliding() -> tuple[str, str]:
        first = next(calls, None)
        if first is not None:
            return first, "mst_" + first + "_x"
        return real()

    monkeypatch.setattr(store_module, "generate_token", colliding)
    with edit_policy(policy_path, now=NOW) as editor:
        token, _ = editor.issue_token("matt-mac")
    assert token.id != existing


def test_issue_with_expiry_and_description(policy_path: Path) -> None:
    bootstrap(policy_path)
    expires = NOW + timedelta(days=90)
    with edit_policy(policy_path, now=NOW) as editor:
        token, plaintext = editor.issue_token("matt-mac", expires=expires, description="ci")
    assert token.expires == expires and token.description == "ci"
    stored = next(t for t in load_policy(policy_path).principals[0].tokens if t.id == token.id)
    assert verify_token_hash(stored.hash, plaintext) and stored.expires == expires


def test_revoke_token(policy_path: Path) -> None:
    bootstrap(policy_path)
    with edit_policy(policy_path, now=NOW) as editor:
        second, _ = editor.issue_token("matt-mac")
        first = editor.policy.principals[0].tokens[0]
        editor.revoke_token("matt-mac", first.id)
    assert [t.id for t in load_policy(policy_path).principals[0].tokens] == [second.id]


def test_rotate_without_grace_removes_the_old_token(policy_path: Path) -> None:
    bootstrap(policy_path)
    old = load_policy(policy_path).principals[0].tokens[0]
    with edit_policy(policy_path, now=NOW) as editor:
        new, plaintext = editor.rotate_token("matt-mac", old.id, description="rotated")
    tokens = load_policy(policy_path).principals[0].tokens
    assert [t.id for t in tokens] == [new.id] and tokens[0].description == "rotated"
    assert verify_token_hash(tokens[0].hash, plaintext)


def test_rotate_with_grace_expires_the_old_token_later(policy_path: Path) -> None:
    bootstrap(policy_path)
    old = load_policy(policy_path).principals[0].tokens[0]
    new_expiry = NOW + timedelta(days=30)
    with edit_policy(policy_path, now=NOW) as editor:
        new, _ = editor.rotate_token("matt-mac", old.id, grace=timedelta(hours=24), expires=new_expiry)
    tokens = {t.id: t for t in load_policy(policy_path).principals[0].tokens}
    assert tokens[old.id].expires == NOW + timedelta(hours=24)
    assert tokens[new.id].expires == new_expiry
    assert tokens[old.id].is_expired(NOW + timedelta(hours=24)) and not tokens[old.id].is_expired(NOW)


def test_rotation_grace_never_extends_an_earlier_expiry(policy_path: Path) -> None:
    bootstrap(policy_path)
    soon = NOW + timedelta(hours=1)
    with edit_policy(policy_path, now=NOW) as editor:
        short, _ = editor.issue_token("matt-mac", expires=soon)
        editor.rotate_token("matt-mac", short.id, grace=timedelta(days=7))
    tokens = {t.id: t for t in load_policy(policy_path).principals[0].tokens}
    assert tokens[short.id].expires == soon


# -- lockout ---------------------------------------------------------------


def test_bootstrap_is_allowed_without_a_usable_admin(policy_path: Path) -> None:
    # step 1 leaves an admin with no token, which would fail the check if it applied to an empty "before"
    with edit_policy(policy_path, now=NOW, create=True) as editor:
        editor.add_principal("matt-mac", "human-device", admin=True)
    assert not has_usable_admin(load_policy(policy_path), NOW)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda e, tid: e.revoke_token("matt-mac", tid),
        lambda e, tid: e.set_disabled("matt-mac", True),
        lambda e, tid: e.remove_principal("matt-mac"),
        lambda e, tid: e.set_admin("matt-mac", False),
    ],
)
def test_lockout_is_refused(policy_path: Path, mutate: Any) -> None:
    bootstrap(policy_path)
    before = policy_path.read_bytes()
    token_id = load_policy(policy_path).principals[0].tokens[0].id
    with pytest.raises(PolicyError, match="would leave no admin"), edit_policy(policy_path, now=NOW) as editor:
        mutate(editor, token_id)
    assert policy_path.read_bytes() == before


def test_lockout_is_allowed_when_another_admin_remains(policy_path: Path) -> None:
    bootstrap(policy_path)
    with edit_policy(policy_path, now=NOW) as editor:
        editor.add_principal("mac-2", "human-device", admin=True)
        editor.issue_token("mac-2")
    with edit_policy(policy_path, now=NOW) as editor:
        editor.set_disabled("matt-mac", True)
        editor.remove_principal("matt-mac")
    assert [p.name for p in load_policy(policy_path).principals] == ["mac-2"]


def test_an_expired_only_token_does_not_count_as_a_usable_admin() -> None:
    expired = Token("aaaaaaaaaaaa", HASH, NOW - timedelta(days=9), NOW)
    policy = Policy(principals=(Principal("m", "human-device", admin=True, tokens=(expired,)),))
    assert not has_usable_admin(policy, NOW)
    assert has_usable_admin(policy, NOW - timedelta(seconds=1))
    with pytest.raises(PolicyError, match="would leave no admin"):
        check_lockout(policy, NOW)
    check_lockout(policy, NOW - timedelta(seconds=1))


def test_agents_never_count_as_admins() -> None:
    token = Token("aaaaaaaaaaaa", HASH, NOW)
    policy = Policy(principals=(Principal("a", "agent", admin=True, tokens=(token,)),))
    assert not has_usable_admin(policy, NOW)


def test_concurrent_edits_do_not_lose_updates(policy_path: Path) -> None:
    import threading

    bootstrap(policy_path)
    errors: list[BaseException] = []

    def worker(index: int) -> None:
        try:
            with edit_policy(policy_path, now=NOW) as editor:
                editor.add_principal(f"agent-{index}", "agent")
        except BaseException as exc:  # pragma: no cover - only on failure
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors
    policy = load_policy(policy_path)
    assert len(policy.principals) == 7 and policy.revision == 8


def test_hash_helper_used_by_the_editor_is_salted() -> None:
    assert hash_token("x") != hash_token("x")


# -- durations -------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "delta"),
    [
        ("90d", timedelta(days=90)),
        ("24h", timedelta(hours=24)),
        ("30m", timedelta(minutes=30)),
        ("2w", timedelta(weeks=2)),
        (" 5d ", timedelta(days=5)),
        ("0d", timedelta(0)),
    ],
)
def test_relative_durations(text: str, delta: timedelta) -> None:
    assert parse_duration_or_time(text, NOW) == NOW + delta


def test_absolute_times() -> None:
    assert parse_duration_or_time("2027-01-01", NOW) == datetime(2027, 1, 1, tzinfo=UTC)
    assert parse_duration_or_time("2027-01-01T10:30:00", NOW) == datetime(2027, 1, 1, 10, 30, tzinfo=UTC)
    assert parse_duration_or_time("2027-01-01T10:30:00Z", NOW) == datetime(2027, 1, 1, 10, 30, tzinfo=UTC)
    assert parse_duration_or_time("2027-01-01T12:00:00+02:00", NOW) == datetime(2027, 1, 1, 10, tzinfo=UTC)


@pytest.mark.parametrize("text", ["", "soon", "90", "d", "-5d", "5x", "1.5d", "2027-13-01", "9999999999d", "1d2h"])
def test_garbage_durations(text: str) -> None:
    with pytest.raises(PolicyError, match="cannot read"):
        parse_duration_or_time(text, NOW)


def test_stat_and_mode_of_temp_files_are_private(policy_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    modes: list[int] = []
    real_open = os.open

    def spy(file: Any, flags: int, mode: int = 0o777, **kw: Any) -> int:
        if flags & os.O_EXCL:
            modes.append(mode)
        return real_open(file, flags, mode, **kw)

    monkeypatch.setattr(os, "open", spy)
    save_policy(policy_path, empty_policy())
    assert modes == [0o600]


def test_edit_policy_locks_the_real_path_not_the_symlink(tmp_path: Path):
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    real = real_dir / "policy.json"
    with edit_policy(real, now=NOW, create=True) as editor:
        editor.add_principal("matt", "human-device", "", admin=True)
    link = tmp_path / "link.json"
    link.symlink_to(real)

    seen: list[str] = []
    original = store_module.FileLock

    def spy(path: str, *args: Any, **kwargs: Any) -> Any:
        seen.append(path)
        return original(path, *args, **kwargs)

    store_module.FileLock = spy  # type: ignore[misc,assignment]
    try:
        with edit_policy(link, now=NOW) as editor:
            editor.add_principal("bot", "agent", "")
        with edit_policy(real, now=NOW) as editor:
            editor.add_principal("bot2", "agent", "")
    finally:
        store_module.FileLock = original  # type: ignore[misc]

    assert seen == [str(real.resolve()) + ".lock"] * 2  # both routes take the same lock
    assert not (tmp_path / "link.json.lock").exists()  # no stray lock next to the link
    assert link.is_symlink() and {p.name for p in load_policy(real).principals} == {"matt", "bot", "bot2"}


# -- import_token ----------------------------------------------------------

OLD_KEY = "old-client-key-" + "x" * 30


def test_import_token_stores_the_digest_under_a_fresh_id_and_the_key_still_matches(policy_path: Path) -> None:

    bootstrap(policy_path)
    with edit_policy(policy_path, now=NOW) as editor:
        editor.add_principal("bot", "agent")
        token = editor.import_token("bot", OLD_KEY, description="migrated client", expires=NOW + timedelta(days=30))
    stored = load_policy(policy_path).principal("bot").tokens[0]  # type: ignore[union-attr]
    assert stored == token and stored.hash == "sha256:" + hashlib.sha256(OLD_KEY.encode()).hexdigest()
    assert verify_token_hash(stored.hash, OLD_KEY) and not verify_token_hash(stored.hash, OLD_KEY + "x")
    assert (stored.created, stored.expires, stored.description) == (NOW, NOW + timedelta(days=30), "migrated client")
    assert re.fullmatch(r"[a-z2-7]{12}", stored.id)
    assert OLD_KEY not in policy_path.read_text()


def test_import_token_refuses_bad_keys_without_repeating_them(policy_path: Path) -> None:
    bootstrap(policy_path)
    with edit_policy(policy_path, now=NOW) as editor:
        editor.add_principal("bot", "agent")
    before = policy_path.read_bytes()
    _, issued = generate_token()
    cases = [
        ("short-key-123456789012345678901", "shorter than 32"),  # 31 characters
        ("", "empty"),
        (OLD_KEY + "\n", "control or non-ASCII"),
        (" " + OLD_KEY, "control or non-ASCII"),
        (OLD_KEY.replace("x", "é"), "control or non-ASCII"),
        (issued, "starts with 'mst_'"),
        ("mst_x", "starts with 'mst_'"),  # not a well-formed token, still refused (and before the length check)
        ("mst_" + "y" * 40, "starts with 'mst_'"),
    ]
    for key, message in cases:
        with pytest.raises(PolicyError, match=message) as info, edit_policy(policy_path, now=NOW) as editor:
            editor.import_token("bot", key)
        assert key == "" or key not in str(info.value)
    with pytest.raises(PolicyError, match="no such principal"), edit_policy(policy_path, now=NOW) as editor:
        editor.import_token("ghost", OLD_KEY)
    assert policy_path.read_bytes() == before


def test_import_token_min_length_can_be_lowered_but_never_below_16(policy_path: Path) -> None:
    bootstrap(policy_path)
    with edit_policy(policy_path, now=NOW) as editor:
        editor.add_principal("bot", "agent")
    sixteen = "k" * 16
    with edit_policy(policy_path, now=NOW) as editor:
        editor.import_token("bot", sixteen, min_length=16)
        for floor in (15, 8, 0):
            with pytest.raises(PolicyError, match="cannot be below 16"):
                editor.import_token("bot", "k" * 20, min_length=floor)
        with pytest.raises(PolicyError, match="shorter than 17"):
            editor.import_token("bot", "j" * 16, min_length=17)


def test_import_token_refuses_an_admin_and_set_admin_refuses_a_principal_with_an_imported_key(
    policy_path: Path,
) -> None:
    bootstrap(policy_path)
    before = policy_path.read_bytes()
    with pytest.raises(PolicyError, match="admins use issued mst_ tokens only") as info:
        with edit_policy(policy_path, now=NOW) as editor:
            editor.import_token("matt-mac", OLD_KEY)
    assert OLD_KEY not in str(info.value) and policy_path.read_bytes() == before
    with edit_policy(policy_path, now=NOW) as editor:
        editor.add_principal("laptop", "human-device")
        token = editor.import_token("laptop", OLD_KEY)
    with pytest.raises(PolicyError, match="imported plain key"), edit_policy(policy_path, now=NOW) as editor:
        editor.set_admin("laptop", True)
    with edit_policy(
        policy_path, now=NOW
    ) as editor:  # an EXPIRED or unrelated token changes nothing: revoke, then issue
        editor.revoke_token("laptop", token.id)
        editor.issue_token("laptop")
        editor.set_admin("laptop", True)
        editor.set_admin("laptop", False)  # dropping the flag is always fine
    assert load_policy(policy_path).principal("laptop").admin is False  # type: ignore[union-attr]


def test_rotating_an_imported_key_replaces_the_sha256_token_with_a_salted_one(policy_path: Path) -> None:
    bootstrap(policy_path)
    with edit_policy(policy_path, now=NOW) as editor:
        editor.add_principal("bot", "agent")
        imported = editor.import_token("bot", OLD_KEY)
    with edit_policy(policy_path, now=NOW) as editor:
        new, plaintext = editor.rotate_token("bot", imported.id)
    tokens = load_policy(policy_path).principal("bot").tokens  # type: ignore[union-attr]
    assert [t.id for t in tokens] == [new.id] and plaintext.startswith("mst_")
    assert tokens[0].hash.startswith("hmac-sha256:") and verify_token_hash(tokens[0].hash, plaintext)
    assert (
        OLD_KEY not in policy_path.read_text()
        and hashlib.sha256(OLD_KEY.encode()).hexdigest() not in policy_path.read_text()
    )


def test_import_token_refuses_a_duplicate_key_and_a_past_expiry(policy_path: Path) -> None:
    bootstrap(policy_path)
    with edit_policy(policy_path, now=NOW) as editor:
        editor.add_principal("bot", "agent")
        editor.add_principal("bot2", "agent")
        editor.import_token("bot", OLD_KEY)
        with pytest.raises(PolicyError, match="already held by a token") as info:
            editor.import_token("bot2", OLD_KEY)  # not even by another principal
        assert OLD_KEY not in str(info.value)
        with pytest.raises(PolicyError, match="already held"):
            editor.import_token("bot", OLD_KEY)
        with pytest.raises(PolicyError, match="must be in the future"):
            editor.import_token("bot2", "z" * 40, expires=NOW)
    assert load_policy(policy_path).principal("bot2").tokens == ()  # type: ignore[union-attr]


# -- admin_expiry_warning ----------------------------------------------------


def _admin(*tokens: Token, name: str = "matt-mac", **changes: Any) -> Principal:
    return Principal(
        name, changes.pop("kind", "human-device"), admin=changes.pop("admin", True), tokens=tokens, **changes
    )


def _token(expires: datetime | None, suffix: str = "a") -> Token:
    return Token("aaaaaaaaaaa" + suffix, HASH, NOW - timedelta(days=100), expires)


def test_warning_when_every_valid_admin_token_expires_within_the_horizon() -> None:
    soon = NOW + timedelta(days=10)
    policy = Policy(principals=(_admin(_token(NOW + timedelta(days=3)), _token(soon, "b")),))
    text = admin_expiry_warning(policy, NOW)
    assert text is not None and "within 14 days" in text and "2026-10-28T12:00:00Z" in text
    assert "token issue" in text and HASH not in text and "aaaaaaaaaaa" not in text  # no token ids, no secrets
    assert "within 20 days" in (admin_expiry_warning(policy, NOW, timedelta(days=20)) or "")
    assert admin_expiry_warning(policy, NOW, timedelta(days=2)) is None  # not within 2 days
    assert admin_expiry_warning(policy, NOW, timedelta(days=10)) is not None  # the boundary counts as within


def test_no_warning_when_one_admin_token_lasts_or_never_expires() -> None:
    soon = _token(NOW + timedelta(days=2))
    for lasting in (_token(None, "b"), _token(NOW + timedelta(days=15), "b")):
        assert admin_expiry_warning(Policy(principals=(_admin(soon, lasting),)), NOW) is None
    other = _admin(_token(NOW + timedelta(days=400), "c"), name="mac-2")
    assert admin_expiry_warning(Policy(principals=(_admin(soon), other)), NOW) is None  # across admins too


def test_an_expired_admin_token_is_ignored_and_only_expired_tokens_get_their_own_warning() -> None:
    expired = _token(NOW - timedelta(days=1))
    assert admin_expiry_warning(Policy(principals=(_admin(expired, _token(None, "b")),)), NOW) is None
    text = admin_expiry_warning(Policy(principals=(_admin(expired),)), NOW)
    assert text is not None and "no admin has a valid token" in text and "--policy-file" in text
    assert admin_expiry_warning(Policy(principals=(_admin(),)), NOW) is None  # an admin never given a token: bootstrap


def test_no_warning_without_a_usable_admin_or_for_admins_that_cannot_administer() -> None:
    assert admin_expiry_warning(Policy(), NOW) is None
    soon = _token(NOW + timedelta(days=1))
    for principal in (_admin(soon, disabled=True), _admin(soon, admin=False), _admin(soon, kind="agent", admin=False)):
        assert admin_expiry_warning(Policy(principals=(principal,)), NOW) is None
