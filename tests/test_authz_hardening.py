"""Review round 1 for ``mattstash.authz``: duplicates, expiry and lockout horizon, file permissions, range errors,
reprs, access-log robustness, evaluation defence in depth."""

import json
import os
import random
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from mattstash.authz import (
    Grant,
    Policy,
    PolicyError,
    Principal,
    Token,
    check_lockout_change,
    edit_policy,
    evaluate,
    format_record,
    hash_token,
    is_valid_token_id,
    load_policy,
    migrate_v1,
    parse_duration,
    parse_duration_or_time,
    parse_policy,
    read_records,
    save_policy,
    validate_pattern,
    validate_policy,
    verify_token_hash,
    visible,
)
from mattstash.authz import accesslog as accesslog_module

NOW = datetime(2026, 10, 18, 12, 0, 0, tzinfo=UTC)
DIGEST = "ab" * 32
HMAC = "hmac-sha256:" + "ab" * 16 + ":" + "cd" * 32
HMAC2 = "hmac-sha256:" + "ee" * 16 + ":" + "cd" * 32
KEY = "k-" + "a" * 30


def bootstrap(path: Path) -> None:
    with edit_policy(path, now=NOW, create=True) as editor:
        editor.add_principal("matt-mac", "human-device", "laptop", admin=True)
    with edit_policy(path, now=NOW) as editor:
        editor.issue_token("matt-mac")


# -- M2: one secret, one token ----


def v1(*entries: dict[str, Any]) -> str:
    return json.dumps({"keys": list(entries)})


def test_migrate_refuses_the_same_key_twice_in_the_file() -> None:
    text = v1({"id": "a", "key": KEY, "ops": ["read"]}, {"id": "b", "key": KEY, "ops": ["admin"]})
    with pytest.raises(PolicyError, match="The same API key is configured more than once"):
        migrate_v1(text, Policy(), 16, NOW)


def test_migrate_refuses_a_key_hashed_and_plain_in_the_file() -> None:
    import hashlib

    digest = hashlib.sha256(KEY.encode()).hexdigest()
    text = v1({"id": "a", "key": KEY}, {"id": "b", "key_sha256": digest.upper()})
    with pytest.raises(PolicyError, match="more than once"):
        migrate_v1(text, Policy(), 16, NOW)


def test_migrate_refuses_a_key_already_in_the_policy(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    with edit_policy(path, now=NOW, create=True) as editor:
        editor.import_v1(v1({"id": "a", "key": KEY}), 16, "human-device")
    with pytest.raises(PolicyError, match="more than once"), edit_policy(path, now=NOW) as editor:
        editor.import_v1(v1({"id": "other", "key": KEY}), 16, "human-device")
    assert [p.name for p in load_policy(path).principals] == ["a"]


def token_policy(*hashes: str) -> Policy:
    principals = tuple(
        Principal(f"p{n}", "agent", tokens=(Token("aaaaaaaaaaa" + "abcdefgh"[n], h, NOW),))
        for n, h in enumerate(hashes)
    )
    return Policy(principals=principals)


def test_validate_policy_rejects_one_hash_on_two_tokens_without_echoing_it() -> None:
    for pair in ((f"sha256:{DIGEST}", f"sha256:{DIGEST}"), (HMAC, HMAC)):
        with pytest.raises(PolicyError, match="same token secret") as info:
            validate_policy(token_policy(*pair))
        assert DIGEST not in str(info.value)
    # parse path too
    text = '{"version":2,"principals":[],"grants":[]}'
    assert parse_policy(text).principals == ()


def test_validate_policy_accepts_distinct_salts_and_schemes() -> None:
    validate_policy(token_policy(HMAC, HMAC2, f"sha256:{DIGEST}"))


# -- M3: expiry in the future, lockout horizon ----


@pytest.mark.parametrize("expires", [NOW, NOW - timedelta(days=1)])
def test_new_tokens_must_expire_in_the_future(tmp_path: Path, expires: datetime) -> None:
    path = tmp_path / "policy.json"
    bootstrap(path)
    before = path.read_bytes()
    token_id = load_policy(path).principals[0].tokens[0].id
    for action in (
        lambda e: e.issue_token("matt-mac", expires),
        lambda e: e.rotate_token("matt-mac", token_id, expires=expires),
    ):
        with pytest.raises(PolicyError, match="must be in the future"), edit_policy(path, now=NOW) as editor:
            action(editor)
    assert path.read_bytes() == before


@pytest.mark.parametrize("expires", [NOW, NOW - timedelta(days=1)])
def test_new_grants_must_expire_in_the_future(tmp_path: Path, expires: datetime) -> None:
    path = tmp_path / "policy.json"
    bootstrap(path)
    before = path.read_bytes()
    with pytest.raises(PolicyError, match="grant's expiry must be in the future"):
        with edit_policy(path, now=NOW) as editor:
            editor.add_grant("matt-mac", key="a", expires=expires)
    assert path.read_bytes() == before
    with edit_policy(path, now=NOW) as editor:  # one second ahead is fine
        editor.add_grant("matt-mac", key="a", expires=NOW + timedelta(seconds=1))


def test_naive_expiry_is_a_policy_error(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    bootstrap(path)
    with pytest.raises(PolicyError, match="timezone-aware"), edit_policy(path, now=NOW) as editor:
        editor.issue_token("matt-mac", datetime(2030, 1, 1))


def test_rotate_with_grace_keeps_the_earlier_expiry_of_the_old_token(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    bootstrap(path)
    with edit_policy(path, now=NOW) as editor:
        editor.add_principal("second", "human-device", admin=True)
        short, _ = editor.issue_token("second", expires=NOW + timedelta(minutes=10))
        editor.issue_token("second")
    with edit_policy(path, now=NOW) as editor:
        editor.rotate_token("second", short.id, grace=timedelta(hours=2))
    kept = {t.id: t for t in load_policy(path).principal("second").tokens}  # type: ignore[union-attr]
    assert kept[short.id].expires == NOW + timedelta(minutes=10)
    with edit_policy(path, now=NOW) as editor:
        editor.rotate_token("matt-mac", load_policy(path).principals[0].tokens[0].id, grace=timedelta(hours=2))
    old = load_policy(path).principals[0].tokens[0]
    assert old.expires == NOW + timedelta(hours=2)


def test_rotating_the_sole_admin_token_into_a_short_lived_one_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    bootstrap(path)  # one non-expiring admin token
    before = path.read_bytes()
    token_id = load_policy(path).principals[0].tokens[0].id
    with pytest.raises(PolicyError, match="within the hour"), edit_policy(path, now=NOW) as editor:
        editor.rotate_token("matt-mac", token_id, grace=timedelta(hours=1), expires=NOW + timedelta(minutes=1))
    assert path.read_bytes() == before


def test_issuing_a_short_lived_admin_token_next_to_a_long_one_is_fine(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    bootstrap(path)
    with edit_policy(path, now=NOW) as editor:
        editor.issue_token("matt-mac", expires=NOW + timedelta(minutes=1))


def test_rotating_to_a_token_that_outlasts_the_hour_is_fine(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    bootstrap(path)
    token_id = load_policy(path).principals[0].tokens[0].id
    with edit_policy(path, now=NOW) as editor:
        editor.rotate_token("matt-mac", token_id, grace=timedelta(hours=1), expires=NOW + timedelta(hours=2))


def test_a_policy_already_near_lockout_can_still_be_repaired(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    short = Token("aaaaaaaaaaaa", HMAC, NOW, NOW + timedelta(minutes=5))
    save_policy(path, Policy(principals=(Principal("a", "human-device", admin=True, tokens=(short,)),)))
    with edit_policy(path, now=NOW) as editor:  # nothing outlasts the hour before, so nothing is refused
        editor.issue_token("a")
    with edit_policy(path, now=NOW) as editor:
        editor.revoke_token("a", "aaaaaaaaaaaa")  # and the long token now carries the admin
    assert len(load_policy(path).principals[0].tokens) == 1


def test_horizon_rule_unit() -> None:
    admin = Principal(
        "a", "human-device", admin=True, tokens=(Token("aaaaaaaaaaaa", HMAC, NOW, NOW + timedelta(days=1)),)
    )
    short = Principal(
        "a", "human-device", admin=True, tokens=(Token("aaaaaaaaaaaa", HMAC, NOW, NOW + timedelta(minutes=5)),)
    )
    check_lockout_change(Policy(principals=(admin,)), Policy(principals=(admin,)), NOW)
    with pytest.raises(PolicyError, match="within the hour"):
        check_lockout_change(Policy(principals=(admin,)), Policy(principals=(short,)), NOW)
    # the before-state was already short: not blocked
    check_lockout_change(Policy(principals=(short,)), Policy(principals=(short,)), NOW)


# -- M4: permissions, ownership and symlinks ----


def mode_of(path: Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def touch(path: Path) -> None:
    with edit_policy(path, now=NOW) as editor:
        editor.add_principal("someone", "agent")


@pytest.mark.parametrize(
    ("start", "expected"), [(0o640, 0o640), (0o644, 0o640), (0o600, 0o600), (0o666, 0o640), (0o755, 0o640)]
)
def test_editing_preserves_mode_but_never_looser_than_0640(tmp_path: Path, start: int, expected: int) -> None:
    path = tmp_path / "policy.json"
    bootstrap(path)
    os.chmod(path, start)
    touch(path)
    assert mode_of(path) == expected


def test_a_new_file_is_0600(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    bootstrap(path)
    assert mode_of(path) == 0o600


def test_a_symlinked_policy_stays_a_symlink_and_the_target_is_updated(tmp_path: Path) -> None:
    real = tmp_path / "data" / "real.json"
    real.parent.mkdir()
    bootstrap(real)
    os.chmod(real, 0o640)
    link = tmp_path / "policy.json"
    link.symlink_to(real)
    touch(link)
    assert link.is_symlink()
    assert os.readlink(link) == str(real)
    assert load_policy(real).principal("someone") is not None
    assert mode_of(real) == 0o640
    assert not list(real.parent.glob(".*.tmp"))


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() != 0, reason="needs root to hand a file to another uid")
def test_root_keeps_the_owner_of_the_file(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    bootstrap(path)
    os.chown(path, 12345, 23456)
    touch(path)
    info = os.stat(path)
    assert (info.st_uid, info.st_gid) == (12345, 23456)


# -- L1: out of range values become PolicyError ----


@pytest.mark.parametrize(
    "text", ["999999w", "0001-01-01T00:00:00+05:00", "9999-12-31T23:59:59-05:00", "9999-12-31T23:59:59-23:00"]
)
def test_range_errors_are_policy_errors_in_durations(text: str) -> None:
    with pytest.raises(PolicyError, match="range of supported dates"):
        parse_duration_or_time(text, NOW if text != "999999w" else datetime(9999, 1, 1, tzinfo=UTC))


def test_duration_helper() -> None:
    assert parse_duration("30m") == timedelta(minutes=30)
    assert parse_duration(" 2w ") == timedelta(weeks=2)
    for bad in ("", "10", "1y", "-5d", "2027-01-01", "1234567d"):
        with pytest.raises(PolicyError, match="cannot read"):
            parse_duration(bad)


def policy_doc(**changes: Any) -> str:
    document = {"version": 2, "revision": 0, "principals": [], "grants": []}
    document.update(changes)
    return json.dumps(document)


def test_parse_policy_range_and_size_errors() -> None:
    big = "9" * 4400
    for text in (
        '{"version":2,"revision":' + big + ',"principals":[],"grants":[]}',
        '{"version":' + big + ',"revision":0,"principals":[],"grants":[]}',
    ):
        with pytest.raises(PolicyError, match=r"too large|revision|version"):
            parse_policy(text)
    with pytest.raises(PolicyError, match="revision"):
        parse_policy(policy_doc(revision=2**63))
    with pytest.raises(PolicyError, match="version"):
        parse_policy(policy_doc(version=-1))
    for stamp in ("0001-01-01T00:00:00+05:00", "9999-12-31T23:59:59-05:00"):
        document = {
            "version": 2,
            "principals": [{"name": "a", "kind": "agent", "created": stamp}],
            "grants": [],
        }
        with pytest.raises(PolicyError, match="range of supported dates"):
            parse_policy(json.dumps(document))


def test_v1_json_with_a_huge_number_or_deep_nesting_is_a_policy_error() -> None:
    with pytest.raises(PolicyError, match="too large"):
        migrate_v1('{"keys":[{"id":"a","key":"' + KEY + '","ops":["read"],"x":' + "9" * 4400 + "}]}", Policy(), 16, NOW)
    # Whether deep nesting surfaces as RecursionError or as a decode error depends on the Python version (3.14's
    # decoder reports it as invalid JSON); either way it must be a PolicyError.
    with pytest.raises(PolicyError):
        migrate_v1("[" * 100000, Policy(), 16, NOW)


def _recursion_error(*args: object, **kwargs: object) -> object:
    raise RecursionError


def test_recursion_while_parsing_is_a_policy_error_on_every_python(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(json, "loads", _recursion_error)
    with pytest.raises(PolicyError, match="API keys file is nested too deeply"):
        migrate_v1('{"keys": []}', Policy(), 16, NOW)
    with pytest.raises(PolicyError, match="policy file is nested too deeply"):
        parse_policy('{"version": 2}')


def test_revision_overflow_cannot_happen_through_edit(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_text(policy_doc(revision=2**63 - 1))
    with pytest.raises(PolicyError, match="revision"), edit_policy(path, now=NOW):
        pass


# -- L2: no hashes in reprs ----


def test_repr_never_contains_a_hash() -> None:
    token = Token("aaaaaaaaaaaa", HMAC, NOW)
    principal = Principal("p", "agent", tokens=(token,))
    for obj in (token, principal, Policy(principals=(principal,))):
        assert "cdcdcd" not in repr(obj)
        assert "abab" not in repr(obj)
        assert "hmac-sha256" not in repr(obj)
    assert "aaaaaaaaaaaa" in repr(token)


# -- L3: format_record never raises ----


def test_format_record_non_finite_and_huge_numbers() -> None:
    line = format_record({"a": float("nan"), "b": float("inf"), "c": -float("inf"), "d": 10**5000, "e": 1.5, "f": 7})
    assert json.loads(line) == {"a": "nan", "b": "inf", "c": "-inf", "d": "<int too large>", "e": 1.5, "f": 7}


def test_format_record_colliding_names_keep_every_field() -> None:
    line = format_record({"k\n": 1, "k\\x0a": 2, "k\\x0a_2": 3, "ts": "t"})
    parsed = json.loads(line)
    assert list(parsed) == ["ts", "k\\x0a", "k\\x0a_2", "k\\x0a_2_2"]
    assert sorted(parsed[k] for k in parsed if k != "ts") == [1, 2, 3]


def test_format_record_long_colliding_names_stay_bounded() -> None:
    long = "x" * 300
    parsed = json.loads(format_record({long: 1, long + "y": 2, long + "z": 3}))
    assert len(parsed) == 3
    assert all(len(name) <= accesslog_module.MAX_VALUE_LENGTH for name in parsed)


class Broken:
    def __str__(self) -> str:
        raise RuntimeError("no")


def test_format_record_unprintable_values() -> None:
    parsed = json.loads(format_record({Broken(): 1, "v": Broken(), "u": "\ud800 \U0001f600 \x00"}))
    assert parsed["v"] == "<unprintable>"
    assert parsed["u"] == "\\ud800 \\U0001f600 \\x00"


def test_format_record_never_raises_for_odd_values() -> None:
    rng = random.Random(7)  # noqa: S311 - a fixed seed for a reproducible fuzz, not security
    pool: list[Any] = [
        None, True, 0, -1, 2**63, 10**4400, 1e308, -0.0, float("nan"), float("inf"), "", "a\nb", "\ud800", "é" * 400,
        b"bytes", bytearray(b"x"), [1, [2]], {"a": {"b": 1}}, (1, 2), {1, 2}, object(), Broken(), 1 + 2j, ...,
    ]  # fmt: skip
    for _ in range(400):
        record = {_key(rng, pool): rng.choice(pool) for _ in range(rng.randint(0, 6))}
        line = format_record(record)
        assert "\n" not in line
        json.loads(line)


def _key(rng: random.Random, pool: list[Any]) -> Any:
    candidates = [k for k in pool if isinstance(k, (str, int, float, bytes, tuple, type(None), bool))]
    return rng.choice([*candidates, "ts", "k", "k\n"])


# -- L4: reading logs never crashes ----


def good(i: int) -> str:
    return json.dumps({"ts": f"2026-10-18T12:00:{i:02d}Z", "principal": "p", "decision": "allowed"}) + "\n"


def test_read_records_survives_hostile_lines_and_files(tmp_path: Path) -> None:
    log = tmp_path / "access.log"
    overlong = b'{"principal":"p","pad":"' + b"x" * (accesslog_module.MAX_LINE_BYTES * 3) + b'"}\n'
    deep = b"[" * 200000 + b"\n"
    log.write_bytes(
        good(1).encode() + deep + overlong + b"\xff\xfe not json\n" + good(2).encode() + overlong[:-1]  # torn, overlong
    )
    (tmp_path / "access.log.1").mkdir()  # a directory where a backup should be
    (tmp_path / "access.log.2").write_bytes(good(0).encode())
    records = read_records(log, limit=10)
    assert [r["ts"] for r in records] == ["2026-10-18T12:00:00Z", "2026-10-18T12:00:01Z", "2026-10-18T12:00:02Z"]


def test_read_records_line_exactly_at_the_limit_is_kept(tmp_path: Path) -> None:
    log = tmp_path / "access.log"
    prefix = b'{"principal":"p","pad":"'
    suffix = b'"}\n'
    pad = accesslog_module.MAX_LINE_BYTES - len(prefix) - len(suffix)
    log.write_bytes(prefix + b"x" * pad + suffix + prefix + b"x" * (pad + 2) + suffix)
    assert len(read_records(log)) == 1


def test_read_records_a_directory_or_unreadable_path_is_just_empty(tmp_path: Path) -> None:
    assert read_records(tmp_path) == []
    assert read_records(tmp_path / "missing" / "access.log") == []


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() == 0, reason="root can read anything")
def test_read_records_skips_a_file_without_permission(tmp_path: Path) -> None:
    log = tmp_path / "access.log"
    log.write_text(good(1))
    (tmp_path / "access.log.1").write_text(good(0))
    os.chmod(tmp_path / "access.log.1", 0)
    assert len(read_records(log)) == 1


def test_read_records_survives_an_unlistable_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    log = tmp_path / "access.log"
    log.write_text(good(1))

    def refuse(self: Path) -> Any:
        raise PermissionError("no listing")

    monkeypatch.setattr(Path, "iterdir", refuse)
    assert len(read_records(log)) == 1


# -- L5: evaluation defence in depth ----


def decide(grant: Grant, action: str, name: str = "db", tags: Any = ("ops",)) -> bool:
    principal = Principal("p", "agent")
    policy = Policy(principals=(principal,), grants=(grant,))
    return evaluate(policy, principal, action, name, tags, NOW).allowed


def test_tag_grants_never_allow_write_or_delete() -> None:
    grant = Grant("g_00000001", "p", None, "ops", frozenset({"list", "read", "write", "delete"}))
    assert decide(grant, "read")
    assert not decide(grant, "write")
    assert not decide(grant, "delete")


def test_grants_with_both_or_neither_selector_match_nothing() -> None:
    actions = frozenset({"read"})
    assert decide(Grant("g_00000001", "p", "db", None, actions), "read")
    assert not decide(Grant("g_00000001", "p", "db", "ops", actions), "read")
    assert not decide(Grant("g_00000001", "p", None, None, actions), "read")
    assert not decide(Grant("g_00000001", "p", "*", "ops", actions), "read")


def test_a_bare_string_for_tags_is_a_type_error() -> None:
    grant = Grant("g_00000001", "p", None, "o", frozenset({"read"}))
    with pytest.raises(TypeError, match="not a single string"):
        decide(grant, "read", tags="ops")
    principal = Principal("p", "agent")
    with pytest.raises(TypeError):
        visible(Policy(principals=(principal,), grants=(grant,)), principal, "read", [("db", "ops")], NOW)


def test_verify_token_hash_rejects_non_string_plaintext() -> None:
    stored = hash_token("mst_aaaaaaaaaaaa_secret")
    assert verify_token_hash(stored, "mst_aaaaaaaaaaaa_secret")
    for bad in (None, b"mst_aaaaaaaaaaaa_secret", 5):
        assert verify_token_hash(stored, bad) is False  # type: ignore[arg-type]


# -- nits ----


def test_is_valid_token_id_is_exported() -> None:
    assert is_valid_token_id("abcdefghijk2")
    assert not is_valid_token_id("ABCDEFGHIJK2")
    assert not is_valid_token_id(None)


def test_underscore_is_a_separator_in_patterns() -> None:
    with pytest.raises(PolicyError, match="did you mean 'db_\\*'"):
        validate_pattern("db_")
    validate_pattern("db_*")


def test_lone_surrogates_in_keys_are_policy_errors() -> None:
    with pytest.raises(PolicyError, match="cannot be encoded"):
        migrate_v1(json.dumps({"keys": [{"id": "a", "key": "\ud800" * 40}]}), Policy(), 16, NOW)
