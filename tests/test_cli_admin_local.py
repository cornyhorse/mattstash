"""``mattstash admin ...`` in local mode (design section 8): the policy file is edited directly."""

import json
import stat
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from admin_helpers import TOKEN_RE, Runner

from mattstash.authz import load_policy, verify_token_hash
from mattstash.cli import exit_codes
from mattstash.cli.handlers import admin as admin_module


@pytest.fixture()
def run(capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture) -> Runner:
    return Runner(capsys, caplog)


@pytest.fixture()
def policy(tmp_path: Path) -> Path:
    return tmp_path / "policy.json"


def admin(policy: Path, *argv: str) -> list[str]:
    return ["admin", "--policy-file", str(policy), *argv]


@pytest.fixture()
def bootstrapped(run: Runner, policy: Path) -> Path:
    """A policy with an admin (matt, with a token), an agent (bot) and a runner."""
    assert run(*admin(policy, "principal", "add", "matt", "--kind", "human-device", "--admin")).code == 0
    assert run(*admin(policy, "token", "issue", "matt")).code == 0
    assert run(*admin(policy, "principal", "add", "bot", "--kind", "agent", "--description", "an agent")).code == 0
    assert run(*admin(policy, "principal", "add", "ansible", "--kind", "runner")).code == 0
    return policy


# ---- bootstrap, principals -----------------------------


def test_bootstrap_creates_the_file_with_the_first_admin(run: Runner, policy: Path):
    result = run(*admin(policy, "principal", "add", "matt", "--kind", "human-device", "--admin"))
    assert result.code == 0 and "created principal matt (human-device)" in result.out
    assert stat.S_IMODE(policy.stat().st_mode) == 0o600
    loaded = load_policy(policy).principals[0]
    assert (loaded.name, loaded.admin, loaded.kind) == ("matt", True, "human-device")


def test_policy_file_from_environment_and_after_the_command(run: Runner, policy: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("MATTSTASH_POLICY_FILE", str(policy))
    assert run("admin", "principal", "add", "matt", "--kind", "human-device", "--admin").code == 0
    other = policy.with_name("other.json")
    assert run("admin", "principal", "add", "x", "--kind", "agent", "--policy-file", str(other)).code == 0
    assert other.exists() and [p.name for p in load_policy(policy).principals] == ["matt"]


def test_neither_server_nor_policy_file_is_a_clear_error(run: Runner):
    result = run("admin", "principal", "list")
    assert result.code == exit_codes.ERROR
    assert "--server-url" in result.err and "--policy-file" in result.err


def test_empty_policy_file_option_is_an_error(run: Runner):
    result = run("admin", "--policy-file", "", "principal", "list")
    assert result.code == 1 and "empty path" in result.err


def test_missing_policy_file_for_reads_explains_how_to_create_it(run: Runner, policy: Path):
    result = run(*admin(policy, "principal", "list"))
    assert result.code == 1 and "policy file not found" in result.err and "principal add" in result.err


def test_principal_list_show_json_and_no_hashes(run: Runner, bootstrapped: Path):
    table = run(*admin(bootstrapped, "principal", "list")).out
    assert table.splitlines()[0].split() == ["NAME", "KIND", "ADMIN", "STATE", "TOKENS", "DESCRIPTION"]
    assert "matt" in table and "human-device" in table and "an agent" in table
    data = json.loads(run(*admin(bootstrapped, "principal", "list", "--json")).out)
    assert [p["name"] for p in data] == ["matt", "bot", "ansible"]
    assert data[0]["legacy"] is False and len(data[0]["tokens"]) == 1
    assert "hash" not in json.dumps(data) and "hmac-sha256" not in json.dumps(data)
    shown = json.loads(run(*admin(bootstrapped, "principal", "show", "bot", "--json")).out)
    assert shown["name"] == "bot" and shown["grants"] == []


def test_principal_show_text_lists_tokens_and_grants(run: Runner, bootstrapped: Path):
    run(*admin(bootstrapped, "grant", "add", "matt", "--key", "db.*"))
    text = run(*admin(bootstrapped, "principal", "show", "matt")).out
    assert "name:        matt" in text and "tokens:" in text and "grants:" in text and "key:db.*" in text
    bare = run(*admin(bootstrapped, "principal", "show", "bot")).out
    assert bare.count("(none)") == 2


def test_empty_lists_say_none(run: Runner, policy: Path):
    run(*admin(policy, "principal", "add", "matt", "--kind", "human-device"))
    assert run(*admin(policy, "grant", "list")).out.strip() == "(none)"
    assert run(*admin(policy, "token", "list", "matt")).out.strip() == "(none)"


def test_unknown_principal_is_reported(run: Runner, bootstrapped: Path):
    result = run(*admin(bootstrapped, "principal", "show", "nobody"))
    assert result.code == exit_codes.NOT_FOUND and "Principal not found: nobody" in result.err


def test_agents_and_runners_cannot_be_admins(run: Runner, bootstrapped: Path):
    result = run(*admin(bootstrapped, "principal", "add", "evil", "--kind", "agent", "--admin"))
    assert result.code == 1 and "admin" in result.err
    assert load_policy(bootstrapped).principal("evil") is None


def test_duplicate_and_invalid_names(run: Runner, bootstrapped: Path):
    assert "already exists" in run(*admin(bootstrapped, "principal", "add", "BOT", "--kind", "agent")).err
    assert run(*admin(bootstrapped, "principal", "add", "_bad", "--kind", "agent")).code == 1


def test_disable_and_enable(run: Runner, bootstrapped: Path):
    assert run(*admin(bootstrapped, "principal", "disable", "bot")).out.strip() == "bot: disabled"
    assert load_policy(bootstrapped).principal("bot").disabled is True  # type: ignore[union-attr]
    assert "disabled" in run(*admin(bootstrapped, "principal", "list")).out
    assert run(*admin(bootstrapped, "principal", "enable", "bot")).out.strip() == "bot: enabled"
    assert load_policy(bootstrapped).principal("bot").disabled is False  # type: ignore[union-attr]
    assert run(*admin(bootstrapped, "principal", "disable", "nobody")).code == 2


def test_remove_needs_yes_without_a_terminal(run: Runner, bootstrapped: Path):
    run(*admin(bootstrapped, "grant", "add", "bot", "--key", "a.*"))
    result = run(*admin(bootstrapped, "principal", "remove", "bot"))
    assert result.code == 1 and "without --yes" in result.err
    assert load_policy(bootstrapped).principal("bot") is not None


def test_remove_with_yes_reports_removed_grants(run: Runner, bootstrapped: Path):
    run(*admin(bootstrapped, "grant", "add", "bot", "--key", "a.*"))
    result = run(*admin(bootstrapped, "principal", "remove", "bot", "--yes"))
    assert result.code == 0 and "removed principal bot (1 grant removed)" in result.out
    policy = load_policy(bootstrapped)
    assert policy.principal("bot") is None and policy.grants == ()
    assert run(*admin(bootstrapped, "principal", "remove", "nobody", "--yes")).code == 2


class _Tty:
    def __init__(self, answers: list[str]) -> None:
        self.answers = answers

    def isatty(self) -> bool:
        return True

    def readline(self) -> str:
        if not self.answers:
            return ""
        return self.answers.pop(0) + "\n"


@pytest.mark.parametrize(("answer", "removed"), [("y", True), ("YES", True), ("n", False), ("", False)])
def test_remove_asks_on_a_terminal(
    run: Runner, bootstrapped: Path, monkeypatch: pytest.MonkeyPatch, answer: str, removed: bool
):
    monkeypatch.setattr(sys, "stdin", _Tty([answer]))
    result = run(*admin(bootstrapped, "principal", "remove", "ansible"))
    assert (load_policy(bootstrapped).principal("ansible") is None) is removed
    assert result.code == (0 if removed else 1)
    assert removed or "not removed" in result.err


def test_remove_at_end_of_input_counts_as_no(run: Runner, bootstrapped: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(sys, "stdin", _Tty([]))
    assert run(*admin(bootstrapped, "principal", "remove", "ansible")).code == 1
    assert load_policy(bootstrapped).principal("ansible") is not None


def test_lockout_is_reported_not_crashed(run: Runner, bootstrapped: Path):
    """Design section 5: a change that leaves nobody able to administer is refused, with the reason."""
    for argv in (
        ["principal", "disable", "matt"],
        ["principal", "remove", "matt", "--yes"],
    ):
        result = run(*admin(bootstrapped, *argv))
        assert result.code == 1 and "no admin principal with a valid token" in result.err
    token_id = load_policy(bootstrapped).principal("matt").tokens[0].id  # type: ignore[union-attr]
    result = run(*admin(bootstrapped, "token", "revoke", "matt", token_id))
    assert result.code == 1 and "no admin principal" in result.err
    assert load_policy(bootstrapped).principal("matt").tokens[0].id == token_id  # type: ignore[union-attr]


# ---- tokens -----------------------------


def test_token_issue_prints_only_the_token_on_stdout(run: Runner, bootstrapped: Path):
    result = run(*admin(bootstrapped, "token", "issue", "bot", "--expires", "90d", "--description", "ci"))
    assert result.code == 0
    lines = result.out.splitlines()
    assert len(lines) == 1 and TOKEN_RE.fullmatch(lines[0]) and 55 <= len(lines[0]) <= 65
    token = lines[0]
    assert token not in result.err and "Shown once; store it now" in result.err
    stored = load_policy(bootstrapped).principal("bot").tokens[0]  # type: ignore[union-attr]
    assert verify_token_hash(stored.hash, token) and token.split("_")[1] == stored.id
    assert stored.id in result.err and stored.description == "ci"
    assert stored.expires is not None
    assert abs((stored.expires - datetime.now(UTC)) - timedelta(days=90)) < timedelta(minutes=1)
    assert token not in bootstrapped.read_text()


def test_token_issue_expiry_variants_and_errors(run: Runner, bootstrapped: Path):
    result = run(*admin(bootstrapped, "token", "issue", "bot", "--expires", "2099-01-01"))
    assert result.code == 0 and "expires 2099-01-01T00:00:00Z" in result.err
    bad = run(*admin(bootstrapped, "token", "issue", "bot", "--expires", "soon"))
    assert bad.code == 1 and "cannot read 'soon'" in bad.err and bad.out == ""
    assert run(*admin(bootstrapped, "token", "issue", "nobody")).code == 2


def test_token_issue_output_file(run: Runner, bootstrapped: Path, tmp_path: Path):
    target = tmp_path / "bot.token"
    result = run(*admin(bootstrapped, "token", "issue", "bot", "--output-file", str(target)))
    assert result.code == 0 and result.out == ""
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    content = target.read_text()
    assert TOKEN_RE.fullmatch(content.rstrip("\n")) and content.endswith("\n") and content.count("\n") == 1
    assert content.strip() not in result.err and str(target) in result.err
    stored = load_policy(bootstrapped).principal("bot").tokens[0]  # type: ignore[union-attr]
    assert verify_token_hash(stored.hash, content.strip())


def test_token_issue_output_file_refuses_to_overwrite(run: Runner, bootstrapped: Path, tmp_path: Path):
    target = tmp_path / "exists"
    target.write_text("precious")
    result = run(*admin(bootstrapped, "token", "issue", "bot", "--output-file", str(target)))
    assert result.code == 1 and "refusing to overwrite" in result.err
    assert target.read_text() == "precious"
    assert load_policy(bootstrapped).principal("bot").tokens == ()  # type: ignore[union-attr]
    link = tmp_path / "link"
    link.symlink_to(tmp_path / "elsewhere")
    assert run(*admin(bootstrapped, "token", "issue", "bot", "--output-file", str(link))).code == 1
    assert not (tmp_path / "elsewhere").exists()


def test_token_issue_failure_leaves_no_empty_output_file(run: Runner, bootstrapped: Path, tmp_path: Path):
    target = tmp_path / "t"
    result = run(*admin(bootstrapped, "token", "issue", "nobody", "--output-file", str(target)))
    assert result.code == 2 and not target.exists()


def test_token_issue_empty_output_file_path(run: Runner, bootstrapped: Path):
    result = run(*admin(bootstrapped, "token", "issue", "bot", "--output-file", ""))
    assert result.code == 1 and "empty path" in result.err


def test_token_list_and_revoke(run: Runner, bootstrapped: Path):
    first = run(*admin(bootstrapped, "token", "issue", "bot", "--expires", "30d")).out.strip()
    run(*admin(bootstrapped, "token", "issue", "bot"))
    tokens = json.loads(run(*admin(bootstrapped, "token", "list", "bot", "--json")).out)
    assert len(tokens) == 2 and all(set(t) == {"id", "created", "expires", "description", "expired"} for t in tokens)
    assert first.split("_")[1] == tokens[0]["id"] and tokens[1]["expires"] is None
    text = run(*admin(bootstrapped, "token", "list", "bot")).out
    assert "never" in text and tokens[0]["id"] in text and first not in text
    result = run(*admin(bootstrapped, "token", "revoke", "bot", tokens[0]["id"]))
    assert result.code == 0 and "revoked token" in result.out
    assert [t.id for t in load_policy(bootstrapped).principal("bot").tokens] == [tokens[1]["id"]]  # type: ignore[union-attr]
    assert run(*admin(bootstrapped, "token", "revoke", "bot", "zzzzzzzzzzzz")).code == 2
    assert run(*admin(bootstrapped, "token", "list", "nobody")).code == exit_codes.NOT_FOUND


def test_token_rotate_without_grace_revokes_the_old_one(run: Runner, bootstrapped: Path):
    old = run(*admin(bootstrapped, "token", "issue", "bot")).out.strip()
    old_id = old.split("_")[1]
    result = run(*admin(bootstrapped, "token", "rotate", "bot", old_id))
    new = result.out.strip()
    assert result.code == 0 and TOKEN_RE.fullmatch(new) and new != old
    assert "is revoked" in result.err and new not in result.err
    assert [t.id for t in load_policy(bootstrapped).principal("bot").tokens] == [new.split("_")[1]]  # type: ignore[union-attr]


def test_token_rotate_with_grace_keeps_the_old_one_for_a_while(run: Runner, bootstrapped: Path):
    old_id = run(*admin(bootstrapped, "token", "issue", "bot")).out.strip().split("_")[1]
    result = run(*admin(bootstrapped, "token", "rotate", "bot", old_id, "--grace", "24h", "--expires", "30d"))
    assert result.code == 0 and "stays valid until" in result.err
    tokens = load_policy(bootstrapped).principal("bot").tokens  # type: ignore[union-attr]
    old, new = tokens
    assert old.id == old_id and old.expires is not None
    assert abs((old.expires - datetime.now(UTC)) - timedelta(hours=24)) < timedelta(minutes=1)
    assert new.expires is not None and new.expires > old.expires


def test_token_rotate_output_file_and_errors(run: Runner, bootstrapped: Path, tmp_path: Path):
    old_id = run(*admin(bootstrapped, "token", "issue", "bot")).out.strip().split("_")[1]
    target = tmp_path / "new"
    result = run(*admin(bootstrapped, "token", "rotate", "bot", old_id, "--output-file", str(target)))
    assert result.code == 0 and result.out == "" and TOKEN_RE.fullmatch(target.read_text().strip())
    assert run(*admin(bootstrapped, "token", "rotate", "bot", "zzzzzzzzzzzz")).code == 2
    assert run(*admin(bootstrapped, "token", "rotate", "bot", old_id, "--grace", "later")).code == 1


# ---- grants, check -----------------------------


def test_grant_add_list_remove(run: Runner, bootstrapped: Path):
    added = run(*admin(bootstrapped, "grant", "add", "bot", "--key", "firefly.*", "--description", "finance"))
    grant_id = added.out.strip()
    assert added.code == 0 and grant_id.startswith("g_") and added.err == ""
    run(*admin(bootstrapped, "grant", "add", "ansible", "--tag", "ops", "--actions", "read", "--expires", "7d"))
    table = run(*admin(bootstrapped, "grant", "list")).out
    assert "key:firefly.*" in table and "tag:ops" in table and "list,read" in table and "finance" in table
    mine = json.loads(run(*admin(bootstrapped, "grant", "list", "--principal", "bot", "--json")).out)
    assert [g["id"] for g in mine] == [grant_id]
    assert mine[0]["actions"] == ["list", "read"] and mine[0]["legacy"] is False and mine[0]["expired"] is False
    assert run(*admin(bootstrapped, "grant", "list", "--principal", "nobody")).code == 2
    removed = run(*admin(bootstrapped, "grant", "remove", grant_id))
    assert removed.code == 0 and grant_id in removed.out
    missing = run(*admin(bootstrapped, "grant", "remove", grant_id))
    assert missing.code == 2 and "Grant not found" in missing.err


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (["--key", "a*b"], "'*' may appear only once"),
        (["--key", "firefly/"], "did you mean"),
        (["--key", "has space"], "printable ASCII"),
        (["--tag", "a;b"], "tag"),
        (["--key", "a", "--actions", "read,fly"], "--actions"),
        (["--key", "a", "--actions", ","], "--actions"),
        (["--key", "a", "--expires", "never-ever"], "cannot read"),
        (["--tag", "ops", "--actions", "write"], "tag grants"),
    ],
)
def test_grant_add_validates_before_writing(run: Runner, bootstrapped: Path, argv: list[str], message: str):
    before = bootstrapped.read_text()
    result = run(*admin(bootstrapped, "grant", "add", "bot", *argv))
    assert result.code == 1 and message in result.err and result.out == ""
    assert bootstrapped.read_text() == before


def test_grant_add_needs_exactly_one_selector(run: Runner, bootstrapped: Path):
    with pytest.raises(SystemExit):
        run(*admin(bootstrapped, "grant", "add", "bot"))
    with pytest.raises(SystemExit):
        run(*admin(bootstrapped, "grant", "add", "bot", "--key", "a", "--tag", "b"))


def test_star_grant_to_an_agent_warns(run: Runner, bootstrapped: Path):
    warned = run(*admin(bootstrapped, "grant", "add", "bot", "--key", "*"))
    assert warned.code == 0 and "warning: granting '*'" in warned.err and warned.out.startswith("g_")
    for principal in ("ansible", "matt"):
        assert "warning" not in run(*admin(bootstrapped, "grant", "add", principal, "--key", "*")).err
    assert "warning" not in run(*admin(bootstrapped, "grant", "add", "bot", "--key", "x*")).err
    unknown = run(*admin(bootstrapped, "grant", "add", "nobody", "--key", "*"))
    assert unknown.code == 2 and "warning" not in unknown.err


def test_check_exit_codes_and_wording(run: Runner, bootstrapped: Path):
    grant_id = run(*admin(bootstrapped, "grant", "add", "bot", "--key", "db.*")).out.strip()
    run(*admin(bootstrapped, "grant", "add", "bot", "--tag", "shared"))
    allowed = run(*admin(bootstrapped, "check", "bot", "read", "db.password"))
    assert (allowed.code, allowed.out) == (0, f"allowed (grant {grant_id})\n")
    denied = run(*admin(bootstrapped, "check", "bot", "write", "db.password"))
    assert (denied.code, denied.out) == (1, "denied (no-grant)\n")
    assert run(*admin(bootstrapped, "check", "bot", "read", "other")).code == 1
    by_tag = run(*admin(bootstrapped, "check", "bot", "read", "other", "--tag", "shared", "--tag", "x"))
    assert by_tag.code == 0 and by_tag.out.startswith("allowed (grant g_")
    run(*admin(bootstrapped, "principal", "disable", "bot"))
    assert run(*admin(bootstrapped, "check", "bot", "read", "db.password")).out == "denied (disabled)\n"


def test_check_unknown_principal_is_not_a_denial(run: Runner, bootstrapped: Path):
    result = run(*admin(bootstrapped, "check", "nobody", "read", "x"))
    assert result.code == exit_codes.NOT_FOUND and "Principal not found" in result.err and result.out == ""


def test_check_rejects_unknown_action(run: Runner, bootstrapped: Path):
    with pytest.raises(SystemExit):
        run(*admin(bootstrapped, "check", "bot", "admin", "x"))


# ---- log -----------------------------


def _record(minutes_ago: int, principal: str, decision: str, key: str = "k", **extra: object) -> str:
    stamp = (datetime.now(UTC) - timedelta(minutes=minutes_ago)).isoformat(timespec="milliseconds")
    record = {
        "ts": stamp.replace("+00:00", "Z"),
        "principal": principal,
        "kind": "agent",
        "action": "read",
        "key": key,
        "decision": decision,
        "client": "10.0.0.1",
        "status": 200 if decision == "allowed" else 404,
        **extra,
    }
    return json.dumps(record)


@pytest.fixture()
def access_log(tmp_path: Path) -> Path:
    path = tmp_path / "access.jsonl"
    (tmp_path / "access.jsonl.1").write_text(
        _record(60 * 48, "bot", "allowed", "old")
        + "\n"
        + _record(30, "bot", "denied", "rotated", reason="no-grant")
        + "\n"
    )
    path.write_text(
        "not json at all\n"
        + _record(20, "matt", "allowed", "mine")
        + "\n"
        + _record(10, "bot", "allowed", "db.password")
        + "\n"
        + _record(5, "bot", "denied", "nope", reason="no-grant")
        + "\n"
    )
    return path


def test_log_table_includes_rotated_backups(run: Runner, access_log: Path):
    result = run("admin", "log", "--log-file", str(access_log))
    assert result.code == 0
    header = result.out.splitlines()[0].split()
    assert header == ["TS", "PRINCIPAL", "KIND", "ACTION", "KEY", "DECISION", "REASON", "CLIENT", "STATUS"]
    keys = [line.split()[4] for line in result.out.splitlines()[1:]]
    assert keys == ["old", "rotated", "mine", "db.password", "nope"]  # chronological, backup first
    assert "no-grant" in result.out and "10.0.0.1" in result.out


def test_log_filters(run: Runner, access_log: Path):
    def keys(*argv: str) -> list[str]:
        out = run("admin", "log", "--log-file", str(access_log), "--json", *argv).out
        return [json.loads(line)["key"] for line in out.splitlines()]

    assert keys("--principal", "bot") == ["old", "rotated", "db.password", "nope"]
    assert keys("--decision", "denied") == ["rotated", "nope"]
    assert keys("--principal", "bot", "--decision", "denied") == ["rotated", "nope"]
    assert keys("--since", "24h") == ["rotated", "mine", "db.password", "nope"]
    assert keys("--since", "15m") == ["db.password", "nope"]
    assert keys("--limit", "2") == ["db.password", "nope"]
    tomorrow = (datetime.now(UTC) + timedelta(days=1)).date().isoformat()
    assert keys("--since", tomorrow) == []


def test_log_json_lines_are_the_raw_records(run: Runner, access_log: Path):
    out = run("admin", "log", "--log-file", str(access_log), "--json", "--limit", "1").out
    assert out.count("\n") == 1 and json.loads(out)["key"] == "nope"


def test_log_file_from_environment_needs_no_policy_file(run: Runner, access_log: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("MATTSTASH_ACCESS_LOG_FILE", str(access_log))
    assert run("admin", "log", "--limit", "1").code == 0
    monkeypatch.delenv("MATTSTASH_ACCESS_LOG_FILE")
    assert "--policy-file" in run("admin", "log").err
    result = run("admin", "--policy-file", str(access_log.parent / "p.json"), "log")
    assert result.code == 1 and "no access log file" in result.err


def test_log_empty_and_bad_arguments(run: Runner, tmp_path: Path):
    assert run("admin", "log", "--log-file", str(tmp_path / "missing.jsonl")).out.strip() == "(none)"
    bad = run("admin", "log", "--log-file", str(tmp_path / "x"), "--since", "yesterday-ish")
    assert bad.code == 1 and "cannot read" in bad.err
    assert run("admin", "log", "--log-file", "").code == 1
    for limit in ("0", "1001", "x"):
        with pytest.raises(SystemExit):
            run("admin", "log", "--log-file", str(tmp_path / "x"), "--limit", limit)


def test_log_output_escapes_control_characters(run: Runner, tmp_path: Path):
    path = tmp_path / "a.jsonl"
    path.write_text(json.dumps({"ts": "2026-01-01T00:00:00Z", "principal": "p\x1b[31m", "key": "é​"}) + "\n")
    out = run("admin", "log", "--log-file", str(path)).out
    assert "\x1b" not in out and "\\x1b[31m" in out and "é" in out and "\\u200b" in out


# ---- migrate-keys -----------------------------

K1 = "k1-" + "a" * 40
K2 = "k2-" + "b" * 40


def _v1(tmp_path: Path, keys: object = None) -> Path:
    path = tmp_path / "keys.json"
    path.write_text(
        json.dumps(
            keys
            or {
                "keys": [
                    {"id": "billing", "key": K1, "ops": ["read"], "prefixes": ["inv."]},
                    {"id": "root", "key": K2, "ops": ["read", "write", "delete", "admin"]},
                ]
            }
        )
    )
    return path


def test_migrate_keys_keeps_the_old_keys_working(run: Runner, policy: Path, tmp_path: Path):
    result = run(*admin(policy, "migrate-keys", "--from", str(_v1(tmp_path))))
    assert result.code == 0 and result.out.split() == ["billing", "root"]
    assert "migrated 2 keys" in result.err
    loaded = load_policy(policy)
    billing, root = loaded.principals
    assert (billing.kind, billing.admin, root.kind, root.admin) == ("agent", False, "human-device", True)
    assert verify_token_hash(billing.tokens[0].hash, K1) and verify_token_hash(root.tokens[0].hash, K2)
    assert {(g.principal, g.key) for g in loaded.grants} == {("billing", "inv.*"), ("root", "*")}
    assert K1 not in policy.read_text()


def test_migrate_keys_min_length_and_errors(run: Runner, policy: Path, tmp_path: Path):
    short = _v1(tmp_path, {"keys": [{"id": "x", "key": "short-key-of-20-chars"}]})
    refused = run(*admin(policy, "migrate-keys", "--from", str(short)))
    assert refused.code == 1 and "shorter than 32" in refused.err and not policy.exists()
    accepted = run(*admin(policy, "migrate-keys", "--from", str(short), "--min-length", "10"))
    assert accepted.code == 0 and "migrated 1 key;" in accepted.err
    again = run(*admin(policy, "migrate-keys", "--from", str(short), "--min-length", "10"))
    assert again.code == 1 and "already exists" in again.err
    with pytest.raises(SystemExit):
        run(*admin(policy, "migrate-keys", "--from", str(short), "--min-length", "0"))
    with pytest.raises(SystemExit):
        run(*admin(policy, "migrate-keys", "--from", str(short), "--min-length", "x"))


def test_migrate_keys_input_problems(run: Runner, policy: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    assert run(*admin(policy, "migrate-keys", "--from", str(tmp_path / "missing.json"))).code == 1
    binary = tmp_path / "b.json"
    binary.write_bytes(b"\xff\xfe\x00")
    assert "not valid UTF-8" in run(*admin(policy, "migrate-keys", "--from", str(binary))).err
    monkeypatch.setattr(admin_module, "_MAX_MIGRATION_FILE", 10)
    assert "too large" in run(*admin(policy, "migrate-keys", "--from", str(_v1(tmp_path)))).err


def test_migrate_keys_is_local_only(run: Runner, tmp_path: Path):
    result = run("admin", "migrate-keys", "--from", str(_v1(tmp_path)))
    assert result.code == 1 and "local mode" in result.err


def test_migrate_keys_with_a_server_url_in_the_environment_still_edits_the_file(
    run: Runner, policy: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("MATTSTASH_SERVER_URL", "http://localhost:9")
    assert run(*admin(policy, "migrate-keys", "--from", str(_v1(tmp_path)))).code == 0
    assert policy.exists()
