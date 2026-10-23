"""Access-log formatting (no forged lines, bounded values) and reading rotated files."""

import json
import re
from datetime import UTC, datetime, timedelta
from logging.handlers import RotatingFileHandler
from pathlib import Path

import pytest

from mattstash.authz import format_record, now_iso, read_records

NOW = datetime(2026, 10, 18, 12, 0, tzinfo=UTC)


def test_format_orders_known_fields_then_others_and_drops_none() -> None:
    line = format_record(
        {
            "extra": "z",
            "status": 200,
            "ts": "t",
            "key": "k",
            "principal": "p",
            "reason": None,
            "decision": "allowed",
            "count": 3,
            "also": 1,
        }
    )
    assert list(json.loads(line)) == ["ts", "principal", "key", "decision", "status", "count", "extra", "also"]
    assert "\n" not in line and " " not in line


def test_values_are_escaped_to_printable_ascii() -> None:
    line = format_record({"key": 'a\nb\r\x00\x1b[31m\x7f caf\u00e9 \u202e \U0001f600 \\ "'})
    assert line.isascii() and "\n" not in line and "\r" not in line
    value = json.loads(line)["key"]
    assert value.isascii() and value.isprintable()
    assert "\\x0a" in value and "\\x0d" in value and "\\x00" in value and "\\x1b" in value and "\\x7f" in value
    assert "\\xe9" in value and "\\u202e" in value and "\\U0001f600" in value


def test_a_forged_record_stays_inside_one_string() -> None:
    attack = 'x"}\n{"principal":"admin","decision":"allowed"}'
    line = format_record({"principal": "bot", "key": attack})
    assert line.count("\n") == 0
    assert json.loads(line)["principal"] == "bot"


def test_strings_are_capped_at_256_characters() -> None:
    parsed = json.loads(format_record({"key": "a" * 1000, "client": "\n" * 1000, "b" * 1000: "x"}))
    assert len(parsed["key"]) == 256 and len(parsed["client"]) == 256
    assert all(len(name) <= 256 for name in parsed)


def test_non_string_values_keep_their_type_or_are_stringified() -> None:
    parsed = json.loads(format_record({"status": 200, "count": 0, "ok": True, "ratio": 0.5, "obj": ["a\n"]}))
    assert parsed["status"] == 200 and parsed["count"] == 0 and parsed["ok"] is True and parsed["ratio"] == 0.5
    assert parsed["obj"] == "['a\\n']"


def test_now_iso_shape() -> None:
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", now_iso())


def record(index: int, principal: str = "bot", decision: str = "allowed", minutes: int | None = None) -> str:
    stamp = (NOW + timedelta(minutes=index if minutes is None else minutes)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    return format_record({"ts": stamp, "principal": principal, "decision": decision, "key": f"k{index}"})


def write(path: Path, *lines: str) -> None:
    path.write_text("".join(line + "\n" for line in lines), encoding="utf-8")


def keys(records: list[dict]) -> list[str]:
    return [r["key"] for r in records]


def test_missing_file_and_nonpositive_limit(tmp_path: Path) -> None:
    assert read_records(tmp_path / "none.log") == []
    assert read_records(tmp_path / "no-dir" / "none.log") == []
    write(tmp_path / "a.log", record(1))
    assert read_records(tmp_path / "a.log", limit=0) == []
    assert read_records(tmp_path / "a.log", limit=-3) == []


def test_reads_chronologically_and_keeps_the_last_limit(tmp_path: Path) -> None:
    path = tmp_path / "access.jsonl"
    write(path, *(record(i) for i in range(10)))
    assert keys(read_records(path)) == [f"k{i}" for i in range(10)]
    assert keys(read_records(path, limit=3)) == ["k7", "k8", "k9"]
    assert keys(read_records(str(path), limit=1)) == ["k9"]


def test_rotated_backups_are_read_oldest_first(tmp_path: Path) -> None:
    path = tmp_path / "access.jsonl"
    write(path, record(6), record(7))
    write(tmp_path / "access.jsonl.1", record(4), record(5))
    write(tmp_path / "access.jsonl.2", record(2), record(3))
    write(tmp_path / "access.jsonl.10", record(0), record(1))  # numeric, not lexical, ordering
    (tmp_path / "access.jsonl.bak").write_text(record(99) + "\n")  # not a rotation file
    (tmp_path / "access.jsonl.1x").write_text(record(98) + "\n")
    (tmp_path / "other.jsonl.1").write_text(record(97) + "\n")
    assert keys(read_records(path, limit=100)) == [f"k{i}" for i in range(8)]
    assert keys(read_records(path, limit=3)) == ["k5", "k6", "k7"]


def test_works_with_the_real_rotating_handler(tmp_path: Path) -> None:
    path = tmp_path / "access.jsonl"
    handler = RotatingFileHandler(path, maxBytes=300, backupCount=5, encoding="utf-8")
    import logging

    logger = logging.getLogger("authz-test-access")
    logger.propagate = False
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    try:
        for i in range(12):
            logger.info(record(i))
    finally:
        logger.removeHandler(handler)
        handler.close()
    assert (tmp_path / "access.jsonl.1").exists()
    got = keys(read_records(path, limit=100))
    assert got == sorted(got, key=lambda k: int(k[1:])) and got[-1] == "k11" and len(got) >= 6


def test_filters(tmp_path: Path) -> None:
    path = tmp_path / "access.jsonl"
    write(
        path,
        record(1, "alice", "allowed"),
        record(2, "bob", "denied"),
        record(3, "alice", "denied"),
        record(4, "bob", "allowed"),
    )
    assert keys(read_records(path, principal="alice")) == ["k1", "k3"]
    assert keys(read_records(path, decision="denied")) == ["k2", "k3"]
    assert keys(read_records(path, principal="bob", decision="allowed")) == ["k4"]
    assert read_records(path, principal="ALICE") == []
    assert keys(read_records(path, since=NOW + timedelta(minutes=3))) == ["k3", "k4"]  # inclusive
    assert keys(read_records(path, since=(NOW + timedelta(minutes=3)).replace(tzinfo=None))) == ["k3", "k4"]
    assert keys(read_records(path, principal="alice", limit=1)) == ["k3"]  # the limit applies after filtering


def test_bad_lines_are_skipped(tmp_path: Path) -> None:
    path = tmp_path / "access.jsonl"
    path.write_bytes(
        (record(1) + '\nthis is not json\n\n[1, 2, 3]\n"just a string"\n{"torn": \n' + record(2) + "\n").encode()
        + b"\xff\xfe broken bytes\n"
        + (record(3) + "\n").encode()
        + record(4).encode()  # no trailing newline
    )
    assert keys(read_records(path)) == ["k1", "k2", "k3", "k4"]


def test_since_skips_records_without_a_usable_timestamp(tmp_path: Path) -> None:
    path = tmp_path / "access.jsonl"
    write(
        path,
        '{"key": "no-ts"}',
        '{"ts": 5, "key": "int-ts"}',
        '{"ts": "garbage", "key": "bad-ts"}',
        '{"ts": "2026-10-18T13:00:00", "key": "naive"}',
        record(120),
    )
    assert keys(read_records(path, since=NOW)) == ["naive", "k120"]
    assert keys(read_records(path)) == ["no-ts", "int-ts", "bad-ts", "naive", "k120"]


def test_a_file_that_vanishes_mid_read_is_ignored(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "access.jsonl"
    write(path, record(1))
    write(tmp_path / "access.jsonl.1", record(0))
    real_open = open

    def flaky(file, *args, **kwargs):
        if str(file).endswith(".1"):
            raise FileNotFoundError(file)
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr("builtins.open", flaky)
    assert keys(read_records(path)) == ["k1"]


def test_memory_is_bounded_by_the_limit(tmp_path: Path) -> None:
    path = tmp_path / "access.jsonl"
    write(path, *(record(i % 50) for i in range(5000)))
    assert len(read_records(path, limit=7)) == 7
