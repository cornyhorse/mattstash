"""Regression tests for the library-side findings of the independent security review.

Numbers refer to the review's finding list (see docs/security-review.md, section 4e).
"""

import errno
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from pykeepass import PyKeePass

from mattstash import MattStash
from mattstash.core import bootstrap
from mattstash.core.bootstrap import DatabaseBootstrapper
from mattstash.credential_store import CredentialStore
from mattstash.utils import filelock
from mattstash.utils.exceptions import (
    DatabaseAccessError,
    DatabaseExistsError,
    DatabaseLockError,
    DatabaseNotFoundError,
    MattStashError,
)
from mattstash.utils.filelock import FileLock


def opens_with(path: Path, password: str) -> bool:
    try:
        PyKeePass(str(path), password=password)
        return True
    except Exception:
        return False


def mode(path) -> int:
    return os.stat(path).st_mode & 0o777


def leftovers(directory: Path) -> list[str]:
    return sorted(p.name for p in directory.iterdir() if p.name.endswith((".new", ".tmp", ".restore")))


_CREATOR = """
import os, sys, time
import pykeepass.pykeepass as _kp
if os.environ.get("MATTSTASH_TEST_BLANK_DB"):  # tests/conftest.py: a cheap Argon2 setting, as in the parent process
    _kp.BLANK_DATABASE_LOCATION = os.environ["MATTSTASH_TEST_BLANK_DB"]
from mattstash import MattStash
path, password, force, start_at = sys.argv[1], sys.argv[2], sys.argv[3] == "1", float(sys.argv[4])
while time.time() < start_at:
    time.sleep(0.001)
try:
    MattStash.create(path, password=password, force=force, sidecar=False)
    print("OK")
except Exception as exc:
    print(type(exc).__name__)
"""


def race(path: Path, passwords: list[str], force: bool) -> list[str]:
    start_at = time.time() + 1.5  # every process waits for the same instant
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", _CREATOR, str(path), pw, "1" if force else "0", str(start_at)],
            stdout=subprocess.PIPE,
            text=True,
        )
        for pw in passwords
    ]
    return [p.communicate(timeout=180)[0].strip() for p in procs]


# ---------------------------------------------------------------------------
# #5 create(): no lock, shared temp names, no atomic create-if-absent
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("trial", range(3))
def test_5b_concurrent_create_without_force_has_exactly_one_winner(tmp_path: Path, trial: int):
    db = tmp_path / "m.kdbx"
    passwords = ["pw-a", "pw-b", "pw-c"]
    results = race(db, passwords, force=False)

    assert results.count("OK") == 1, results  # was: 2 of 12 trials reported several OKs and left an unopenable DB
    assert all(r in ("OK", "DatabaseExistsError") for r in results), results
    winner = passwords[results.index("OK")]
    assert opens_with(db, winner)
    assert [pw for pw in passwords if opens_with(db, pw)] == [winner]
    assert leftovers(tmp_path) == []


def test_5b_concurrent_forced_creates_are_serialised_and_leave_a_consistent_database(tmp_path: Path):
    db = tmp_path / "m.kdbx"
    MattStash.create(str(db), password="seed")
    passwords = ["pw-a", "pw-b", "pw-c"]
    results = race(db, passwords, force=True)

    assert all(r == "OK" for r in results), results  # was: raw FileExistsError/FileNotFoundError escaped
    assert sum(opens_with(db, pw) for pw in passwords) == 1  # exactly one caller's password opens the final DB
    assert leftovers(tmp_path) == []
    assert len([p for p in tmp_path.iterdir() if ".bak-" in p.name]) == 3  # one backup per forced create


def test_5a_forced_create_waits_for_a_live_writer_and_stale_writers_then_fail_loudly(tmp_path: Path):
    """`setup --force` against a running writer used to let the writer rename its OLD database over the new one."""
    db = tmp_path / "m.kdbx"
    MattStash.create(str(db), password="old-pw")
    stale_writer = MattStash(path=str(db), password="old-pw")
    stale_writer.put("keep", value="1")  # loaded in memory, holds an old-password copy

    finished = threading.Event()
    outcome: dict = {}

    def replace():
        try:
            outcome["info"] = DatabaseBootstrapper(str(db)).create("NEW-pw", force=True)
        except Exception as exc:  # pragma: no cover - failure path
            outcome["error"] = exc
        finished.set()

    with FileLock(str(db) + ".lock"):  # a writer is mid-save
        thread = threading.Thread(target=replace)
        thread.start()
        assert not finished.wait(0.8), "create() must wait for the writer's lock, not race it"
    thread.join(timeout=60)
    assert "error" not in outcome, outcome.get("error")

    assert opens_with(db, "NEW-pw") and not opens_with(db, "old-pw")
    with pytest.raises(DatabaseAccessError):  # the stale writer must not silently resurrect the old database
        stale_writer.put("late-write", value="2")
    assert MattStash(path=str(db), password="NEW-pw").list() == []


def test_5_creators_wait_for_the_lock_and_time_out_with_a_typed_error(tmp_path: Path):
    db = tmp_path / "m.kdbx"
    with FileLock(str(db) + ".lock"):
        with pytest.raises(DatabaseLockError):
            DatabaseBootstrapper(str(db)).create("pw", lock_timeout=0.2)
    assert not db.exists() and leftovers(tmp_path) == []


# ---------------------------------------------------------------------------
# #7 backups are never overwritten
# ---------------------------------------------------------------------------


def test_7_two_forced_creates_in_the_same_instant_keep_every_backup(tmp_path: Path, monkeypatch):
    """Backups were named with 1-second resolution and the later one overwrote the earlier: the ORIGINAL was lost."""
    db = tmp_path / "m.kdbx"
    MattStash.create(str(db), password="original")
    MattStash(path=str(db), password="original").put("precious", value="irreplaceable")
    original = db.read_bytes()

    class FrozenClock(bootstrap.datetime):  # every call sees the same instant
        @classmethod
        def now(cls, tz=None):
            return bootstrap.datetime(2026, 10, 7, 12, 0, 0, 123456, tzinfo=tz)

    monkeypatch.setattr(bootstrap, "datetime", FrozenClock)
    infos = [DatabaseBootstrapper(str(db)).create(f"pw{i}", force=True) for i in range(3)]

    backups = [b for info in infos for b in info.backups]
    assert len(backups) == len(set(backups)) == 3  # no collisions (counter suffixes), nothing overwritten
    assert [Path(b).read_bytes() for b in infos[0].backups] == [
        original
    ]  # the original DB survives in the first backup
    assert all(mode(b) == 0o600 for b in backups)


def test_7_real_back_to_back_creates_do_not_collide(tmp_path: Path):
    db = tmp_path / "m.kdbx"
    MattStash.create(str(db), password="a")
    names = {Path(b).name for i in range(3) for b in DatabaseBootstrapper(str(db)).create(f"p{i}", force=True).backups}
    assert len(names) == 3 and all(".bak-" in n for n in names)


# ---------------------------------------------------------------------------
# #18 failures while swapping files in
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("backup", [True, False])
def test_18_failed_database_swap_restores_the_old_sidecar_and_keeps_the_old_database(
    tmp_path: Path, monkeypatch, backup: bool
):
    """The sidecar was replaced first; if the database swap then failed, the old DB was left with the NEW password."""
    db = tmp_path / "m.kdbx"
    MattStash.create(str(db), password="old-pw", sidecar=True)
    old_db = db.read_bytes()
    sidecar = tmp_path / ".mattstash.txt"
    assert sidecar.read_text() == "old-pw"

    real_replace = os.replace

    def failing_replace(src, dst, *args, **kwargs):
        if str(dst) == str(db):
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr(bootstrap.os, "replace", failing_replace)
    with pytest.raises(MattStashError, match="No space left"):
        DatabaseBootstrapper(str(db)).create("new-pw", sidecar=True, force=True, backup=backup)
    monkeypatch.undo()

    assert db.read_bytes() == old_db and opens_with(db, "old-pw")  # old database untouched
    assert sidecar.read_text() == "old-pw"  # and it still has its password (works even with backup=False)
    assert mode(sidecar) == 0o600
    assert leftovers(tmp_path) == []


def test_18_failure_removing_the_stale_sidecar_is_reported_and_does_not_lose_the_new_password(
    tmp_path: Path, monkeypatch
):
    db = tmp_path / "m.kdbx"
    MattStash.create(str(db), password="old-pw", sidecar=True)
    real_remove = os.remove

    def failing_remove(path, *args, **kwargs):
        if str(path).endswith(".mattstash.txt"):
            raise OSError(errno.EROFS, "Read-only file system")
        return real_remove(path, *args, **kwargs)

    monkeypatch.setattr(bootstrap.os, "remove", failing_remove)
    info = DatabaseBootstrapper(str(db)).create("brand-new", force=True, backup=False)
    monkeypatch.undo()

    assert info.password == "brand-new" and opens_with(db, "brand-new")  # the caller still gets the password
    assert any("could not remove the old sidecar" in w for w in info.warnings)


def test_18_forced_create_without_backup_still_installs_and_cleans_up(tmp_path: Path):
    db = tmp_path / "m.kdbx"
    MattStash.create(str(db), password="old", sidecar=True)
    info = DatabaseBootstrapper(str(db)).create("new", force=True, backup=False, sidecar=True)
    assert info.backups == [] and (tmp_path / ".mattstash.txt").read_text() == "new"
    assert opens_with(db, "new") and leftovers(tmp_path) == []


def test_5_non_force_create_never_replaces_a_file_that_appears_late(tmp_path: Path, monkeypatch):
    """Create-if-absent is atomic: a database that shows up between the check and the install is not overwritten."""
    db = tmp_path / "m.kdbx"
    real_link = os.link

    def racing_link(src, dst, *args, **kwargs):
        if str(dst) == str(db):
            db.write_bytes(b"someone else's database")  # appears right before our install
        return real_link(src, dst, *args, **kwargs)

    monkeypatch.setattr(bootstrap.os, "link", racing_link)
    with pytest.raises(DatabaseExistsError):
        DatabaseBootstrapper(str(db)).create("pw")
    assert db.read_bytes() == b"someone else's database" and leftovers(tmp_path) == []


def test_5_filesystems_without_hard_links_still_work(tmp_path: Path, monkeypatch):
    def no_links(*args, **kwargs):
        raise OSError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(bootstrap.os, "link", no_links)
    db = tmp_path / "m.kdbx"
    DatabaseBootstrapper(str(db)).create("pw", sidecar=True)
    assert opens_with(db, "pw") and (tmp_path / ".mattstash.txt").read_text() == "pw" and leftovers(tmp_path) == []
    with pytest.raises(DatabaseExistsError):  # the fallback still refuses to overwrite
        DatabaseBootstrapper(str(db)).create("other")


# ---------------------------------------------------------------------------
# #19 FileLock misreports real errors as contention
# ---------------------------------------------------------------------------


def test_19_lock_failures_that_are_not_contention_fail_fast(tmp_path: Path, monkeypatch):
    """ENOLCK (no lock manager on NFS, ...) used to spin for the full timeout and report 'timed out'."""

    def no_lock_manager(fd):
        raise OSError(errno.ENOLCK, "No locks available")

    monkeypatch.setattr(filelock, "_try_lock", no_lock_manager)
    started = time.monotonic()
    with pytest.raises(DatabaseLockError, match="No locks available"):
        FileLock(str(tmp_path / "x.lock"), timeout=10).acquire()
    assert time.monotonic() - started < 1.0


@pytest.mark.parametrize("code", [errno.EAGAIN, errno.EACCES])
def test_19_real_contention_is_still_retried_until_the_timeout(tmp_path: Path, monkeypatch, code: int):
    def busy(fd):
        raise OSError(code, "busy")

    monkeypatch.setattr(filelock, "_try_lock", busy)
    with pytest.raises(DatabaseLockError, match="Timed out"):
        FileLock(str(tmp_path / "x.lock"), timeout=0.2, poll_interval=0.01).acquire()


# ---------------------------------------------------------------------------
# #6 (store part) saving a closed store must not look like success
# ---------------------------------------------------------------------------


def test_6_saving_a_store_that_is_not_open_raises(temp_db: Path):
    store = CredentialStore(str(temp_db), "irrelevant")
    with pytest.raises(DatabaseAccessError, match="not open"):
        store.save()


# ---------------------------------------------------------------------------
# #6 reload failure must not leave a half-open instance
# ---------------------------------------------------------------------------


def test_6_failed_reload_discards_state_and_recovers(temp_db: Path):
    stash = MattStash(str(temp_db))
    stash.put("a", value="1")
    original = temp_db.read_bytes()

    temp_db.write_bytes(b"not a database")
    assert stash.reload() is False
    assert stash._credential_store is None and stash._entry_manager is None

    temp_db.write_bytes(original)  # operator restores the file; the same instance must work again
    assert stash.get("a", show_password=True)["value"] == "1"
    stash.put("b", value="2")  # and writes must really be saved, not silently dropped
    assert MattStash(str(temp_db)).get("b", show_password=True)["value"] == "2"


# ---------------------------------------------------------------------------
# #8 readers must not queue behind a writer that is merely waiting for the file lock
# ---------------------------------------------------------------------------


def test_8_reader_is_not_blocked_by_writer_waiting_for_another_process(temp_db: Path):
    stash = MattStash(str(temp_db), lock_timeout=3.0)
    stash.put("a", value="1")
    stash.get("a")  # open

    other_process = FileLock(str(temp_db) + ".lock", timeout=1.0)
    other_process.acquire()  # simulates another process holding the write lock
    try:
        writer_started = threading.Event()
        outcome: list[BaseException | None] = []

        def writer() -> None:
            writer_started.set()
            try:
                stash.put("b", value="2")
                outcome.append(None)
            except BaseException as exc:
                outcome.append(exc)

        thread = threading.Thread(target=writer)
        thread.start()
        writer_started.wait(2)
        time.sleep(0.3)  # the writer is now parked on the file lock

        started = time.monotonic()
        assert stash.get("a", show_password=True)["value"] == "1"
        assert time.monotonic() - started < 1.0, "reader waited for the writer's file-lock timeout"
    finally:
        other_process.release()
    thread.join(10)
    assert outcome == [None]


def test_8_backup_takes_the_same_locks_as_writers(temp_db: Path, tmp_path: Path):
    stash = MattStash(str(temp_db), lock_timeout=0.3)
    stash.put("a", value="1")
    holder = FileLock(str(temp_db) + ".lock", timeout=1.0)
    holder.acquire()
    try:
        with pytest.raises(DatabaseLockError):
            stash.backup(str(tmp_path / "copy.kdbx"))
    finally:
        holder.release()
    assert not (tmp_path / "copy.kdbx").exists()


# ---------------------------------------------------------------------------
# #15 a symlinked database must stay a symlink (and the real file must be updated)
# ---------------------------------------------------------------------------


def test_15_symlinked_database_keeps_its_link_and_updates_the_target(tmp_path: Path):
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    real = real_dir / "secrets.kdbx"
    MattStash.create(str(real), password="pw", sidecar=False)

    link = tmp_path / "link.kdbx"
    link.symlink_to(real)

    stash = MattStash(str(link), password="pw")
    stash.put("a", value="1")
    stash.put("b", value="2")

    assert link.is_symlink(), "saving replaced the symlink with a regular file"
    assert MattStash(str(real), password="pw").get("b", show_password=True)["value"] == "2"
    assert not (tmp_path / "link.kdbx.lock").exists()  # one lock file, next to the real database
    assert (real_dir / "secrets.kdbx.lock").exists()


def test_15_two_paths_to_one_database_share_a_lock(tmp_path: Path):
    real = tmp_path / "real.kdbx"
    MattStash.create(str(real), password="pw", sidecar=False)
    link = tmp_path / "link.kdbx"
    link.symlink_to(real)

    via_link = MattStash(str(link), password="pw")
    via_real = MattStash(str(real), password="pw")
    assert via_link._file_lock.path == via_real._file_lock.path


# ---------------------------------------------------------------------------
# #16 a database that disappears must not keep being served from memory
# ---------------------------------------------------------------------------


def test_16_reads_fail_once_the_database_file_is_gone(temp_db: Path):
    stash = MattStash(str(temp_db))
    stash.put("a", value="1")
    assert stash.get("a") is not None  # loaded into memory

    temp_db.unlink()
    with pytest.raises(DatabaseNotFoundError):
        stash.get("a")
    with pytest.raises(DatabaseNotFoundError):
        stash.list()
    with pytest.raises(DatabaseNotFoundError):
        stash.put("b", value="2")
    assert not temp_db.exists()  # and nothing resurrected it


def test_16_instance_recovers_when_the_file_comes_back(tmp_path: Path):
    db = tmp_path / "x.kdbx"
    MattStash.create(str(db), password="pw", sidecar=False)
    stash = MattStash(str(db), password="pw")
    stash.put("a", value="1")
    saved = db.read_bytes()

    db.unlink()
    with pytest.raises(DatabaseNotFoundError):
        stash.get("a")

    db.write_bytes(saved)  # e.g. the volume is mounted again
    assert stash.get("a", show_password=True)["value"] == "1"


# ---------------------------------------------------------------------------
# #19 (db-url) IPv6 hosts and port range
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("endpoint", "expected"),
    [
        ("db.internal:5432", ("db.internal", 5432)),
        ("[::1]:5432", ("[::1]", 5432)),
        ("::1:5432", ("[::1]", 5432)),  # unbracketed: must not produce postgresql://u@::1:5432/db
        ("postgresql://u:p@[2001:db8::10]:6543/app", ("[2001:db8::10]", 6543)),
        ("10.0.0.5:3306", ("10.0.0.5", 3306)),
    ],
)
def test_19_db_url_hosts_are_normalised_for_urls(temp_db: Path, endpoint: str, expected: tuple[str, int]):
    assert MattStash(str(temp_db))._parse_host_port(endpoint) == expected


@pytest.mark.parametrize(
    "endpoint", ["db:0", "db:65536", "db:99999999999", "[::1:5432", "[db]:5432", "fe80::1%eth0:5432"]
)
def test_19_db_url_rejects_bad_ports_and_hosts(temp_db: Path, endpoint: str):
    with pytest.raises(ValueError):
        MattStash(str(temp_db))._parse_host_port(endpoint)


def test_19_db_url_with_bare_ipv6_endpoint_is_a_valid_url(temp_db: Path):
    from urllib.parse import urlparse

    stash = MattStash(str(temp_db))
    stash.put("pg", username="u", password="p@ss", url="::1:5432", notes="")
    url = stash.get_db_url("pg", database="app", mask_password=False)
    parsed = urlparse(url)
    assert (parsed.hostname, parsed.port, parsed.username) == ("::1", 5432, "u")


# ---------------------------------------------------------------------------
# Recycle Bin: entries trashed by another KeePass client are deleted, not secrets to serve
# ---------------------------------------------------------------------------


def test_trashed_entries_are_not_served_listed_or_resolved(temp_db: Path):
    stash = MattStash(str(temp_db))
    stash.put("old", value="1")
    stash.put("old", value="2")  # old@0000000001 / old@0000000002 style history
    stash.put("keep", value="k")
    password = stash.password

    kp = PyKeePass(str(temp_db), password=password)
    for entry in [e for e in kp.entries if (e.title or "").startswith("old")]:
        kp.trash_entry(entry)
    kp.save()

    fresh = MattStash(str(temp_db))
    assert fresh.get("old") is None
    assert fresh.get("old", version=1) is None
    assert [c.credential_name for c in fresh.list(latest_only=True)] == ["keep"]
    assert [c.credential_name for c in fresh.list()] == ["keep@0000000001"]
    assert fresh.list_versions("old") == []

    # version numbers are not reused, so a later restore from the bin cannot collide with a live entry
    fresh.put("old", value="3")
    assert fresh.get("old", show_password=True)["value"] == "3"
    assert fresh.list_versions("old") == ["0000000003"]


# ---------------------------------------------------------------------------
# password whitespace: file sources strip it, so a padded password must not be stored in one
# ---------------------------------------------------------------------------


def test_padded_password_cannot_be_combined_with_a_sidecar(tmp_path: Path):
    db = tmp_path / "x.kdbx"
    with pytest.raises(MattStashError, match="whitespace"):
        MattStash.create(str(db), password=" pw ", sidecar=True)
    assert list(tmp_path.iterdir()) == []  # refused before anything was written (not even a lock file)


def test_padded_password_without_sidecar_works_but_warns(tmp_path: Path):
    db = tmp_path / "x.kdbx"
    _stash, info = MattStash.create_with_info(str(db), password=" pw ", sidecar=False)
    assert opens_with(db, " pw ")
    assert any("whitespace" in w for w in info.warnings)


def test_setup_prints_the_warnings_it_collected(tmp_path: Path, caplog, monkeypatch):
    import io

    from mattstash.cli.main import main

    db = tmp_path / "x.kdbx"
    monkeypatch.setattr("sys.stdin", io.StringIO(" padded \n"))
    assert main(["--db", str(db), "setup", "--password-stdin"]) == 0
    assert any(r.levelname == "WARNING" and "whitespace" in r.getMessage() for r in caplog.records)
