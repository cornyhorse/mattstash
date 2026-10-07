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
import sys, time
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
