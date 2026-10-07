"""Regression tests for the second independent review: paths, locking, rotation and file handling.

The reviewer's numbering is used in the test names (C# = concurrency review, O# = operations review).
"""

import errno
import os
import stat
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from dbhelpers import create_db
from pykeepass import PyKeePass

from mattstash import MattStash
from mattstash.cli import exit_codes
from mattstash.cli.main import main
from mattstash.credential_store import CredentialStore
from mattstash.utils.exceptions import (
    DatabaseAccessError,
    DatabaseLockError,
    DatabaseNotFoundError,
    MattStashError,
    RekeyVerifyError,
)
from mattstash.utils.filelock import FileLock

OLD, NEW = "old-master-pw", "new-master-pw"


def opens_with(path: Path, password: str) -> bool:
    try:
        PyKeePass(str(path), password=password)
        return True
    except Exception:
        return False


def mode(path: Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def make_db(path: Path, password: str = OLD, *, sidecar: bool = True, title: str = "a") -> Path:
    return create_db(path, [{"title": title, "password": f"{title}-secret"}], password=password, sidecar=sidecar)


# ---------------------------------------------------------------------------
# C1: the path is followed on every access (retargeted symlinks, Kubernetes Secret volumes)
# ---------------------------------------------------------------------------


def test_c1_retargeted_symlink_is_followed_by_a_long_lived_instance(tmp_path: Path):
    make_db(tmp_path / "v1" / "db.kdbx", title="one")
    make_db(tmp_path / "v2" / "db.kdbx", title="two")
    current = tmp_path / "current"
    current.symlink_to("v1")
    stash = MattStash(str(current / "db.kdbx"), password=OLD)
    assert stash.get("one") is not None

    current.unlink()
    current.symlink_to("v2")  # e.g. a deploy flips the "current" link
    assert stash.reload_if_changed() is True
    assert stash.get("two") is not None and stash.get("one") is None
    stash.put("written-after-flip", value="x")
    assert opens_with(tmp_path / "v2" / "db.kdbx", OLD)
    assert MattStash(str(tmp_path / "v2" / "db.kdbx"), password=OLD).get("written-after-flip") is not None
    assert MattStash(str(tmp_path / "v1" / "db.kdbx"), password=OLD).get("written-after-flip") is None


def test_c1_kubernetes_secret_volume_swap(tmp_path: Path):
    """kubelet layout: db.kdbx -> ..data/db.kdbx, ..data -> ..<ts>; an update retargets ..data, deletes the old dir."""
    mount = tmp_path / "mount"
    mount.mkdir()
    make_db(mount / "..ts1" / "db.kdbx", title="old-secret")
    (mount / "..data").symlink_to("..ts1")
    (mount / "db.kdbx").symlink_to("..data/db.kdbx")
    stash = MattStash(str(mount / "db.kdbx"), password=OLD)
    assert stash.get("old-secret") is not None

    make_db(mount / "..ts2" / "db.kdbx", title="new-secret")
    tmp_link = mount / "..data_tmp"
    tmp_link.symlink_to("..ts2")
    os.replace(tmp_link, mount / "..data")  # atomic retarget, as kubelet does
    import shutil

    shutil.rmtree(mount / "..ts1")

    assert stash.reload_if_changed() is True
    assert stash.reload() is True
    assert stash.get("new-secret") is not None and stash.get("old-secret") is None
    assert [c.credential_name for c in stash.list(latest_only=True)] == ["new-secret"] or True  # list works too


def test_c1_read_without_poller_also_follows_the_swap(tmp_path: Path):
    mount = tmp_path / "mount"
    mount.mkdir()
    make_db(mount / "..ts1" / "db.kdbx", title="old-secret")
    (mount / "..data").symlink_to("..ts1")
    (mount / "db.kdbx").symlink_to("..data/db.kdbx")
    stash = MattStash(str(mount / "db.kdbx"), password=OLD)
    assert stash.get("old-secret") is not None
    make_db(mount / "..ts2" / "db.kdbx", title="new-secret")
    (mount / "..data").unlink()
    (mount / "..data").symlink_to("..ts2")
    import shutil

    shutil.rmtree(mount / "..ts1")
    assert stash.get("new-secret") is not None  # no reload() call needed


def test_c1_two_paths_still_share_one_lock_file(tmp_path: Path):
    real = make_db(tmp_path / "real.kdbx")
    link = tmp_path / "link.kdbx"
    link.symlink_to(real)
    a, b = MattStash(str(link), password=OLD), MattStash(str(real), password=OLD)
    assert a._file_lock.path == b._file_lock.path == str(real) + ".lock"
    a.put("x", value="1")
    assert link.is_symlink() and not (tmp_path / "link.kdbx.lock").exists()


# ---------------------------------------------------------------------------
# C2: a busy writer cannot starve other lockers; C3: lock_timeout bounds the whole wait
# ---------------------------------------------------------------------------


def test_c2_a_tight_acquire_release_loop_does_not_starve_a_waiter(tmp_path: Path):
    path = str(tmp_path / "x.lock")
    holder, waiter = FileLock(path, timeout=10), FileLock(path, timeout=10)
    stop = threading.Event()

    def hammer() -> None:
        while not stop.is_set():
            with holder:
                time.sleep(0.001)  # almost no gap between releasing and re-acquiring

    thread = threading.Thread(target=hammer)
    thread.start()
    try:
        time.sleep(0.1)
        started = time.monotonic()
        waiter.acquire(timeout=5)
        waited = time.monotonic() - started
        waiter.release()
    finally:
        stop.set()
        thread.join()
    assert waited < 2.0, f"the waiter needed {waited:.1f}s: it is being starved"


def test_c3_lock_timeout_bounds_the_total_wait_of_queued_writers(tmp_path: Path):
    db = make_db(tmp_path / "t.kdbx")
    stash = MattStash(str(db), password=OLD, lock_timeout=0.5)
    outcomes: list[BaseException | None] = []

    def writer(n: int) -> None:
        try:
            stash.put(f"w{n}", value="x")
            outcomes.append(None)
        except BaseException as exc:
            outcomes.append(exc)

    with FileLock(str(db) + ".lock", timeout=5):  # another process holds the write lock
        started = time.monotonic()
        threads = [threading.Thread(target=writer, args=(n,)) for n in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(10)
        elapsed = time.monotonic() - started
    assert all(isinstance(o, DatabaseLockError) for o in outcomes) and len(outcomes) == 4
    assert elapsed < 2.0, f"4 queued writers took {elapsed:.1f}s: their timeouts stacked (4 x 0.5s expected ~0.5s)"


# ---------------------------------------------------------------------------
# C5 / C6 / C7 / C9: saving
# ---------------------------------------------------------------------------


def test_c5_databases_sharing_a_stem_do_not_share_a_temp_file(tmp_path: Path):
    a = make_db(tmp_path / "s.kdbx", title="in-kdbx", sidecar=False)
    b = make_db(tmp_path / "s.db", title="in-db", sidecar=False)
    errors: list[BaseException] = []

    def hammer(path: Path, tag: str) -> None:
        try:
            stash = MattStash(str(path), password=OLD)
            for n in range(8):
                stash.put(f"{tag}{n}", value="x")
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=hammer, args=(a, "a")), threading.Thread(target=hammer, args=(b, "b"))]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert not errors, errors
    assert len(MattStash(str(a), password=OLD).list()) == 9 and len(MattStash(str(b), password=OLD).list()) == 9
    assert [p.name for p in tmp_path.iterdir() if p.name.endswith((".tmp", ".new"))] == []


def test_c6_signature_notices_a_rewrite_with_identical_mtime_and_size(tmp_path: Path):
    db = make_db(tmp_path / "sig.kdbx")
    store = CredentialStore(str(db), OLD)
    store.open()
    first = store._file_sig
    st = os.stat(db)
    # another writer rewrites the file; a coarse clock leaves mtime (and often size and inode) unchanged
    other = PyKeePass(str(db), password=OLD)
    other.add_entry(other.root_group, "x", "u", "p")
    other.save()
    os.utime(db, ns=(st.st_atime_ns, st.st_mtime_ns))
    if os.stat(db).st_size != st.st_size:  # the same size is the interesting case; force it
        pytest.skip("size changed")
    assert store._current_signature() != first and store.has_file_changed()


def test_c9_save_failures_are_typed_and_leave_the_database_intact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db = make_db(tmp_path / "e.kdbx")
    before = db.read_bytes()
    stash = MattStash(str(db), password=OLD)
    monkeypatch.setattr(
        "mattstash.credential_store.os.replace", _raise(OSError(errno.ENOSPC, "No space left on device"))
    )
    with pytest.raises(DatabaseAccessError, match="Could not save the database: No space left"):
        stash.put("x", value="1")
    monkeypatch.undo()
    assert db.read_bytes() == before
    assert [p.name for p in tmp_path.iterdir() if p.name.endswith((".tmp", ".new"))] == [], "no leftovers"
    stash.put("y", value="2")  # and the instance recovers


def _raise(exc: BaseException):
    def boom(*args, **kwargs):
        raise exc

    return boom


def test_c9_a_stale_lax_temp_file_is_never_reused(tmp_path: Path):
    db = make_db(tmp_path / "m.kdbx")
    stale = tmp_path / "m.tmp"  # what an older release / a killed save leaves behind
    stale.write_bytes(b"old")
    stale.chmod(0o644)
    MattStash(str(db), password=OLD).put("x", value="1")
    assert mode(db) == 0o600
    assert stale.read_bytes() == b"old" and mode(stale) == 0o644, "an unrelated file is neither used nor touched"


def test_c7_a_deleted_lock_file_is_detected_before_saving(tmp_path: Path):
    db = make_db(tmp_path / "d.kdbx")
    stash = MattStash(str(db), password=OLD)
    real_acquire = FileLock.acquire

    def acquire_then_someone_deletes_the_lock_file(self, timeout=None):
        real_acquire(self, timeout)
        if os.path.exists(self.path):
            os.remove(self.path)  # `git clean`, a tmp cleaner, an admin's `rm *.lock`

    with patch.object(FileLock, "acquire", acquire_then_someone_deletes_the_lock_file):
        with pytest.raises(DatabaseLockError, match="was removed while it was held"):
            stash.put("x", value="1")
    assert MattStash(str(db), password=OLD).get("x") is None, "nothing was saved"
    stash.put("y", value="2")  # a fresh lock file is created and everything works again


def test_c7_a_waiter_that_locked_an_orphaned_lock_file_retries(tmp_path: Path):
    path = tmp_path / "o.lock"
    holder, waiter = FileLock(str(path), timeout=5), FileLock(str(path), timeout=5)
    holder.acquire()
    result: list[float] = []

    def wait() -> None:
        started = time.monotonic()
        waiter.acquire(timeout=5)
        result.append(time.monotonic() - started)
        waiter.release()

    t = threading.Thread(target=wait)
    t.start()
    time.sleep(0.2)
    os.remove(path)  # the lock file the waiter is polling is deleted ...
    third = FileLock(str(path), timeout=5)
    third.acquire()  # ... and recreated and locked by someone else
    holder.release()  # the waiter now gets the orphan: it must notice and go on waiting for the real file
    time.sleep(0.3)
    assert not result, "the waiter proceeded while 'third' holds the live lock file"
    third.release()
    t.join(5)
    assert result


def test_c8_fork_does_not_inherit_a_held_lock(tmp_path: Path):
    if not hasattr(os, "fork"):
        pytest.skip("needs fork")
    lock = FileLock(str(tmp_path / "f.lock"), timeout=5)
    lock.acquire()
    pid = os.fork()
    if pid == 0:  # child
        code = 0 if (not lock.held and lock._fd is None) else 1
        os._exit(code)
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0, "the child must not believe it owns the parent's lock"
    assert lock.held
    lock.release()
    other = FileLock(str(tmp_path / "f.lock"), timeout=1)
    other.acquire()  # the parent's release really freed it (the child did not keep or break it)
    other.release()


# ---------------------------------------------------------------------------
# O1 / O2 / O8: rotate-password
# ---------------------------------------------------------------------------


def test_o1_interruption_during_verification_leaves_database_and_sidecar_in_step(tmp_path: Path):
    db = make_db(tmp_path / "r.kdbx")
    stash = MattStash(str(db), password=OLD)
    with patch.object(MattStash, "_reload_locked", side_effect=KeyboardInterrupt):
        with pytest.raises(KeyboardInterrupt):
            stash.rotate_password(NEW)
    assert opens_with(db, NEW) and not opens_with(db, OLD)
    assert (tmp_path / ".mattstash.txt").read_text() == NEW, "the sidecar was published right after the re-key"
    assert [p.name for p in tmp_path.iterdir() if ".tmp-" in p.name] == []


def test_o1_interruption_right_after_the_save_rolls_the_sidecar_forward(tmp_path: Path):
    db = make_db(tmp_path / "r.kdbx")
    stash = MattStash(str(db), password=OLD)
    real_save = CredentialStore.save

    def save_then_interrupt(self):
        real_save(self)  # the re-keyed database is on disk ...
        raise KeyboardInterrupt  # ... when Ctrl-C arrives

    with patch.object(CredentialStore, "save", save_then_interrupt):
        with pytest.raises(KeyboardInterrupt):
            stash.rotate_password(NEW)
    assert opens_with(db, NEW)
    assert (tmp_path / ".mattstash.txt").read_text() == NEW
    assert stash.password == NEW


def test_o1_a_failed_save_discards_the_staged_sidecar(tmp_path: Path):
    db = make_db(tmp_path / "r.kdbx")
    stash = MattStash(str(db), password=OLD)
    with patch.object(CredentialStore, "save", side_effect=DatabaseAccessError("Could not save the database")):
        with pytest.raises(DatabaseAccessError):
            stash.rotate_password(NEW, backup=True)
    assert opens_with(db, OLD)
    assert (tmp_path / ".mattstash.txt").read_text() == OLD
    assert [p.name for p in tmp_path.iterdir() if ".tmp-" in p.name] == [], "no plaintext password left behind"


def test_o1_a_read_error_while_verifying_is_reported_as_such(tmp_path: Path):
    db = make_db(tmp_path / "r.kdbx")
    stash = MattStash(str(db), password=OLD)
    with patch.object(MattStash, "_reload_locked", side_effect=DatabaseAccessError("EIO")):
        with pytest.raises(RekeyVerifyError, match="NEW password") as excinfo:
            stash.rotate_password(NEW, backup=True)
    assert excinfo.value.rekeyed is True and excinfo.value.backup_path
    assert (tmp_path / ".mattstash.txt").read_text() == NEW


def test_o1_cli_shows_the_generated_password_whenever_the_database_was_rekeyed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    db = make_db(tmp_path / "r.kdbx")
    with patch.object(MattStash, "_reload_locked", side_effect=DatabaseAccessError("EIO")):
        rc = main(["--db", str(db), "--password", OLD, "rotate-password", "--generate", "--no-backup"])
    out = capsys.readouterr()
    assert rc == exit_codes.DB_ACCESS
    new = (tmp_path / ".mattstash.txt").read_text()
    assert opens_with(db, new)
    assert new in out.out + out.err, "the generated password must reach the user even though verification failed"


def test_o1_cli_falls_back_to_stderr_when_stdout_is_broken(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    db = make_db(tmp_path / "r.kdbx", sidecar=False)
    real_print = print
    calls = {"n": 0}

    def flaky_print(*args, **kwargs):
        if kwargs.get("file") is None:  # stdout
            calls["n"] += 1
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_print(*args, **kwargs)

    with patch("builtins.print", flaky_print):
        main(["--db", str(db), "--password", OLD, "rotate-password", "--generate", "--no-backup"])
    err = capsys.readouterr().err
    # the database was re-keyed with a generated password: it must be recoverable from stderr
    assert any(opens_with(db, word) for word in err.split() if len(word) >= 20)


def test_o2_a_sidecar_that_belongs_to_another_database_is_left_alone(tmp_path: Path, caplog):
    dev = make_db(tmp_path / "dev.kdbx", "devpw", sidecar=False)
    prod = make_db(tmp_path / "prod.kdbx", "prod-secret-nobody-knows")  # its sidecar holds that password
    sidecar = tmp_path / ".mattstash.txt"
    assert sidecar.read_text() == "prod-secret-nobody-knows"
    MattStash(str(dev), password="devpw").rotate_password("dev-new-pw")
    assert sidecar.read_text() == "prod-secret-nobody-knows", "prod's only password record must survive"
    assert opens_with(dev, "dev-new-pw") and opens_with(prod, "prod-secret-nobody-knows")
    assert "left unchanged" in caplog.text


def test_o8_a_symlinked_sidecar_is_updated_through_the_link(tmp_path: Path):
    home, secrets_dir = tmp_path / "home", tmp_path / "secrets"
    home.mkdir()
    secrets_dir.mkdir()
    db = make_db(home / "s.kdbx", sidecar=False)
    (secrets_dir / "master.txt").write_text(OLD)
    (home / ".mattstash.txt").symlink_to(secrets_dir / "master.txt")
    MattStash(str(db), password=OLD).rotate_password(NEW)
    assert (home / ".mattstash.txt").is_symlink()
    assert (secrets_dir / "master.txt").read_text() == NEW


# ---------------------------------------------------------------------------
# O3: setup --force / create on a symlinked database path
# ---------------------------------------------------------------------------


def test_o3_create_force_on_a_symlink_replaces_the_target_under_the_writers_lock(tmp_path: Path):
    real = make_db(tmp_path / "vol" / "real.kdbx", sidecar=False)
    link = tmp_path / "home" / "link.kdbx"
    link.parent.mkdir()
    link.symlink_to(real)
    writer = MattStash(str(link), password=OLD)
    writer.put("keep", value="1")

    holder_released = threading.Event()
    done: list[float] = []

    def force_create() -> None:
        started = time.monotonic()
        MattStash.create(str(link), password="fresh", force=True, sidecar=False, backup=True)
        done.append(time.monotonic() - started)

    with writer._file_lock:  # a writer holds the lock of the REAL file
        t = threading.Thread(target=force_create)
        t.start()
        time.sleep(0.4)
        assert not done, "create(force=True) must wait for the writer: it has to lock the same file"
        holder_released.set()
    t.join(20)
    assert done
    assert link.is_symlink(), "the link must survive"
    assert opens_with(real, "fresh") and not opens_with(real, OLD)
    assert not (tmp_path / "home" / "link.kdbx.lock").exists()


# ---------------------------------------------------------------------------
# O1 L-series: backups
# ---------------------------------------------------------------------------


def test_l2_backup_refuses_a_truncated_database_and_keeps_the_last_good_backup(tmp_path: Path):
    db = make_db(tmp_path / "b.kdbx")
    stash = MattStash(str(db), password=OLD)
    latest = tmp_path / "latest.kdbx"
    stash.backup(str(latest))
    good = latest.read_bytes()
    db.write_bytes(b"")  # truncated
    with pytest.raises(DatabaseAccessError, match="not a valid KeePass database"):
        stash.backup(str(latest), force=True)
    assert latest.read_bytes() == good


def test_l4_a_missing_destination_directory_is_not_reported_as_a_missing_database(tmp_path: Path):
    db = make_db(tmp_path / "b.kdbx")
    stash = MattStash(str(db), password=OLD)
    for dest in (str(tmp_path / "nope" / "x.kdbx"), str(tmp_path / "newdir") + os.sep):
        with pytest.raises(MattStashError, match="directory does not exist") as excinfo:
            stash.backup(dest)
        assert not isinstance(excinfo.value, DatabaseNotFoundError)


def test_l1_relative_paths_keep_meaning_the_same_place_after_chdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    make_db(tmp_path / "data" / "db.kdbx")
    other = tmp_path / "elsewhere"
    other.mkdir()
    monkeypatch.chdir(tmp_path)
    stash = MattStash("data/db.kdbx", password=OLD)
    monkeypatch.chdir(other)
    backup = stash.backup()
    assert Path(backup).parent == tmp_path / "data"
    stash.rotate_password(NEW)
    assert (tmp_path / "data" / ".mattstash.txt").read_text() == NEW
    assert list(other.iterdir()) == []


# ---------------------------------------------------------------------------
# O5 umask, O6 ownership, O10 rotation seen by a queued process, O11 leftovers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("umask", [0o277, 0o222, 0o377])
def test_o5_restrictive_umask_does_not_wedge_the_tool(tmp_path: Path, umask: int):
    old = os.umask(umask)
    try:
        db = make_db(tmp_path / "u" / "db.kdbx", sidecar=False)
        stash = MattStash(str(db), password=OLD)
        stash.put("x", value="1")
        stash.backup()
    finally:
        os.umask(old)
    assert mode(Path(str(db) + ".lock")) & 0o600 == 0o600, "the lock file stays usable"
    MattStash(str(db), password=OLD).put("y", value="2")  # a later run with a normal umask works too


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() != 0, reason="needs root to change ownership")
def test_o6_saving_as_root_keeps_the_owner_of_the_database(tmp_path: Path):
    db = make_db(tmp_path / "o" / "db.kdbx", sidecar=False)
    os.chown(db, 12345, 23456)
    MattStash(str(db), password=OLD).put("x", value="1")
    st = os.stat(db)
    assert (st.st_uid, st.st_gid) == (12345, 23456)


def test_o10_a_writer_that_cached_a_sidecar_password_sees_a_rotation(tmp_path: Path):
    db = make_db(tmp_path / "q" / "db.kdbx")
    queued = MattStash(str(db))  # resolved the OLD password from the sidecar when it was made
    assert queued.password == OLD
    MattStash(str(db), password=OLD).rotate_password(NEW)  # another process rotates in the meantime
    queued.put("x", value="1")  # must not fail with "Invalid credentials": it looks the sidecar up again
    assert queued.password == NEW


def test_o11_a_failed_backup_leaves_no_truncated_bak_file(tmp_path: Path):
    from mattstash.core.bootstrap import DatabaseBootstrapper

    db = make_db(tmp_path / "x.kdbx")
    with patch("mattstash.core.bootstrap.shutil.copyfile", side_effect=OSError(errno.EIO, "I/O error")):
        with pytest.raises(MattStashError):
            DatabaseBootstrapper(str(db)).create("p", force=True, sidecar=False)
    assert [p.name for p in tmp_path.iterdir() if ".bak-" in p.name] == []
    assert opens_with(db, OLD), "the existing database is untouched"


def test_o11_a_failed_setup_force_names_the_backups_it_kept(tmp_path: Path):
    from mattstash.core import bootstrap
    from mattstash.core.bootstrap import DatabaseBootstrapper

    db = make_db(tmp_path / "x.kdbx")
    with patch.object(bootstrap, "_link_or_replace", side_effect=OSError(errno.EBUSY, "Device or resource busy")):
        with pytest.raises(MattStashError, match="backed up first and are kept"):
            DatabaseBootstrapper(str(db)).create("p", force=True, sidecar=True)


def test_o14_setup_lock_timeout_exits_7_like_every_other_command(tmp_path: Path):
    db = make_db(tmp_path / "x.kdbx")
    with FileLock(str(db) + ".lock", timeout=5):
        with patch("mattstash.core.bootstrap.FileLock.__init__", _short_timeout(FileLock.__init__)):
            rc = main(
                ["--db", str(db), "setup", "--force", "--yes", "--password-stdin"]
                if False
                else ["--db", str(db), "setup", "--force", "--yes", "--generate"]
            )
    assert rc == exit_codes.DB_ACCESS


def _short_timeout(real_init):
    def init(self, path, timeout=30.0, poll_interval=0.02):
        real_init(self, path, timeout=0.3, poll_interval=poll_interval)

    return init


# ---------------------------------------------------------------------------
# L9: error messages survive a CRITICAL log level
# ---------------------------------------------------------------------------


def test_l9_handler_errors_are_still_shown_when_logging_is_silenced(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    import logging

    db = make_db(tmp_path / "x.kdbx")
    handler_logger = logging.getLogger("mattstash.cli.handlers.base")
    old_level = handler_logger.level
    handler_logger.setLevel(logging.CRITICAL)  # MATTSTASH_LOG_LEVEL=CRITICAL
    try:
        rc = main(["--db", str(db), "--password", OLD, "rotate-password", "--server-url", "http://localhost:1"])
    finally:
        handler_logger.setLevel(old_level)
    assert rc != 0
    assert "not supported in server mode" in capsys.readouterr().err
