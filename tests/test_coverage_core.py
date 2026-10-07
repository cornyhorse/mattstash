"""Line-coverage tests for the core package, the credential store and the small utility modules.

Every test here exercises a branch that the behavioural suites do not reach: error paths of the file lock, the
bootstrapper and the store, the legacy helpers of the entry manager, the validation limits and so on. Races and
failures that cannot be provoked on demand (a database that vanishes while a lock is being taken, a symlink that is
flipped mid-write, a lock file that cannot be opened for writing) are provoked by wrapping the one primitive involved,
so the tests are deterministic and behave the same for root and for an unprivileged user.
"""

import errno
import importlib
import importlib.metadata
import logging
import os
import stat
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from dbhelpers import create_db, populate
from pykeepass import PyKeePass

import mattstash
from mattstash import MattStash, list_creds, list_versions, prune
from mattstash.core import bootstrap
from mattstash.core.bootstrap import DatabaseBootstrapper, _link_or_replace, _makedirs_private
from mattstash.core.entry_manager import EntryManager
from mattstash.credential_store import CredentialStore
from mattstash.utils import filelock
from mattstash.utils.exceptions import (
    DatabaseAccessError,
    DatabaseLockError,
    DatabaseNotFoundError,
    InvalidCredentialError,
    MattStashError,
    RekeyVerifyError,
)
from mattstash.utils.filelock import FileLock
from mattstash.utils.fileops import match_owner
from mattstash.utils.validation import (
    sanitize_error_message,
    validate_credential_title,
    validate_notes,
    validate_url,
    validate_username,
)
from mattstash.version_manager import VersionManager, parse_version_suffix

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


def write_sidecar(db: Path, password: str) -> None:
    sidecar = db.parent / ".mattstash.txt"
    sidecar.write_text(password)
    sidecar.chmod(0o600)


# ---------------------------------------------------------------------------
# entry_manager
# ---------------------------------------------------------------------------


def test_an_entry_without_a_title_is_skipped_by_lookups_and_does_not_break_writes(tmp_path: Path):
    db = create_db(
        tmp_path / "db.kdbx",
        [{"title": "", "password": "orphan"}, {"title": "k@0000000001", "password": "v1"}],
        password=OLD,
    )
    assert PyKeePass(str(db), password=OLD).entries[0].title is None, "the fixture must hold a title-less entry"
    stash = MattStash(str(db), password=OLD)

    found = stash.get("k", show_password=True)
    assert isinstance(found, dict) and found["value"] == "v1"
    assert stash.list_versions("k") == ["0000000001"]
    stash.put("k", value="v2")
    assert stash.list_versions("k") == ["0000000001", "0000000002"]
    assert "orphan" not in str(stash.list(latest_only=True))  # nothing is listed under a made-up name


def test_putting_a_simple_secret_with_an_empty_tag_list_still_uses_the_simple_form(tmp_path: Path):
    db = make_db(tmp_path / "db.kdbx", sidecar=False)
    stash = MattStash(str(db), password=OLD)
    stash.put("s", username="u", password="p", autoincrement=False)

    stored = stash.put("s", value="plain", tags=[], autoincrement=False)  # tags=[] does not make it a full credential

    assert isinstance(stored, dict) and stored["value"] == "*****"
    entry = PyKeePass(str(db), password=OLD).find_entries(title="s", first=True)
    assert entry is not None and entry.password == "plain" and not entry.username and not entry.tags


def test_putting_a_full_credential_with_tags_stores_them(tmp_path: Path):
    db = make_db(tmp_path / "db.kdbx", sidecar=False)
    stash = MattStash(str(db), password=OLD)

    stored = stash.put("svc", username="u", password="p", tags=["prod", "db"])

    assert stored is not None and not isinstance(stored, dict)
    assert (stored.username, stored.version) == ("u", "0000000001")
    assert sorted(stored.tags) == ["db", "prod"], "the returned credential carries the tags"
    reread = stash.get("svc", show_password=True)
    assert reread is not None and not isinstance(reread, dict) and reread.password == "p"
    assert sorted(reread.tags) == ["db", "prod"], "and so does a fresh read"
    on_disk = PyKeePass(str(db), password=OLD).find_entries(title="svc@0000000001", first=True)
    assert on_disk is not None and sorted(on_disk.tags) == ["db", "prod"], "and so does the file"

    stash.put("svc", username="u", password="p2", tags=[])  # a new version without tags
    latest = stash.get("svc")
    assert latest is not None and not isinstance(latest, dict) and latest.tags == []


class _LegacyEntry:
    """An entry whose ``tags`` cannot be assigned (very old pykeepass): only add_tag/remove_tag work."""

    def __init__(self, tags: list[str]) -> None:
        self._tags = list(tags)

    @property
    def tags(self) -> list[str]:
        return list(self._tags)

    @tags.setter
    def tags(self, value: object) -> None:
        raise AttributeError("tags cannot be assigned")

    def remove_tag(self, tag: str) -> None:
        if tag == "stubborn":
            raise ValueError("cannot be removed")
        self._tags.remove(tag)

    def add_tag(self, tag: str) -> None:
        if tag == "refused":
            raise ValueError("cannot be added")
        self._tags.append(tag)


def test_tags_fall_back_to_add_and_remove_when_the_attribute_is_read_only():
    entry = _LegacyEntry(["old", "stubborn"])

    EntryManager(MagicMock())._set_entry_tags(entry, ["new", "refused", "extra"])  # type: ignore[arg-type]

    # "old" was removed, "stubborn" and "refused" failed individually without stopping the rest
    assert entry.tags == ["stubborn", "new", "extra"]


# ---------------------------------------------------------------------------
# core.mattstash
# ---------------------------------------------------------------------------


def test_open_keeps_its_password_when_the_refreshed_one_does_not_open_the_database_either(tmp_path: Path):
    db = make_db(tmp_path / "db.kdbx")
    write_sidecar(db, "wrong-one")
    stash = MattStash(str(db))  # the password comes from the sidecar
    assert stash.password == "wrong-one"
    write_sidecar(db, "wrong-two")  # "rotated" to another password that does not open the database either

    with pytest.raises(DatabaseAccessError):
        stash.get("a")

    assert stash.password == "wrong-one", "a candidate that does not open the database is not adopted"
    write_sidecar(db, OLD)  # the operator fixes the sidecar: the very same instance recovers
    found = stash.get("a", show_password=True)
    assert isinstance(found, dict) and found["value"] == "a-secret" and stash.password == OLD


def test_a_writer_gives_up_when_the_path_keeps_changing_and_its_time_is_up(tmp_path: Path):
    make_db(tmp_path / "v1" / "db.kdbx", title="one")
    make_db(tmp_path / "v2" / "db.kdbx", title="two")
    current = tmp_path / "current"
    current.symlink_to("v1")
    stash = MattStash(str(current / "db.kdbx"), password=OLD, lock_timeout=0)  # no time at all to retry
    real_acquire = FileLock.acquire

    def acquire_then_flip(self: FileLock, *args: object, **kwargs: object) -> None:
        real_acquire(self, *args, **kwargs)  # type: ignore[arg-type]
        if current.readlink() == Path("v1"):
            current.unlink()
            current.symlink_to("v2")  # retargeted while the (old) lock was being taken

    with patch.object(FileLock, "acquire", acquire_then_flip):
        with pytest.raises(DatabaseLockError, match="kept changing"):
            stash.put("late", value="x")

    for name in ("v1", "v2"):
        assert MattStash(str(tmp_path / name / "db.kdbx"), password=OLD).get("late") is None


def test_backup_reports_a_database_that_disappears_while_the_lock_is_being_taken(tmp_path: Path):
    db = make_db(tmp_path / "db.kdbx")
    stash = MattStash(str(db), password=OLD)
    real_acquire = FileLock.acquire

    def acquire_then_remove_database(self: FileLock, *args: object, **kwargs: object) -> None:
        real_acquire(self, *args, **kwargs)  # type: ignore[arg-type]
        os.remove(db)

    with patch.object(FileLock, "acquire", acquire_then_remove_database):
        with pytest.raises(DatabaseNotFoundError):
            stash.backup()

    assert not list(tmp_path.glob("*.bak-*")), "no backup of nothing"


def test_backup_reports_a_database_file_that_cannot_be_read(tmp_path: Path):
    unreadable = tmp_path / "dir.kdbx"
    unreadable.mkdir()  # exists, but is not a file that can be read (the same for root and for everyone else)
    stash = MattStash(str(unreadable), password=OLD)

    with pytest.raises(DatabaseAccessError, match="Cannot read the database file"):
        stash.backup()

    assert not list(tmp_path.glob("*.bak-*"))


def test_rotate_reports_the_original_error_and_keeps_the_staged_password_when_the_outcome_is_unknown(tmp_path: Path):
    db = make_db(tmp_path / "db.kdbx")  # with a sidecar, so a staged copy of the new password exists
    stash = MattStash(str(db), password=OLD)

    def change_then_lose_sight_of_the_file(store: CredentialStore, new_password: str) -> None:
        def cannot_tell() -> None:
            raise DatabaseAccessError("Cannot read the database file: too many open files")

        store._current_signature = cannot_tell  # type: ignore[method-assign]
        raise RuntimeError("interrupted")

    with patch.object(
        CredentialStore, "change_password", autospec=True, side_effect=change_then_lose_sight_of_the_file
    ):
        with pytest.raises(RuntimeError, match="interrupted") as info:
            stash.rotate_password(NEW)

    assert info.value.__suppress_context__, "the original error is reported, not the one raised while investigating"
    assert (tmp_path / ".mattstash.txt").read_text() == OLD
    staged = list(tmp_path.glob(".mattstash.txt.tmp-*"))
    assert len(staged) == 1 and staged[0].read_text() == NEW, "unknown outcome: the staged password is kept"
    assert opens_with(db, OLD) and stash.password == OLD


def test_an_interrupt_after_the_rekey_is_reported_as_a_rekey_with_the_backup_named(tmp_path: Path):
    db = make_db(tmp_path / "db.kdbx", sidecar=False)
    stash = MattStash(str(db), password=OLD)

    def interrupted() -> None:
        raise KeyboardInterrupt  # not an Exception: the announcement helper lets it through

    with pytest.raises(RekeyVerifyError, match="NEW password is in effect") as info:
        stash.rotate_password(NEW, backup=True, on_rekeyed=interrupted)

    assert isinstance(info.value.__cause__, KeyboardInterrupt)
    backup_path = info.value.backup_path
    assert backup_path is not None and opens_with(Path(backup_path), OLD), "the pre-rotation copy is named"
    assert opens_with(db, NEW) and not opens_with(db, OLD)
    assert stash.password == NEW


def test_reload_of_an_instance_that_never_opened_a_missing_database_reports_false(missing_db: Path):
    assert MattStash(str(missing_db), password=OLD).reload() is False


def test_hydrate_env_skips_variables_that_are_set_and_keys_without_a_field(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
):
    db = create_db(
        tmp_path / "db.kdbx",
        [{"title": "svc", "username": "user", "password": "pw", "props": {"region": "eu"}}],
        password=OLD,
    )
    monkeypatch.setenv("ALREADY_SET", "keep-me")
    monkeypatch.setenv("NEVER_SET", "")  # registered, so the environment is restored afterwards
    monkeypatch.setenv("HYDRATED_REGION", "")
    stash = MattStash(str(db), password=OLD)

    with caplog.at_level(logging.WARNING, logger="mattstash.core.mattstash"):
        stash.hydrate_env(
            {
                "svc:AWS_ACCESS_KEY_ID": "ALREADY_SET",  # the variable is already set: left alone
                "no-colon": "NEVER_SET",  # not Title:FIELD: warned about and skipped
                "svc:region": "HYDRATED_REGION",  # processing goes on after both
            }
        )

    assert os.environ["ALREADY_SET"] == "keep-me"
    assert os.environ["NEVER_SET"] == ""
    assert os.environ["HYDRATED_REGION"] == "eu"
    assert "Invalid mapping key 'no-colon'" in caplog.text


# ---------------------------------------------------------------------------
# credential_store
# ---------------------------------------------------------------------------


def test_save_recreates_a_database_that_was_deleted_after_it_was_opened(tmp_path: Path):
    db = make_db(tmp_path / "db.kdbx", sidecar=False)
    store = CredentialStore(str(db), OLD)
    store.open()
    os.remove(db)

    store.save()  # nothing to take the mode or owner from: a private file is written

    assert db.exists() and mode(db) == 0o600 and opens_with(db, OLD)
    assert not store.has_file_changed()


def test_an_interrupted_save_removes_its_temporary_files(tmp_path: Path):
    db = make_db(tmp_path / "db.kdbx", sidecar=False)
    before, listing = db.read_bytes(), sorted(p.name for p in tmp_path.iterdir())
    store = CredentialStore(str(db), OLD)
    kp = store.open()
    assert kp is not None

    with patch.object(kp, "save", side_effect=KeyboardInterrupt):
        with pytest.raises(KeyboardInterrupt):
            store.save()

    assert sorted(p.name for p in tmp_path.iterdir()) == listing, "no staged or pykeepass temp file is left"
    assert db.read_bytes() == before


def test_store_helpers_cope_with_open_returning_nothing(tmp_path: Path):
    db = make_db(tmp_path / "db.kdbx", sidecar=False)
    store = CredentialStore(str(db), OLD)

    with patch.object(store, "open", return_value=None):
        assert store.find_entry_by_title("a") is None
        assert store.find_entries_by_prefix("a") == []
        with pytest.raises(DatabaseAccessError, match="Unable to open"):
            store.create_entry("new")
        assert store.delete_entry(MagicMock()) is False
        assert store.get_all_entries() == []


# ---------------------------------------------------------------------------
# core.bootstrap
# ---------------------------------------------------------------------------


def test_makedirs_private_stops_at_the_top_of_the_file_system():
    made: list[str] = []
    target = os.path.abspath(os.path.join(os.sep, "no-such-top", "a", "b"))

    with (
        patch("os.path.isdir", return_value=False),  # nothing exists, not even the root
        patch("os.makedirs", side_effect=lambda directory, **kwargs: made.append(directory)),
        patch("os.chmod"),
    ):
        _makedirs_private(target)

    assert made[0] == os.path.abspath(os.sep) and made[-1] == target, "created from the top down, and the walk ended"
    assert len(made) == 4


def test_link_or_replace_without_hard_links_refuses_an_existing_target_and_replaces_nothing(tmp_path: Path):
    src, existing, absent = tmp_path / "src", tmp_path / "existing", tmp_path / "absent"
    src.write_text("new")
    existing.write_text("old")

    with patch("os.link", side_effect=OSError(errno.EPERM, "hard links are not supported")):
        with pytest.raises(FileExistsError):
            _link_or_replace(str(src), str(existing), replace=False)
        assert existing.read_text() == "old" and src.exists()

        _link_or_replace(str(src), str(absent), replace=False)  # nothing in the way: renamed instead

    assert absent.read_text() == "new" and not src.exists()


def test_create_reports_a_directory_that_cannot_be_created(tmp_path: Path):
    blocker = tmp_path / "blocker"
    blocker.write_text("a file where a directory is needed")

    with pytest.raises(MattStashError, match="Cannot create the directory"):
        DatabaseBootstrapper(str(blocker / "sub" / "db.kdbx")).create(OLD, sidecar=True)

    assert blocker.read_text() == "a file where a directory is needed"


def test_a_failed_database_swap_removes_the_sidecar_it_just_installed_when_there_was_none_before(tmp_path: Path):
    db = tmp_path / "db.kdbx"
    real_link_or_replace = bootstrap._link_or_replace

    def fail_for_the_database(src: str, dst: str, *, replace: bool) -> None:
        if os.path.realpath(dst) == os.path.realpath(db):
            raise OSError(errno.EIO, "Input/output error")
        real_link_or_replace(src, dst, replace=replace)

    with patch.object(bootstrap, "_link_or_replace", side_effect=fail_for_the_database):
        with pytest.raises(MattStashError, match="Failed to install the new database"):
            DatabaseBootstrapper(str(db)).create(OLD, sidecar=True)

    # no database, no sidecar for a database that does not exist, no staging leftovers (only the lock file remains)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["db.kdbx.lock"]


# ---------------------------------------------------------------------------
# utils.filelock
# ---------------------------------------------------------------------------


def _deny_write_access(deny: Path):
    """An ``os.open`` replacement that refuses to open ``deny`` for writing (as a 0400 file does for a normal user)."""
    real_open = os.open

    def fake_open(path, flags, *args, **kwargs):  # type: ignore[no-untyped-def]
        if os.fspath(path) == str(deny) and flags & os.O_RDWR:
            raise PermissionError(errno.EACCES, "Permission denied", str(path))
        return real_open(path, flags, *args, **kwargs)

    return fake_open


def test_a_lock_file_that_cannot_be_opened_for_writing_is_locked_read_only_and_made_usable(tmp_path: Path):
    path = tmp_path / "x.lock"
    path.touch()
    path.chmod(0o400)
    lock = FileLock(str(path), timeout=0)

    with patch("os.open", side_effect=_deny_write_access(path)):
        lock.acquire()

    assert lock.held
    lock.release()
    assert mode(path) == 0o600, "a read-only lock file we own is repaired so later writers can open it"


def test_a_lock_file_that_can_be_neither_opened_for_writing_nor_read_reports_the_permission_error(tmp_path: Path):
    path = tmp_path / "absent.lock"  # the read-only fallback fails with "no such file"; that is not what is reported
    lock = FileLock(str(path), timeout=0)

    with patch("os.open", side_effect=_deny_write_access(path)):
        with pytest.raises(DatabaseLockError, match="Cannot create lock file") as info:
            lock.acquire()

    assert "Permission denied" in str(info.value) and "No such file" not in str(info.value)
    assert not lock.held and not path.exists()


def test_the_lock_file_mode_is_left_alone_on_a_platform_without_fchmod(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    path = tmp_path / "x.lock"
    path.touch()
    path.chmod(0o400)
    lock = FileLock(str(path), timeout=0)

    with monkeypatch.context() as scoped:
        scoped.delattr(os, "fchmod")
        with patch("os.open", side_effect=_deny_write_access(path)):
            lock.acquire()

    assert lock.held and mode(path) == 0o400
    lock.release()


def test_a_lock_file_owned_by_someone_else_is_not_modified(tmp_path: Path):
    path = tmp_path / "x.lock"
    path.touch()
    path.chmod(0o400)
    someone_else = os.stat(path).st_uid + 4242  # neither the owner nor root
    lock = FileLock(str(path), timeout=0)

    with patch.object(os, "geteuid", return_value=someone_else), patch("os.open", side_effect=_deny_write_access(path)):
        lock.acquire()

    assert lock.held and mode(path) == 0o400, "not ours to change"
    lock.release()


def test_a_new_lock_file_takes_the_owner_of_a_reference_file_that_has_another(tmp_path: Path):
    """Run as root (the usual case for the ownership fix) the lock file really changes hands; unprivileged, the owner
    can only be compared, so the reference is made to *look* like it belongs to someone else."""
    reference = tmp_path / "db.kdbx"
    reference.touch()
    reference.chmod(0o660)
    real = os.stat(reference)
    other = SimpleNamespace(st_uid=real.st_uid + 1, st_gid=real.st_gid + 1, st_mode=real.st_mode)
    real_stat = os.stat

    def stat_with_another_owner(path, *args, **kwargs):
        return other if str(path) == str(reference) else real_stat(path, *args, **kwargs)

    lock = FileLock(str(tmp_path / "db.kdbx.lock"), timeout=0, reference=str(reference))
    with patch("mattstash.utils.filelock.os.stat", stat_with_another_owner):
        with patch("mattstash.utils.filelock.match_owner") as hand_over:
            lock.acquire()

    assert lock.held
    hand_over.assert_called_once_with(other, str(tmp_path / "db.kdbx.lock"))
    assert mode(tmp_path / "db.kdbx.lock") == 0o660, "the database's group read/write bits are shared with the lock"
    lock.release()


def test_a_reference_file_that_does_not_exist_is_ignored(tmp_path: Path):
    path = tmp_path / "x.lock"
    lock = FileLock(str(path), timeout=0, reference=str(tmp_path / "no-such-database.kdbx"))

    lock.acquire()

    assert lock.held and mode(path) == 0o600
    lock.release()


def test_acquire_times_out_when_the_lock_file_is_replaced_and_there_is_no_time_left(tmp_path: Path):
    path = tmp_path / "x.lock"
    real_try_lock = filelock._try_lock

    def lock_then_delete_the_file(fd: int) -> None:
        real_try_lock(fd)
        os.unlink(path)  # the lock we just got is on an orphan

    lock = FileLock(str(path), timeout=0)
    with patch.object(filelock, "_try_lock", side_effect=lock_then_delete_the_file):
        with pytest.raises(DatabaseLockError, match="kept being replaced"):
            lock.acquire()

    assert not lock.held and lock._fd is None


def test_releasing_a_lock_that_has_no_descriptor_just_resets_it(tmp_path: Path):
    lock = FileLock(str(tmp_path / "x.lock"))
    lock._depth = 1  # a state the public API never produces: owned, but without a descriptor

    lock.release()

    assert not lock.held and lock.depth == 0


def test_a_forked_childs_copy_is_closed_without_unlocking_the_parents_lock(tmp_path: Path):
    path = tmp_path / "x.lock"
    lock = FileLock(str(path), timeout=0)
    lock.acquire()
    assert lock._fd is not None
    inherited = os.dup(lock._fd)  # the parent's descriptor: same open file description, so the same flock
    other = FileLock(str(path), timeout=0)
    try:
        lock._forget_after_fork()

        assert not lock.held and lock._fd is None
        with pytest.raises(DatabaseLockError, match="Timed out"):
            other.acquire()  # an explicit unlock would have released the parent's lock too
    finally:
        os.close(inherited)

    other.acquire()  # the parent's descriptor is gone: the lock is free
    assert other.held
    other.release()
    FileLock(str(tmp_path / "never-held.lock"))._forget_after_fork()  # nothing to close is fine too


# ---------------------------------------------------------------------------
# utils.fileops
# ---------------------------------------------------------------------------


def test_match_owner_only_tries_to_keep_the_group_when_not_root(tmp_path: Path):
    reference = os.stat(tmp_path)
    calls: list[tuple[str, int, int]] = []

    def record(path: str, uid: int, gid: int) -> None:
        calls.append((path, uid, gid))

    with patch.object(os, "chown", side_effect=record):
        with patch.object(os, "geteuid", return_value=1000):
            match_owner(reference, "target")
        with patch.object(os, "geteuid", return_value=0):
            match_owner(reference, "target")

    assert calls == [("target", -1, reference.st_gid), ("target", reference.st_uid, reference.st_gid)]


# ---------------------------------------------------------------------------
# utils.validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("title", "message"),
    [
        ("", "cannot be empty"),
        ("   ", "cannot be empty"),
        ("t" * 256, "too long"),
        (".hidden", "cannot start with"),
        ("a\\b", "invalid character"),
        ("a\x00b", "invalid character"),
        ("a\nb", "invalid character"),
    ],
)
def test_invalid_credential_titles_are_refused(title: str, message: str):
    with pytest.raises(InvalidCredentialError, match=message):
        validate_credential_title(title)


@pytest.mark.parametrize("title", ["cloud/hetzner/s3-key", "myapp/db-password", "a/b", "trailing/"])
def test_forward_slashes_are_allowed_in_titles_as_namespace_separators(title: str):
    validate_credential_title(title)  # PR #16: "/" is no longer rejected


def test_a_credential_title_at_the_limit_is_accepted():
    validate_credential_title("t" * 255)


def test_username_url_and_notes_limits():
    validate_username("u" * 255)
    validate_url("")
    validate_url("   ")
    validate_notes("n" * 65535)

    with pytest.raises(InvalidCredentialError, match="Username too long"):
        validate_username("u" * 256)
    with pytest.raises(InvalidCredentialError, match="URL too long"):
        validate_url("http://" + "a" * 2048)
    with pytest.raises(InvalidCredentialError, match="Notes too long"):
        validate_notes("n" * 65536)


@pytest.mark.parametrize("char", ["\0", "\n", "\r", "\t"])
def test_a_url_with_a_control_character_is_refused(char: str):
    with pytest.raises(InvalidCredentialError, match="URL contains invalid character"):
        validate_url(f"http://exa{char}mple.com")


def test_sanitize_error_message_hides_the_home_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "home" / "alice"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))  # what expanduser uses on Windows

    message = sanitize_error_message(RuntimeError(f"cannot read {home}/notes.txt"))

    assert message == "cannot read ~/notes.txt"


# ---------------------------------------------------------------------------
# version_manager
# ---------------------------------------------------------------------------


def test_parse_version_suffix_of_a_missing_title_is_none():
    assert parse_version_suffix(None, "base") is None
    assert parse_version_suffix("", "base") is None
    assert parse_version_suffix("base@0000000007", "base") == 7


def test_parse_version_splits_on_the_last_at_sign():
    manager = VersionManager()
    assert manager.parse_version("user@host@0000000002") == ("user@host", 2)
    assert manager.parse_version("user@host") == ("user@host", None)
    assert manager.parse_version("plain") == ("plain", None)


# ---------------------------------------------------------------------------
# module_functions and the package itself
# ---------------------------------------------------------------------------


def test_module_level_list_creds_and_prune(tmp_path: Path):
    db = tmp_path / "db.kdbx"
    create_db(db, [], password=OLD)
    populate(
        db,
        OLD,
        [{"title": f"app@{n:010d}", "password": f"v{n}"} for n in (1, 2, 3)] + [{"title": "other", "password": "o"}],
    )

    listed = list_creds(path=str(db), password=OLD)
    assert sorted(c.credential_name for c in listed) == ["app@0000000001", "app@0000000002", "app@0000000003", "other"]

    assert prune("app", 1) == ["0000000001", "0000000002"]  # the shared default instance now points at ``db``
    assert list_versions("app") == ["0000000003"]


def test_the_version_falls_back_to_a_placeholder_when_the_package_is_not_installed():
    installed = mattstash.__version__
    try:
        with patch("importlib.metadata.version", side_effect=importlib.metadata.PackageNotFoundError("mattstash")):
            importlib.reload(mattstash)
        assert mattstash.__version__ == "0.0.0"
    finally:
        importlib.reload(mattstash)  # put the real version (and every other name) back for the other tests
    assert mattstash.__version__ == installed
    assert mattstash.MattStash is MattStash
