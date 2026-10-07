"""Tests for the cross-process advisory lock."""

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from mattstash.utils.exceptions import DatabaseLockError
from mattstash.utils.filelock import FileLock


def test_lock_file_is_private(tmp_path: Path):
    path = tmp_path / "x.lock"
    with FileLock(str(path)):
        assert oct(os.stat(path).st_mode & 0o777) == "0o600"


def test_two_locks_on_the_same_file_exclude_each_other(tmp_path: Path):
    path = str(tmp_path / "x.lock")
    with FileLock(path):
        with pytest.raises(DatabaseLockError, match="Timed out"):
            FileLock(path, timeout=0.2).acquire()
    FileLock(path, timeout=0.2).acquire()  # free again after release


def test_lock_is_reentrant_for_the_same_object(tmp_path: Path):
    lock = FileLock(str(tmp_path / "x.lock"))
    lock.acquire()
    lock.acquire()
    lock.release()
    # still held: another object cannot take it
    with pytest.raises(DatabaseLockError):
        FileLock(str(tmp_path / "x.lock"), timeout=0.1).acquire()
    lock.release()
    FileLock(str(tmp_path / "x.lock"), timeout=0.1).acquire()


def test_release_without_acquire_is_harmless(tmp_path: Path):
    FileLock(str(tmp_path / "x.lock")).release()


def test_unwritable_location_is_a_lock_error(tmp_path: Path):
    with pytest.raises(DatabaseLockError, match="Cannot create lock file"):
        FileLock(str(tmp_path / "missing-dir" / "x.lock")).acquire()


def test_lock_is_released_when_the_holder_process_dies(tmp_path: Path):
    path = str(tmp_path / "x.lock")
    holder = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import sys,time; from mattstash.utils.filelock import FileLock;"
            "l=FileLock(sys.argv[1]); l.acquire(); print('held', flush=True); time.sleep(60)",
            path,
        ],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert holder.stdout.readline().strip() == "held"
        with pytest.raises(DatabaseLockError):
            FileLock(path, timeout=0.2).acquire()
        holder.kill()
        holder.wait(timeout=10)
        deadline = time.monotonic() + 5
        FileLock(path, timeout=5).acquire()  # a crashed writer must not wedge the database
        assert time.monotonic() < deadline
    finally:
        holder.kill()
