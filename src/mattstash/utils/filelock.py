"""
mattstash.utils.filelock
------------------------
Small cross-process advisory lock used to serialise read-modify-write cycles on
the KDBX file (CLI + server, or several server processes sharing a volume).

POSIX uses ``flock`` (per open file description, so two ``FileLock`` objects in the
same process also exclude each other); Windows uses ``msvcrt.locking``. The lock is
advisory: it only protects against other MattStash writers.

Network filesystems (NFS/SMB) give weaker ``flock`` guarantees; run a single writer there.

A ``FileLock`` instance is re-entrant for the thread-level owner but is NOT itself
thread-safe; callers serialise access with a ``threading.RLock`` (MattStash does).
"""

import contextlib
import errno
import os
import stat
import sys
import time
import weakref
from types import TracebackType
from typing import Optional

from .exceptions import DatabaseLockError
from .fileops import match_owner

if sys.platform == "win32":  # pragma: no cover - exercised on Windows only
    import msvcrt

    def _try_lock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)

    def _unlock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)

else:
    import fcntl

    def _try_lock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)


# errno values meaning "somebody else holds the lock" (retry); anything else is a real failure (fail fast)
_CONTENTION = {errno.EAGAIN, errno.EACCES, errno.EWOULDBLOCK, errno.EDEADLK}
if sys.platform == "win32":  # pragma: no cover
    _CONTENTION.add(getattr(errno, "EDEADLOCK", errno.EDEADLK))


class FileLock:
    """Exclusive advisory lock on ``path`` (created with mode 0600 if missing).

    * **Fair enough.** Waiters poll; a writer that releases and immediately re-acquires would starve them
      (the free window is microseconds, a poll interval is milliseconds). Waiters therefore *touch* the lock file
      on every poll, and a holder that finds the file touched since it acquired the lock yields for one poll
      interval after releasing, so a waiting process gets the lock instead of being locked out indefinitely.
    * **Delete-safe.** If the lock file is removed or replaced while we wait, the lock we got is on an orphaned
      file that no later locker will see; it is detected after acquiring and the acquisition is retried.
    * **Umask-safe.** The file is made 0600 regardless of the umask (a 0400 lock file would block every later
      ``O_RDWR`` open); an existing read-only lock file is still usable (``flock`` needs no write access).
    * **Fork-safe.** A forked child never owns the parent's lock: it closes its copy of the descriptor without
      unlocking (unlocking would release the parent's lock too).
    """

    #: Every live lock, so the at-fork hook can reset them in a child process.
    _instances: "weakref.WeakSet[FileLock]" = weakref.WeakSet()

    def __init__(
        self, path: str, timeout: float = 30.0, poll_interval: float = 0.02, reference: Optional[str] = None
    ) -> None:
        self.path = path
        self.timeout = timeout
        self.poll_interval = poll_interval
        #: The file this lock protects (the database). A lock file this process creates gets its owner, group and
        #: group permissions, so a lock created by root (or by one member of a shared group) does not lock the
        #: service user out of the database it has every right to write.
        self.reference = reference
        self._fd: Optional[int] = None
        self._depth = 0
        self._acquired_ns = 0
        FileLock._instances.add(self)

    @property
    def held(self) -> bool:
        return self._depth > 0

    @property
    def depth(self) -> int:
        """How many times the current owner has acquired the lock (re-entrant)."""
        return self._depth

    def _open(self) -> int:
        try:
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        except PermissionError as exc:
            # e.g. a 0400 lock file left by a restrictive umask: flock does not need write access
            try:
                fd = os.open(self.path, os.O_RDONLY)
            except OSError:
                # Report the original problem (permission denied), not the fallback's "no such file".
                raise DatabaseLockError(f"Cannot create lock file {self.path}: {exc.strerror or exc}") from exc
        except OSError as exc:
            raise DatabaseLockError(f"Cannot create lock file {self.path}: {exc.strerror or exc}") from exc
        self._fix_ownership(fd)
        return fd

    def _fix_ownership(self, fd: int) -> None:
        """Make a lock file we own usable by everyone who may write the database (POSIX; best effort)."""
        if not (hasattr(os, "fchmod") and hasattr(os, "geteuid")):
            return
        with contextlib.suppress(OSError):
            st = os.fstat(fd)
            if st.st_uid != os.geteuid() and os.geteuid() != 0:
                return  # not ours to change
            wanted = stat.S_IMODE(st.st_mode) | 0o600
            if self.reference is not None:
                try:
                    ref = os.stat(self.reference)
                except OSError:
                    ref = None
                if ref is not None:
                    wanted |= stat.S_IMODE(ref.st_mode) & 0o060  # the database's group read/write bits
                    if (st.st_uid, st.st_gid) != (ref.st_uid, ref.st_gid):
                        match_owner(ref, self.path)
            if wanted != stat.S_IMODE(st.st_mode):
                os.fchmod(fd, wanted)

    def _is_current(self, fd: int) -> bool:
        """True if ``fd`` is still the file at ``self.path`` (it may have been deleted or replaced meanwhile)."""
        try:
            on_disk = os.stat(self.path)
        except OSError:
            return False
        held = os.fstat(fd)
        return (on_disk.st_ino, on_disk.st_dev) == (held.st_ino, held.st_dev)

    def check_current(self) -> None:
        """Raise ``DatabaseLockError`` if the lock file we hold was deleted or replaced while we held it.

        After that, a newcomer locks a *different* file and no longer excludes us: the caller must not go on to
        write (and silently overwrite someone else's update).
        """
        if self._fd is not None and not self._is_current(self._fd):
            raise DatabaseLockError(
                f"The lock file {self.path} was removed while it was held, so other writers are no longer excluded; "
                "nothing was saved. Retry the operation."
            )

    def acquire(self, timeout: Optional[float] = None, *, reported_timeout: Optional[float] = None) -> None:
        """Take the lock, waiting at most ``timeout`` seconds (default: the lock's own).

        ``reported_timeout`` is what a timeout error says was waited when the caller spent part of a larger
        budget elsewhere (it passes the remainder as ``timeout`` and the whole budget here).
        """
        if self._depth:
            self._depth += 1
            return
        wait = self.timeout if timeout is None else timeout
        shown = wait if reported_timeout is None else reported_timeout
        deadline = time.monotonic() + wait
        fd = self._open()
        try:
            while True:
                try:
                    _try_lock(fd)
                except OSError as exc:
                    if exc.errno not in _CONTENTION:
                        # e.g. ENOLCK on a network filesystem without locking: waiting will not help
                        raise DatabaseLockError(f"Cannot lock {self.path}: {exc.strerror or exc}") from exc
                    if time.monotonic() >= deadline:
                        raise DatabaseLockError(
                            f"Timed out after {shown:.0f}s waiting for another MattStash process to release {self.path}"
                        ) from exc
                    with contextlib.suppress(Exception):  # OSError, NotImplementedError, TypeError (Windows)
                        os.utime(fd, None)  # "somebody is waiting": the holder reads this when it releases
                    time.sleep(self.poll_interval)
                    continue
                if self._is_current(fd):
                    break
                # the lock file was deleted/replaced while we waited: our lock is on an orphan. Start over.
                with contextlib.suppress(OSError):
                    _unlock(fd)
                os.close(fd)
                fd = -1  # closed: the error path below must not close this number again (it may be reused)
                if time.monotonic() >= deadline:
                    raise DatabaseLockError(
                        f"Timed out after {shown:.0f}s: the lock file {self.path} kept being replaced while waiting"
                    )
                fd = self._open()
        except BaseException:
            if fd >= 0:
                with contextlib.suppress(OSError):
                    os.close(fd)
            raise
        self._fd = fd
        self._depth = 1
        self._acquired_ns = time.time_ns()

    def release(self) -> None:
        if not self._depth:
            return
        self._depth -= 1
        if self._depth:
            return
        fd, self._fd = self._fd, None
        if fd is None:
            return
        waiters = False
        with contextlib.suppress(OSError):
            waiters = os.fstat(fd).st_mtime_ns >= self._acquired_ns
        with contextlib.suppress(OSError):
            _unlock(fd)
        os.close(fd)
        if waiters:
            # Give a process that has been polling for this lock a chance to see it free (see the class docstring).
            time.sleep(self.poll_interval * 1.5)

    def _forget_after_fork(self) -> None:
        """In a forked child: drop the inherited descriptor *without* unlocking (that would unlock the parent)."""
        fd, self._fd, self._depth = self._fd, None, 0
        if fd is not None:
            with contextlib.suppress(OSError):
                os.close(fd)

    def __enter__(self) -> "FileLock":
        self.acquire()
        return self

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        self.release()


def _after_fork_in_child() -> None:  # pragma: no cover - runs only in a forked child
    for lock in list(FileLock._instances):
        lock._forget_after_fork()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)
