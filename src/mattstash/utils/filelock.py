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
import sys
import time
from types import TracebackType
from typing import Optional

from .exceptions import DatabaseLockError

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
    """Exclusive advisory lock on ``path`` (created with mode 0600 if missing)."""

    def __init__(self, path: str, timeout: float = 30.0, poll_interval: float = 0.05) -> None:
        self.path = path
        self.timeout = timeout
        self.poll_interval = poll_interval
        self._fd: Optional[int] = None
        self._depth = 0

    def acquire(self) -> None:
        if self._depth:
            self._depth += 1
            return
        try:
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        except OSError as exc:
            raise DatabaseLockError(f"Cannot create lock file {self.path}: {exc.strerror or exc}") from exc

        deadline = time.monotonic() + self.timeout
        while True:
            try:
                _try_lock(fd)
                break
            except OSError as exc:
                if exc.errno not in _CONTENTION:
                    # e.g. ENOLCK on a network filesystem without locking: waiting will not help
                    os.close(fd)
                    raise DatabaseLockError(f"Cannot lock {self.path}: {exc.strerror or exc}") from exc
                if time.monotonic() >= deadline:
                    os.close(fd)
                    raise DatabaseLockError(
                        f"Timed out after {self.timeout:.0f}s waiting for another MattStash "
                        f"process to release {self.path}"
                    ) from exc
                time.sleep(self.poll_interval)
        self._fd = fd
        self._depth = 1

    def release(self) -> None:
        if not self._depth:
            return
        self._depth -= 1
        if self._depth:
            return
        fd, self._fd = self._fd, None
        if fd is not None:
            with contextlib.suppress(OSError):
                _unlock(fd)
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
