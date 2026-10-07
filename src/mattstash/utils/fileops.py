"""
mattstash.utils.fileops
-----------------------
Small helpers for files that hold secrets: they are created ``0600`` from the first byte and are
published with an atomic rename, so a reader (or a crash) never sees a partial or world-readable file.
"""

import contextlib
import os
import secrets
import shutil
from typing import Optional

_CHUNK = 1024 * 1024


def _temp_name(path: str) -> str:
    return f"{path}.tmp-{os.getpid()}-{secrets.token_hex(4)}"


def discard(path: Optional[str]) -> None:
    """Remove ``path`` if it exists (used to clean up staged temp files)."""
    if path:
        with contextlib.suppress(OSError):
            os.remove(path)


def stage_private_file(path: str, data: bytes) -> str:
    """Write ``data`` to a new ``0600`` temp file next to ``path`` and return its name.

    Publish it with :func:`os.replace` (atomic) or throw it away with :func:`discard`.
    """
    tmp = _temp_name(path)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        discard(tmp)
        raise
    return tmp


def copy_private(src: str, dest: str, *, overwrite: bool = False) -> None:
    """Copy ``src`` to ``dest`` as a ``0600`` file, atomically.

    The data is written to a temp file beside ``dest`` and then renamed into place, so ``dest`` is
    either absent/unchanged or complete. Without ``overwrite`` an existing ``dest`` is never touched
    (``FileExistsError``): the temp file is hard-linked to ``dest``, which fails if it exists, so two
    racing callers cannot both succeed.
    """
    tmp = _temp_name(dest)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with open(src, "rb") as source, os.fdopen(fd, "wb") as target:
            shutil.copyfileobj(source, target, _CHUNK)
            target.flush()
            os.fsync(target.fileno())
        if overwrite:
            os.replace(tmp, dest)
            return
        try:
            os.link(tmp, dest)  # atomic "create only if absent"
        except FileExistsError:
            raise
        except OSError:
            # Filesystem without hard links: fall back to check-then-rename (small race window).
            if os.path.lexists(dest):
                raise FileExistsError(dest) from None
            os.replace(tmp, dest)
    finally:
        discard(tmp)
