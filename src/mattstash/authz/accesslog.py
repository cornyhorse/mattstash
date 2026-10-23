"""The structured access log: one JSON object per line (design section 6).

Writing is the server's job (a ``RotatingFileHandler``); this module formats a record safely and reads the files
back for ``mattstash admin log`` and ``GET /admin/access-log``. Values are never logged, only names and decisions.
"""

import json
import math
import re
from collections import deque
from collections.abc import Iterator, Mapping
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Optional

MAX_VALUE_LENGTH = 256
#: Records with an ``event`` field are about the log itself, not a request: ``access-log-probe`` (written by the
#: readiness probe of a failing file) and ``access-log-gap`` (``lost`` request lines the file missed). They have no
#: principal, action or key; readers should label them, not show an empty row.
PROBE_EVENT = "access-log-probe"
GAP_EVENT = "access-log-gap"
#: Leading fields, in this order; any other field follows in the order given.
FIELD_ORDER = (
    "ts",
    "principal",
    "kind",
    "token",
    "action",
    "route",
    "key",
    "decision",
    "reason",
    "grant",
    "client",
    "status",
    "count",
)

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_UNPRINTABLE = "<unprintable>"
_INT_TOO_LARGE = "<int too large>"
#: Longer lines are skipped without being read into memory (a record is a few hundred bytes).
MAX_LINE_BYTES = 64 * 1024


def printable(value: object) -> str:
    """``value`` as ASCII with control characters and non-ASCII escaped, so a client can't forge log lines.

    Same rule as ``server/app/logsafe.py``: ``\\n`` becomes ``\\x0a``, a non-ASCII character a ``\\u`` escape (one
    beyond U+FFFF a ``\\U`` escape). Never raises: a value whose ``str()`` fails becomes ``<unprintable>``.
    """
    try:
        text = str(value)
    except Exception:  # an int above the digit limit, a broken __str__: log a placeholder, not a crash
        return _UNPRINTABLE
    text = text.encode("ascii", "backslashreplace").decode("ascii")
    return _CONTROL.sub(lambda match: f"\\x{ord(match.group()):02x}", text)


def _clean(value: object) -> object:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        try:
            str(value)
        except ValueError:  # more digits than Python converts
            return _INT_TOO_LARGE
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else printable(value)  # "nan", "inf": JSON has no such numbers
    return printable(value)[:MAX_VALUE_LENGTH]


def _unique(name: str, taken: set[str]) -> str:
    """``name``, or ``name_2``, ``name_3``... (cut so the whole stays within the length bound) if already taken."""
    candidate, number = name, 1
    while candidate in taken:
        number += 1
        suffix = f"_{number}"
        candidate = name[: MAX_VALUE_LENGTH - len(suffix)] + suffix
    taken.add(candidate)
    return candidate


def format_record(record: Mapping[str, object]) -> str:
    """One JSON line (no newline inside it, none at the end). ``None`` values are dropped. Never raises.

    Values are cleaned (see :func:`printable`); non-finite floats become the strings ``"nan"``/``"inf"``, integers
    too large to print become ``"<int too large>"``. Field names are cleaned the same way; if two names clean to
    the same text, the first keeps it and the later ones get ``_2``, ``_3``... so no field is silently lost.
    """
    ordered = [name for name in FIELD_ORDER if name in record]
    ordered += [name for name in record if name not in FIELD_ORDER]
    taken: set[str] = set()
    cleaned = {
        _unique(printable(name)[:MAX_VALUE_LENGTH], taken): _clean(record[name])
        for name in ordered
        if record[name] is not None
    }
    return json.dumps(cleaned, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def now_iso() -> str:
    """The current UTC time as ``2026-10-18T12:03:44.120Z``."""
    return datetime.now(UTC).isoformat(timespec="milliseconds").removesuffix("+00:00") + "Z"


def _parse_ts(value: object) -> Optional[datetime]:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.utcoffset() is not None else parsed.replace(tzinfo=UTC)


def _log_files(path: Path) -> list[Path]:
    """Oldest first: ``path.N`` ... ``path.1`` (the handler numbers backups from the newest), then ``path``."""
    backups: list[tuple[int, Path]] = []
    with suppress(OSError):  # an unreadable directory: only the main file can be tried
        if path.parent.is_dir():
            for candidate in path.parent.iterdir():
                suffix = candidate.name[len(path.name) + 1 :]
                if candidate.name.startswith(path.name + ".") and suffix.isascii() and suffix.isdigit():
                    backups.append((int(suffix), candidate))
    return [candidate for _, candidate in sorted(backups, reverse=True)] + [path]


def _lines(file: Path) -> Iterator[bytes]:
    """The lines of ``file`` of at most ``MAX_LINE_BYTES``; longer ones are skipped without being held in memory."""
    with open(file, "rb") as handle:
        while True:
            line = handle.readline(MAX_LINE_BYTES + 1)
            if not line:
                return
            if len(line) > MAX_LINE_BYTES and not line.endswith(b"\n"):
                while line and not line.endswith(b"\n"):  # discard the rest of the overlong line, a piece at a time
                    line = handle.readline(MAX_LINE_BYTES)
                continue
            yield line


def read_records(
    path: "str | Path",
    *,
    principal: Optional[str] = None,
    decision: Optional[str] = None,
    since: Optional[datetime] = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """The last ``limit`` matching records of the log and its rotated backups, in chronological order.

    Event records (see :data:`GAP_EVENT`) are returned like any other record unless a filter excludes them (a
    ``principal`` or ``decision`` filter does); callers label them by their ``event`` field.

    Lines that are not a JSON object are skipped (a crash can leave a torn last line), and so are lines longer than
    ``MAX_LINE_BYTES`` and lines too deeply nested to parse. A file that can't be read (absent, rotated away while
    we read, a directory, no permission) is skipped. Memory is bounded by ``limit``, not by the size of the files.
    """
    if limit <= 0:
        return []
    if since is not None and since.utcoffset() is None:
        since = since.replace(tzinfo=UTC)
    kept: deque[dict[str, Any]] = deque(maxlen=limit)
    for file in _log_files(Path(path)):
        with suppress(OSError):
            for line in _lines(file):
                try:
                    record = json.loads(line.decode("utf-8", errors="replace"))
                except (ValueError, RecursionError):
                    continue
                if not isinstance(record, dict):
                    continue
                if principal is not None and record.get("principal") != principal:
                    continue
                if decision is not None and record.get("decision") != decision:
                    continue
                if since is not None:
                    stamp = _parse_ts(record.get("ts"))
                    if stamp is None or stamp < since:
                        continue
                kept.append(record)
    return list(kept)
