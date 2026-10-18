"""The structured access log: one JSON object per line (design section 6).

Writing is the server's job (a ``RotatingFileHandler``); this module formats a record safely and reads the files
back for ``mattstash admin log`` and ``GET /admin/access-log``. Values are never logged, only names and decisions.
"""

import json
import re
from collections import deque
from collections.abc import Mapping
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Optional

MAX_VALUE_LENGTH = 256
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


def printable(value: object) -> str:
    """``value`` as ASCII with control characters and non-ASCII escaped, so a client can't forge log lines.

    Same rule as ``server/app/logsafe.py``: ``\\n`` becomes ``\\x0a``, a non-ASCII character a ``\\u`` escape.
    """
    text = str(value).encode("ascii", "backslashreplace").decode("ascii")
    return _CONTROL.sub(lambda match: f"\\x{ord(match.group()):02x}", text)


def _clean(value: object) -> object:
    if isinstance(value, (bool, int, float)):
        return value
    return printable(value)[:MAX_VALUE_LENGTH]


def format_record(record: Mapping[str, object]) -> str:
    """One JSON line (no newline inside it, none at the end). ``None`` values are dropped."""
    ordered = [name for name in FIELD_ORDER if name in record]
    ordered += [name for name in record if name not in FIELD_ORDER]
    cleaned = {printable(name)[:MAX_VALUE_LENGTH]: _clean(record[name]) for name in ordered if record[name] is not None}
    return json.dumps(cleaned, separators=(",", ":"), ensure_ascii=True)


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
    if path.parent.is_dir():
        for candidate in path.parent.iterdir():
            suffix = candidate.name[len(path.name) + 1 :]
            if candidate.name.startswith(path.name + ".") and suffix.isascii() and suffix.isdigit():
                backups.append((int(suffix), candidate))
    return [candidate for _, candidate in sorted(backups, reverse=True)] + [path]


def read_records(
    path: "str | Path",
    *,
    principal: Optional[str] = None,
    decision: Optional[str] = None,
    since: Optional[datetime] = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """The last ``limit`` matching records of the log and its rotated backups, in chronological order.

    Lines that are not a JSON object are skipped (a crash can leave a torn last line). Memory is bounded by
    ``limit``, not by the size of the files.
    """
    if limit <= 0:
        return []
    if since is not None and since.utcoffset() is None:
        since = since.replace(tzinfo=UTC)
    kept: deque[dict[str, Any]] = deque(maxlen=limit)
    for file in _log_files(Path(path)):
        with suppress(FileNotFoundError):  # absent, or rotated away while we read
            with open(file, encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    try:
                        record = json.loads(line)
                    except ValueError:
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
