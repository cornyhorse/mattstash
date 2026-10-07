"""Make untrusted text safe to put in a single log line (no forged records)."""

import re

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def printable(value: object) -> str:
    """Return ``value`` as ASCII with control characters and non-ASCII escaped (``\\n`` -> ``\\x0a``)."""
    text = str(value).encode("ascii", "backslashreplace").decode("ascii")
    return _CONTROL.sub(lambda match: f"\\x{ord(match.group()):02x}", text)
