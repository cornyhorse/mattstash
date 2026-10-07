"""
mattstash.cli.inputs
--------------------
Helpers for reading secrets without putting them on the command line.

Anything passed in ``argv`` is visible to other local users (``ps``, ``/proc/<pid>/cmdline``) and ends
up in shell history. The CLI therefore accepts secrets from stdin, from files and from the environment
as well. The helpers here implement the shared rules:

* stdin / file *values* (``put --value -``, ``--value-file``, ``--entry-password-stdin`` ...) have
  exactly one trailing newline removed and must not be empty;
* *credential files* (database password, API key, new master password) have surrounding
  whitespace stripped, like ``KDBX_PASSWORD_FILE``;
* only one option per invocation may consume stdin;
* error messages name the option or file, never its content.
"""

import os
import sys
from typing import IO, Optional

#: Upper bound for a secret read from stdin or a file (guards against ``/dev/zero`` and similar).
MAX_SECRET_BYTES = 1024 * 1024


class InputError(ValueError):
    """A secret input could not be read or is unusable. The message is safe to show."""


class StdinClaim:
    """Tracks which option has claimed stdin: only one option per invocation may read it."""

    def __init__(self) -> None:
        self._owner: Optional[str] = None

    def claim(self, option: str) -> None:
        if self._owner is not None and self._owner != option:
            raise InputError(
                f"{self._owner} and {option} both read from stdin; only one option can consume stdin per invocation"
            )
        self._owner = option


def strip_one_newline(text: str) -> str:
    """Remove exactly one trailing line break (``\\n`` or ``\\r\\n``)."""
    if text.endswith("\r\n"):
        return text[:-2]
    if text.endswith("\n"):
        return text[:-1]
    return text


def _decode(data: bytes, what: str) -> str:
    if len(data) > MAX_SECRET_BYTES:
        raise InputError(f"{what} is larger than {MAX_SECRET_BYTES} bytes")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise InputError(f"{what} is not valid UTF-8 text") from None


def read_stdin_secret(option: str, stream: Optional[IO[bytes]] = None) -> str:
    """Read a secret from stdin (all of it), dropping one trailing newline. Rejects empty input."""
    stdin = sys.stdin
    try:
        interactive = stdin.isatty()
    except (AttributeError, ValueError):
        interactive = False
    if interactive:
        print(f"mattstash: reading {option} from the terminal; finish with Ctrl-D", file=sys.stderr)
    if stream is None:
        stream = getattr(stdin, "buffer", None)
    if stream is not None:
        data = stream.read(MAX_SECRET_BYTES + 1)
    else:  # text-only stdin replacement (e.g. io.StringIO)
        data = stdin.read(MAX_SECRET_BYTES + 1).encode("utf-8")
    value = strip_one_newline(_decode(data, f"input on stdin for {option}"))
    if not value:
        raise InputError(f"{option}: no data received on stdin (empty value)")
    return value


def read_stdin_line(option: str) -> str:
    """Read the first line of stdin (line break removed) as a password. Rejects empty input.

    Same rule as ``setup --password-stdin``: one line, so a pipeline can send the password followed by anything.
    """
    stdin = sys.stdin
    try:
        interactive = stdin.isatty()
    except (AttributeError, ValueError):
        interactive = False
    if interactive:
        print(f"mattstash: reading {option} from the terminal; finish with Enter", file=sys.stderr)
    line = stdin.readline(MAX_SECRET_BYTES + 1)
    if len(line) > MAX_SECRET_BYTES:
        raise InputError(f"{option}: the first line on stdin is larger than {MAX_SECRET_BYTES} bytes")
    value = line.rstrip("\r\n")
    if not value:
        raise InputError(f"{option}: no password received on stdin (empty line)")
    return value


def read_secret_file(option: str, path: str) -> str:
    """Read a secret value from ``path``, dropping one trailing newline. Rejects empty files."""
    path = os.path.expanduser(path)
    try:
        with open(path, "rb") as f:
            data = f.read(MAX_SECRET_BYTES + 1)
    except OSError as exc:
        raise InputError(f"{option}: cannot read {path}: {exc.strerror or exc}") from None
    value = strip_one_newline(_decode(data, f"{option} file {path}"))
    if not value:
        raise InputError(f"{option}: file {path} is empty")
    return value


def read_credential_file(option: str, path: str) -> str:
    """Read a password / API key from ``path`` with surrounding whitespace stripped (like ``KDBX_PASSWORD_FILE``)."""
    path = os.path.expanduser(path)
    try:
        with open(path, "rb") as f:
            data = f.read(MAX_SECRET_BYTES + 1)
    except OSError as exc:
        raise InputError(f"{option}: cannot read {path}: {exc.strerror or exc}") from None
    value = _decode(data, f"{option} file {path}").strip()
    if not value:
        raise InputError(f"{option}: file {path} is empty")
    return value


def read_credential_env_file(env_name: str) -> Optional[str]:
    """Value of the credential file named by environment variable ``env_name`` (None if unset/empty)."""
    path = os.environ.get(env_name)
    if not path:
        return None
    return read_credential_file(env_name, path)
