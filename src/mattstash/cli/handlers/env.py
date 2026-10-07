"""
mattstash.cli.handlers.env
--------------------------
Handlers for ``env`` and ``exec``: hand secrets to containers, pods and scripts as environment variables.

* ``env`` prints them (``shell``, ``dotenv`` or ``json``) -- the only place they are written to stdout.
* ``exec`` builds the same environment and replaces the process with the command (``execve``), so the
  child's exit status is the command's, and nothing is written to disk or stdout.

Both work against the local database and, with ``--server-url``, against a MattStash server (list names,
then fetch each selected secret). Secret values are never logged and never appear in error messages.
"""

import os
import shutil
import signal
import sys
from argparse import Namespace
from typing import Dict, List, Optional, Tuple

from ...core.env_vars import STANDARD_FIELDS, SecretSource, collect_env, format_env, parse_mappings
from ...core.mattstash import MattStash
from ...utils.exceptions import CredentialNotFoundError, ServerError
from .. import exit_codes
from ..http_client import MattStashServerClient
from ..inputs import InputError
from .base import BaseHandler


class ServerSecretSource:
    """``SecretSource`` backed by the MattStash HTTP API (names via ``list``, values via ``get``)."""

    def __init__(self, client: MattStashServerClient) -> None:
        self._client = client
        self._cache: Dict[str, Optional[Dict[str, object]]] = {}

    def titles(self, prefix: str) -> List[str]:
        names = []
        for item in self._client.list(show_password=False, prefix=prefix or None):
            name = item.get("name")
            if not isinstance(name, str):
                continue
            # An older server lists every stored version ("name@0000000003"); the API addresses base names.
            base, sep, suffix = name.rpartition("@")
            if sep and base and suffix.isascii() and suffix.isdigit():
                name = base
            # The server filters by prefix too; do not rely on it.
            if name.startswith(prefix):
                names.append(name)
        return names

    def value(self, title: str, field: str) -> Optional[str]:
        if field not in STANDARD_FIELDS:
            raise ValueError(
                f"field {field!r} is not available in server mode (the API exposes only {', '.join(STANDARD_FIELDS)})"
            )
        if title not in self._cache:
            self._cache[title] = self._client.get(title, show_password=True)
        data = self._cache[title]
        if data is None:
            raise CredentialNotFoundError(f"secret not found: {title}")
        value = data.get(field)
        return value if isinstance(value, str) else None


class EnvHandler(BaseHandler):
    """Handler for ``mattstash env``."""

    def handle(self, args: Namespace) -> int:
        env, code = self._collect(args)
        if env is None:
            return code
        try:
            output = format_env(env, self.opt(args, "format", str) or "shell")
        except ValueError as exc:
            self.error(str(exc))
            return exit_codes.ERROR
        sys.stdout.write(output)
        sys.stdout.flush()
        return exit_codes.OK

    # ---- shared with exec -------------------------------------------------------

    def _collect(self, args: Namespace) -> Tuple[Optional[Dict[str, str]], int]:
        """Resolve the selected secrets. Returns ``(env, 0)`` or ``(None, exit_code)`` after reporting."""
        try:
            mappings = parse_mappings(self.opt(args, "mappings", list) or [])
            prefix = self.opt(args, "prefix", str)
            strip_prefix = getattr(args, "strip_prefix", True) is not False
            upper = self.flag(args, "upper")
            # JSON is data (nothing applies it to an environment), so only the other formats and `exec` need the guard.
            allow_reserved = self.flag(args, "allow_reserved") or self.opt(args, "format", str) == "json"
            if self.is_server_mode(args):
                client = self.get_server_client(args)
                if client is None:
                    return None, exit_codes.ERROR
                source: SecretSource = ServerSecretSource(client)
                env = collect_env(
                    source,
                    prefix=prefix,
                    mappings=mappings,
                    strip_prefix=strip_prefix,
                    upper=upper,
                    allow_reserved=allow_reserved,
                )
            else:
                stash = MattStash(path=self.opt(args, "path", str), password=self.opt(args, "password", str))
                env = stash.resolve_env(
                    prefix=prefix,
                    mappings=mappings,
                    strip_prefix=strip_prefix,
                    upper=upper,
                    allow_reserved=allow_reserved,
                )
            return env, exit_codes.OK
        except CredentialNotFoundError as exc:
            self.error(str(exc))
            return None, exit_codes.NOT_FOUND
        except ServerError as exc:
            self.error(f"Server error: {exc}")
            return None, exit_codes.ERROR
        except (ValueError, InputError) as exc:
            self.error(str(exc))
            return None, exit_codes.ERROR


#: Environment variables that unlock the vault itself; ``exec`` does not hand them to the command by default.
VAULT_CREDENTIAL_ENV = ("KDBX_PASSWORD", "MATTSTASH_API_KEY")


def _exists_but_not_executable(command: str) -> bool:
    """True if ``command`` names an existing file that is not executable (the shell's "permission denied", 126).

    Mirrors the lookup ``shutil.which`` just failed: the path itself when it contains a separator, else each ``PATH``
    directory.
    """
    if os.sep in command:
        return os.path.exists(command)
    for directory in (os.environ.get("PATH") or "").split(os.pathsep):
        candidate = os.path.join(directory or os.curdir, command)
        if os.path.isfile(candidate) and not os.access(candidate, os.X_OK):
            return True
    return False


def _restore_default_signals() -> None:
    """Python ignores SIGPIPE (and SIGXFSZ) at start-up, and ignored signals survive ``execve``.

    Without this, a command's pipelines die with "Broken pipe" errors and exit status 1 instead of the usual
    signal-141 behaviour: ``exec`` must not change how the command runs.
    """
    for name in ("SIGPIPE", "SIGXFSZ"):
        number = getattr(signal, name, None)
        if number is not None:
            signal.signal(number, signal.SIG_DFL)


class ExecHandler(EnvHandler):
    """Handler for ``mattstash exec [options] -- COMMAND [ARGS...]``."""

    def handle(self, args: Namespace) -> int:
        command = list(self.opt(args, "command", list) or [])
        if command[:1] == ["--"]:
            command = command[1:]
        if not command:
            self.error("exec: no command given. Usage: mattstash exec [options] -- COMMAND [ARGS...]")
            return exit_codes.ERROR

        # Resolve the program with the caller's PATH (a secret named PATH must not redirect the lookup).
        program = shutil.which(command[0], path=os.environ.get("PATH"))
        if program is None:
            if _exists_but_not_executable(command[0]):
                self.error(f"exec: cannot execute {command[0]}: permission denied")
                return exit_codes.COMMAND_NOT_EXECUTABLE
            self.error(f"exec: command not found: {command[0]}")
            return exit_codes.COMMAND_NOT_FOUND

        env, code = self._collect(args)
        if env is None:
            return code

        child_env = dict(os.environ)
        if not self.flag(args, "keep_vault_env"):
            # The command gets the secrets that were asked for, not the keys to the whole vault. (Injected
            # variables are added after this, so a secret deliberately mapped to one of these names still wins.)
            for name in VAULT_CREDENTIAL_ENV:
                child_env.pop(name, None)
        override = self.flag(args, "override")
        for name, value in env.items():
            # "already set" is judged against what the command would inherit: a vault variable removed above does
            # not block a secret that was deliberately mapped to that name.
            if override or name not in child_env:
                child_env[name] = value

        sys.stdout.flush()
        sys.stderr.flush()
        _restore_default_signals()
        try:
            # Intentional: `exec` runs the user's command with no shell involved (argv is passed as a list).
            os.execve(program, command, child_env)  # noqa: S606
        except OSError as exc:
            self.error(f"exec: cannot execute {command[0]}: {exc.strerror or exc.__class__.__name__}")
            return exit_codes.COMMAND_NOT_EXECUTABLE
        return exit_codes.OK  # pragma: no cover - execve only returns on failure (or when mocked)
