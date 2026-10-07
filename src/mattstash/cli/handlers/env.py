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
            # The server filters too; do not rely on it.
            if isinstance(name, str) and name.startswith(prefix):
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
            output = format_env(env, getattr(args, "format", None) or "shell")
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
            mappings = parse_mappings(getattr(args, "mappings", None) or [])
            prefix: Optional[str] = getattr(args, "prefix", None)
            strip_prefix = bool(getattr(args, "strip_prefix", True))
            upper = bool(getattr(args, "upper", False))
            if self.is_server_mode(args):
                client = self.get_server_client(args)
                if client is None:
                    return None, exit_codes.ERROR
                source: SecretSource = ServerSecretSource(client)
                env = collect_env(source, prefix=prefix, mappings=mappings, strip_prefix=strip_prefix, upper=upper)
            else:
                stash = MattStash(path=getattr(args, "path", None), password=getattr(args, "password", None))
                env = stash.resolve_env(prefix=prefix, mappings=mappings, strip_prefix=strip_prefix, upper=upper)
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


class ExecHandler(EnvHandler):
    """Handler for ``mattstash exec [options] -- COMMAND [ARGS...]``."""

    def handle(self, args: Namespace) -> int:
        command = list(getattr(args, "command", None) or [])
        if command[:1] == ["--"]:
            command = command[1:]
        if not command:
            self.error("exec: no command given. Usage: mattstash exec [options] -- COMMAND [ARGS...]")
            return exit_codes.ERROR

        # Resolve the program with the caller's PATH (a secret named PATH must not redirect the lookup).
        program = shutil.which(command[0], path=os.environ.get("PATH"))
        if program is None:
            if os.sep in command[0] and os.path.exists(command[0]):
                self.error(f"exec: cannot execute {command[0]}: permission denied")
                return exit_codes.COMMAND_NOT_EXECUTABLE
            self.error(f"exec: command not found: {command[0]}")
            return exit_codes.COMMAND_NOT_FOUND

        env, code = self._collect(args)
        if env is None:
            return code

        child_env = dict(os.environ)
        override = bool(getattr(args, "override", False))
        for name, value in env.items():
            if override or name not in os.environ:
                child_env[name] = value

        sys.stdout.flush()
        sys.stderr.flush()
        try:
            # Intentional: `exec` runs the user's command with no shell involved (argv is passed as a list).
            os.execve(program, command, child_env)  # noqa: S606
        except OSError as exc:
            self.error(f"exec: cannot execute {command[0]}: {exc.strerror or exc.__class__.__name__}")
            return exit_codes.COMMAND_NOT_EXECUTABLE
        return exit_codes.OK  # pragma: no cover - execve only returns on failure (or when mocked)
