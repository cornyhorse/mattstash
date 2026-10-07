"""
mattstash.core.env_vars
-----------------------
Turn secrets into environment variables (``mattstash env`` / ``mattstash exec``).

Everything here is I/O free so it can be unit-tested and shared by the local (KeePass) and the
server (HTTP) code paths: a :class:`SecretSource` supplies titles and field values,
:func:`collect_env` applies the selection rules, and the ``format_*`` functions render the result.

Selection
~~~~~~~~~
* ``prefix``: every secret whose *base* title starts with the prefix becomes a variable. The name is the
  title (prefix removed unless ``strip_prefix`` is False) with every character outside ``[A-Za-z0-9_]``
  replaced by ``_`` (and upper-cased with ``upper``).
* ``mappings``: ``ENVVAR -> "TITLE[:FIELD]"``; ``FIELD`` is ``password`` (default), ``username``, ``url``,
  ``notes`` or the name of a custom property. The field is taken after the *last* ``:``, so a title that
  itself contains ``:`` needs an explicit field (``ENVVAR=a:b:password``).
* Name collisions are errors (the message names the titles, never the values).
* The latest version of each secret is used.

Safety
~~~~~~
Names are validated against ``[A-Za-z_][A-Za-z0-9_]*`` before anything is emitted, and the shell
renderer quotes every value with :func:`shlex.quote`, so any value (newlines, quotes, ``$(...)``)
is inert when the output is ``eval``-ed.
"""

import json
import re
import shlex
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Dict, List, Optional, Protocol, Tuple

from ..utils.exceptions import CredentialNotFoundError
from ..utils.logging_config import get_logger

logger = get_logger(__name__)

#: Valid environment variable names (ASCII only; never starts with a digit).
ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*", re.ASCII)

#: Fields every secret can provide; any other FIELD names a custom property.
STANDARD_FIELDS = ("password", "username", "url", "notes")
DEFAULT_FIELD = "password"

#: Output formats of ``mattstash env``.
FORMATS = ("shell", "dotenv", "json")

_UNSAFE_NAME_CHARS = re.compile(r"[^A-Za-z0-9_]", re.ASCII)
# Characters that never need quoting in a dotenv value (any dotenv parser reads these literally).
_DOTENV_PLAIN = re.compile(r"[A-Za-z0-9_./:@%+,=-]*", re.ASCII)


class SecretSource(Protocol):
    """Where secrets come from (the KeePass database or a MattStash server)."""

    def titles(self, prefix: str) -> List[str]:
        """Base titles (latest version of each secret) that start with ``prefix``."""
        ...

    def value(self, title: str, field: str) -> Optional[str]:
        """Field value of the latest version of ``title``.

        Raises ``CredentialNotFoundError`` if there is no such secret; returns ``None`` or ``""`` if the
        field is unset.
        """
        ...


@dataclass(frozen=True)
class EnvMapping:
    """One ``ENVVAR=TITLE[:FIELD]`` mapping."""

    env_name: str
    title: str
    field: str


def validate_env_name(name: str) -> str:
    """Return ``name`` if it is a valid environment variable name, else raise ``ValueError``."""
    if not ENV_NAME_RE.fullmatch(name):
        raise ValueError(f"invalid environment variable name {name!r}: it must match [A-Za-z_][A-Za-z0-9_]*")
    return name


def split_target(target: str) -> Tuple[str, str]:
    """Split ``TITLE[:FIELD]`` at the last ``:`` (field defaults to ``password``)."""
    title, sep, field = target.rpartition(":")
    if not sep:
        title, field = target, DEFAULT_FIELD
    if not title or not field:
        raise ValueError(f"invalid mapping target {target!r}: expected TITLE or TITLE:FIELD")
    return title, field


def parse_mapping(spec: str) -> EnvMapping:
    """Parse ``ENVVAR=TITLE[:FIELD]`` (split at the first ``=``: env names cannot contain one)."""
    name, sep, target = spec.partition("=")
    if not sep or not target:
        raise ValueError(f"invalid mapping {spec!r}: expected ENVVAR=TITLE[:FIELD]")
    title, field = split_target(target)
    return EnvMapping(validate_env_name(name), title, field)


def parse_mappings(specs: Iterable[str]) -> Dict[str, str]:
    """Parse several ``ENVVAR=TITLE[:FIELD]`` strings into ``{ENVVAR: "TITLE[:FIELD]"}``; duplicates are errors."""
    result: Dict[str, str] = {}
    for spec in specs:
        mapping = parse_mapping(spec)
        if mapping.env_name in result:
            raise ValueError(f"environment variable {mapping.env_name} is mapped more than once")
        result[mapping.env_name] = spec.partition("=")[2]
    return result


def derive_env_name(title: str, prefix: str, *, strip_prefix: bool = True, upper: bool = False) -> str:
    """Environment variable name for ``title`` selected through ``prefix`` (validated)."""
    name = title[len(prefix) :] if strip_prefix and title.startswith(prefix) else title
    name = _UNSAFE_NAME_CHARS.sub("_", name)
    if upper:
        name = name.upper()
    if not ENV_NAME_RE.fullmatch(name):
        raise ValueError(
            f"secret {title!r} does not map to a valid environment variable name ({name!r}); "
            "choose another --prefix or map it explicitly with --map ENVVAR=TITLE"
        )
    return name


def _checked_value(origin: str, env_name: str, value: str) -> str:
    if "\0" in value:
        raise ValueError(f"{origin} contains a NUL byte and cannot be used as environment variable {env_name}")
    return value


def collect_env(
    source: SecretSource,
    *,
    prefix: Optional[str] = None,
    mappings: Optional[Mapping[str, str] | Iterable[str]] = None,
    strip_prefix: bool = True,
    upper: bool = False,
) -> Dict[str, str]:
    """Build ``{ENVVAR: value}`` from ``source`` according to ``prefix`` and ``mappings``.

    Raises:
        ValueError: nothing selected, invalid names/mappings, NUL in a value, or a name collision.
        CredentialNotFoundError: a mapped secret does not exist or has no value for the field, or
            ``prefix`` matches no secret.
    """
    if mappings is None:
        mapped: Dict[str, str] = {}
    elif isinstance(mappings, str):  # a single "ENVVAR=TITLE[:FIELD]" (not an iterable of characters)
        mapped = parse_mappings([mappings])
    elif isinstance(mappings, Mapping):
        mapped = dict(mappings)
    else:
        mapped = parse_mappings(mappings)
    if prefix is None and not mapped:
        raise ValueError("nothing selected: give a prefix and/or at least one ENVVAR=TITLE[:FIELD] mapping")

    env: Dict[str, str] = {}
    origins: Dict[str, str] = {}

    def add(env_name: str, value: str, origin: str) -> None:
        if env_name in env:
            raise ValueError(f"environment variable {env_name} would be set by both {origins[env_name]} and {origin}")
        env[env_name] = _checked_value(origin, env_name, value)
        origins[env_name] = origin

    if prefix is not None:
        titles = sorted(set(source.titles(prefix)))
        if not titles:
            raise CredentialNotFoundError(f"no secrets found with prefix {prefix!r}")
        for title in titles:
            env_name = derive_env_name(title, prefix, strip_prefix=strip_prefix, upper=upper)
            value = source.value(title, DEFAULT_FIELD)
            if not value:
                logger.warning("skipping %r: it has no password/value", title)
                continue
            add(env_name, value, repr(title))

    for env_name in sorted(mapped):
        validate_env_name(env_name)
        title, field = split_target(mapped[env_name])
        value = source.value(title, field)
        if not value:
            raise CredentialNotFoundError(f"secret {title!r} has no value for field {field!r} (for {env_name})")
        add(env_name, value, f"{title!r}:{field}")
    if not env:
        raise CredentialNotFoundError("nothing to export: every selected secret was empty")
    return env


# ---- rendering ---------------------------------------------------------------


def format_shell(env: Mapping[str, str]) -> str:
    """``export NAME='value'`` lines (POSIX sh/bash/zsh); every value goes through :func:`shlex.quote`."""
    return "".join(f"export {validate_env_name(name)}={shlex.quote(value)}\n" for name, value in sorted(env.items()))


def _dotenv_value(value: str) -> str:
    if _DOTENV_PLAIN.fullmatch(value):
        return value
    if "'" not in value and "\n" not in value and "\r" not in value:
        return f"'{value}'"  # literal in compose, python-dotenv, systemd, ...
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")
    return f'"{escaped.replace("$", chr(92) + "$")}"'


def format_dotenv(env: Mapping[str, str]) -> str:
    """``NAME=value`` lines for dotenv consumers.

    Plain values are written bare; other values are single-quoted. Values containing a single quote
    or a line break are double-quoted with ``\\\\``, ``\\"``, ``\\n``, ``\\r`` and ``\\$`` escapes. Dotenv
    dialects differ on quoting; ``--format shell`` and ``--format json`` are unambiguous.
    """
    return "".join(f"{validate_env_name(name)}={_dotenv_value(value)}\n" for name, value in sorted(env.items()))


def format_json(env: Mapping[str, str]) -> str:
    """A JSON object ``{"NAME": "value", ...}`` (ASCII-only output, sorted keys)."""
    for name in env:
        validate_env_name(name)
    return json.dumps(dict(sorted(env.items())), indent=2) + "\n"


def format_env(env: Mapping[str, str], fmt: str) -> str:
    """Render ``env`` as ``shell``, ``dotenv`` or ``json``."""
    if fmt == "shell":
        return format_shell(env)
    if fmt == "dotenv":
        return format_dotenv(env)
    if fmt == "json":
        return format_json(env)
    raise ValueError(f"unknown format {fmt!r}; expected one of {', '.join(FORMATS)}")
