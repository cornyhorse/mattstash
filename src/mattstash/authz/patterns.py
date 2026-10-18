"""Key-name patterns and tags (design section 4.2 and 4.3).

Matching is plain, case-sensitive string comparison against the credential name as stored in KeePass: no Unicode
or case normalisation, no trimming, and ``.``, ``/``, ``-`` get no special treatment. The only wildcard is a single
``*`` as the last character, which makes the rest of the pattern a prefix.
"""

from .errors import PolicyError

MAX_PATTERN_LENGTH = 255  # the server's name limit
MAX_TAG_LENGTH = 64
SEPARATORS = (".", "/", "-", "_")


def _printable_ascii(text: str) -> bool:
    return all(0x21 <= ord(char) <= 0x7E for char in text)


def validate_pattern(p: str) -> None:
    """Raise :class:`PolicyError` unless ``p`` is a usable key pattern.

    ``*`` may appear once, as the last character. A pattern that ends in a separator but has no ``*`` (``firefly/``)
    is refused because an exact-name grant on such a name is almost always a forgotten ``*``.
    """
    if not isinstance(p, str) or not p:
        raise PolicyError("key pattern must be a non-empty string")
    if len(p) > MAX_PATTERN_LENGTH:
        raise PolicyError(f"key pattern is longer than {MAX_PATTERN_LENGTH} characters")
    if not _printable_ascii(p):
        raise PolicyError("key pattern may contain only printable ASCII characters without whitespace")
    if p.count("*") > 1 or ("*" in p and not p.endswith("*")):
        raise PolicyError(f"key pattern {p!r}: '*' may appear only once, as the last character")
    if not p.endswith("*") and p[-1] in SEPARATORS:
        raise PolicyError(f"key pattern {p!r} ends in {p[-1]!r} but has no '*'; did you mean '{p}*'?")


def pattern_matches(pattern: str, name: str) -> bool:
    """Whether a (validated) ``pattern`` covers ``name``.

    It does not validate: the legacy v1 prefixes converted to ``<prefix>*`` may be longer than a user-written
    pattern may be, and evaluation is on the hot path.
    """
    if pattern.endswith("*"):
        return name.startswith(pattern[:-1])
    return name == pattern


def validate_tag(t: str) -> None:
    """Raise :class:`PolicyError` unless ``t`` can be a KeePass tag in a grant.

    KeePass joins tags with ``;`` or ``,`` when it stores them, so neither may appear inside one.
    """
    if not isinstance(t, str) or not t:
        raise PolicyError("tag must be a non-empty string")
    if len(t) > MAX_TAG_LENGTH:
        raise PolicyError(f"tag is longer than {MAX_TAG_LENGTH} characters")
    if not t.isprintable():
        raise PolicyError("tag may contain only printable characters")
    if t != t.strip():
        raise PolicyError("tag must not start or end with whitespace")
    if ";" in t or "," in t:
        raise PolicyError("tag must not contain ';' or ','")
