# ruff: noqa: RUF001  (the look-alike characters are the point of these tests)
"""Key patterns and tags: matching is plain, case-sensitive string comparison (design section 4.2)."""

import pytest

from mattstash.authz import PolicyError, pattern_matches, validate_pattern, validate_tag


@pytest.mark.parametrize(
    ("pattern", "name", "expected"),
    [
        ("firefly", "firefly", True),
        ("firefly", "firefly-mcp", False),  # an exact name is not a prefix
        ("firefly", "firefly.token", False),
        ("firefly", "Firefly", False),  # case sensitive
        ("firefly.*", "firefly.token", True),
        ("firefly.*", "firefly.db.password", True),
        ("firefly.*", "firefly", False),
        ("firefly.*", "firefly-mcp", False),
        ("FIREFLY.*", "firefly.token", False),
        ("firefly*", "firefly", True),
        ("firefly*", "firefly-mcp", True),
        ("firefly*", "firefly.token", True),
        ("firefly*", "Firefly", False),
        ("firefly/*", "firefly/token", True),
        ("firefly/*", "firefly/", True),
        ("firefly/*", "firefly", False),
        ("firefly/*", "firefly.token", False),
        ("firefly/token", "firefly/token", True),
        ("firefly/token", "firefly/token/", False),  # trailing slash is part of the name
        ("*", "anything", True),
        ("*", "", True),
        ("firefly", "firefly​", False),  # zero width space
        ("firefly", "fіrefly", False),  # Cyrillic i
        ("firefly*", "fіrefly", False),
        ("a-b", "a‐b", False),  # unicode hyphen
    ],
)
def test_matching(pattern: str, name: str, expected: bool) -> None:
    assert pattern_matches(pattern, name) is expected


@pytest.mark.parametrize(
    "pattern",
    ["*", "a", "firefly", "firefly.*", "firefly/*", "firefly-*", "firefly_*", "a/b/c", "x" * 255, "x" * 254 + "*"],
)
def test_valid_patterns(pattern: str) -> None:
    validate_pattern(pattern)


@pytest.mark.parametrize(
    "pattern",
    [
        "",
        "**",
        "a*b",
        "*a",
        "a**",
        "a *",
        " a",
        "a\n",
        "a\tb",
        "café",
        "а",
        "x" * 256,
        "a\x7f",
        "a\x00",
    ],
)
def test_invalid_patterns(pattern: str) -> None:
    with pytest.raises(PolicyError):
        validate_pattern(pattern)


@pytest.mark.parametrize("pattern", ["firefly/", "firefly.", "firefly-", "firefly_", "a/b/"])
def test_trailing_separator_without_star_gets_a_hint(pattern: str) -> None:
    with pytest.raises(PolicyError, match=f"did you mean '{pattern}\\*'"):
        validate_pattern(pattern)


def test_non_string_pattern_is_rejected() -> None:
    with pytest.raises(PolicyError):
        validate_pattern(None)  # type: ignore[arg-type]


@pytest.mark.parametrize("tag", ["a", "ops", "has space", "café", "x" * 64, "a.b/c-d_e"])
def test_valid_tags(tag: str) -> None:
    validate_tag(tag)


@pytest.mark.parametrize("tag", ["", "x" * 65, "a;b", "a,b", " a", "a ", "a\nb", "a\x00", None])
def test_invalid_tags(tag: str) -> None:
    with pytest.raises(PolicyError):
        validate_tag(tag)
