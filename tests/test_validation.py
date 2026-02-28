"""Tests for mattstash.utils.validation — credential title validation.

Covers the slash-in-title regression fix (0.1.6 → 0.1.9):
  Forward slashes are intentional namespace separators and must be accepted.
  Backslashes, null bytes, and control characters remain blocked.
"""

import pytest

from mattstash.utils.exceptions import InvalidCredentialError
from mattstash.utils.validation import (
    MAX_TITLE_LENGTH,
    validate_credential_title,
)

# ── Forward slashes ALLOWED (namespace separators) ──────────────────────


@pytest.mark.parametrize(
    "title",
    [
        "cloud/hetzner/s3-access-key",
        "cloud/hetzner/s3-secret-key",
        "cloud/hetzner/project-id",
        "cloud/cloudflare/api-token",
        "services/postgres/main",
        "a/b/c/d/e",
        "single-segment",
        "trailing/",
        "/leading",
    ],
    ids=lambda t: t.replace("/", "_"),
)
def test_forward_slash_titles_accepted(title: str) -> None:
    """Titles with / as namespace separator must be accepted."""
    validate_credential_title(title)  # should not raise


# ── Dangerous characters BLOCKED ────────────────────────────────────────


@pytest.mark.parametrize(
    "title, char_name",
    [
        ("back\\slash", "backslash"),
        ("null\0byte", "null byte"),
        ("new\nline", "newline"),
        ("carriage\rreturn", "carriage return"),
        ("tab\there", "tab"),
    ],
)
def test_dangerous_chars_rejected(title: str, char_name: str) -> None:
    """Backslashes, null bytes, and control characters must be rejected."""
    with pytest.raises(InvalidCredentialError, match="invalid character"):
        validate_credential_title(title)


# ── Empty / whitespace titles ───────────────────────────────────────────


@pytest.mark.parametrize("title", ["", "   ", "\t", "\n"])
def test_empty_or_whitespace_rejected(title: str) -> None:
    with pytest.raises(InvalidCredentialError, match="cannot be empty"):
        validate_credential_title(title)


# ── Dot-prefix titles ──────────────────────────────────────────────────


@pytest.mark.parametrize("title", [".hidden", ".env", "..secret"])
def test_dot_prefix_rejected(title: str) -> None:
    with pytest.raises(InvalidCredentialError, match=r"cannot start with '.'"):
        validate_credential_title(title)


# ── Length limit ────────────────────────────────────────────────────────


def test_max_length_accepted() -> None:
    validate_credential_title("a" * MAX_TITLE_LENGTH)  # exactly at limit


def test_over_max_length_rejected() -> None:
    with pytest.raises(InvalidCredentialError, match="too long"):
        validate_credential_title("a" * (MAX_TITLE_LENGTH + 1))


# ── Realistic namespace titles (regression guard) ───────────────────────


REAL_WORLD_TITLES = [
    "cloud/hetzner/s3-access-key",
    "cloud/hetzner/s3-secret-key",
    "cloud/hetzner/project-id",
    "cloud/hetzner/hcloud-token",
    "cloud/hetzner/kopia-s3-access-key",
    "cloud/hetzner/kopia-s3-secret-key",
    "cloud/cloudflare/api-token",
    "backup/borg/local-passphrase",
    "backup/borg/cloud-passphrase",
]


@pytest.mark.parametrize("title", REAL_WORLD_TITLES)
def test_real_world_namespace_titles(title: str) -> None:
    """Existing namespace-separated entries must pass validation."""
    validate_credential_title(title)
