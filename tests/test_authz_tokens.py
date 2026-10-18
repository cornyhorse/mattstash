"""Token format, parsing and hashing."""

import hashlib
import re

import pytest

from mattstash.authz import (
    DUMMY_HASH,
    PolicyError,
    generate_token,
    hash_token,
    is_legacy_hash,
    parse_token,
    validate_token_hash,
    verify_token_hash,
)


def test_generate_and_parse_round_trip() -> None:
    token_id, plaintext = generate_token()
    assert re.fullmatch(r"[a-z2-7]{12}", token_id)
    assert plaintext.startswith(f"mst_{token_id}_")
    assert 50 <= len(plaintext) <= 70 and plaintext.isascii() and plaintext.isprintable()
    parsed = parse_token(plaintext)
    assert parsed is not None and parsed[0] == token_id
    assert plaintext == f"mst_{parsed[0]}_{parsed[1]}"


def test_tokens_are_unique() -> None:
    assert len({generate_token()[1] for _ in range(50)}) == 50


@pytest.mark.parametrize(
    "value",
    [
        "",
        "mst_",
        "mst__x",
        "mst_abcdefghijkl",  # no secret separator
        "mst_abcdefghijkl_",  # empty secret
        "mst_ABCDEFGHIJKL_secret",  # uppercase id
        "mst_abcdefghijk_secret",  # 11 characters
        "mst_abcdefghijklm_secret",  # 13 characters
        "mst_abcdefghijk1_secret",  # '1' is not base32
        "mst_abcdefghijkl_sec ret",
        "mst_abcdefghijkl_sec\nret",
        "mst_abcdefghijkl_secéret",
        "MST_abcdefghijkl_secret",
        "xmst_abcdefghijkl_secret",
        "mst_abcdefghijkl_" + "a" * 201,
        None,
        42,
        b"mst_abcdefghijkl_x",
    ],
)
def test_malformed_tokens_do_not_parse(value: object) -> None:
    assert parse_token(value) is None


def test_underscores_in_the_secret_are_kept() -> None:
    assert parse_token("mst_abcdefghijkl_a_b__c-d") == ("abcdefghijkl", "a_b__c-d")


def test_hash_verifies_only_the_right_token() -> None:
    _, plaintext = generate_token()
    _, other = generate_token()
    stored = hash_token(plaintext)
    assert re.fullmatch(r"hmac-sha256:[0-9a-f]{32}:[0-9a-f]{64}", stored)
    assert verify_token_hash(stored, plaintext)
    assert not verify_token_hash(stored, other)
    assert not verify_token_hash(stored, plaintext + "x")
    assert not verify_token_hash(stored, "")
    # the secret alone is not enough: the digest covers the whole token
    assert not verify_token_hash(stored, plaintext.split("_", 2)[2])


def test_hashing_is_salted() -> None:
    _, plaintext = generate_token()
    assert hash_token(plaintext) != hash_token(plaintext)


def test_lone_surrogates_do_not_raise() -> None:
    stored = hash_token("mst_abcdefghijkl_ok")
    assert verify_token_hash(stored, "mst_\ud800_bad") is False
    assert verify_token_hash("sha256:" + "0" * 64, "\ud800") is False


def test_legacy_sha256_hash() -> None:
    plaintext = "a-legacy-key-of-sufficient-length-0123"
    stored = "sha256:" + hashlib.sha256(plaintext.encode()).hexdigest()
    assert is_legacy_hash(stored)
    assert not is_legacy_hash(hash_token(plaintext))
    assert not is_legacy_hash(None)
    assert verify_token_hash(stored, plaintext)
    assert not verify_token_hash(stored, plaintext + "x")
    validate_token_hash(stored)


@pytest.mark.parametrize(
    "stored",
    [
        "",
        "sha256:",
        "sha256:abc",
        "sha256:" + "G" * 64,
        "sha256:" + "A" * 64,  # stored hashes are lower case
        "hmac-sha256:" + "0" * 32,
        "hmac-sha256:" + "0" * 31 + ":" + "0" * 64,
        "hmac-sha256:" + "0" * 32 + ":" + "0" * 63,
        "hmac-sha256:" + "0" * 32 + ":" + "0" * 64 + ":extra",
        "md5:" + "0" * 32,
        "plain-text-token",
        None,
        123,
    ],
)
def test_malformed_stored_hash(stored: object) -> None:
    assert verify_token_hash(stored, "mst_abcdefghijkl_x") is False  # type: ignore[arg-type]
    with pytest.raises(PolicyError, match="malformed"):
        validate_token_hash(stored)


def test_error_message_does_not_repeat_the_hash() -> None:
    secret_looking = "hmac-sha256:" + "ab" * 16 + ":" + "cd" * 31
    with pytest.raises(PolicyError) as info:
        validate_token_hash(secret_looking)
    assert "abab" not in str(info.value) and "cdcd" not in str(info.value)


def test_dummy_hash_is_well_formed_and_matches_nothing() -> None:
    validate_token_hash(DUMMY_HASH)
    assert not verify_token_hash(DUMMY_HASH, generate_token()[1])
