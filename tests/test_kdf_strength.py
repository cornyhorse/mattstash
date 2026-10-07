"""The tests use a cheap Argon2 setting for speed (tests/conftest.py); these prove users do not get it."""

import pytest
from pykeepass import PyKeePass

from mattstash import MattStash

MIB = 1024 * 1024


def kdf_cost(path) -> tuple[str, int, int]:
    kp = PyKeePass(str(path), password="pw")
    params = kp.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
    return kp.kdf_algorithm, params["I"].value, params["M"].value


@pytest.mark.real_kdf
def test_databases_created_by_mattstash_use_a_strong_kdf(tmp_path):
    db = tmp_path / "x.kdbx"
    MattStash.create(str(db), password="pw", sidecar=False)
    algorithm, iterations, memory = kdf_cost(db)
    assert algorithm in ("argon2", "argon2id")
    # at least as strong as ~10 passes over 64 MiB (today's pykeepass template: 14 passes over 64 MiB)
    assert memory >= 64 * MIB
    assert iterations * memory >= 10 * 64 * MIB


@pytest.mark.real_kdf
def test_saving_and_rotating_the_password_keep_the_kdf_cost(tmp_path):
    db = tmp_path / "x.kdbx"
    stash = MattStash.create(str(db), password="pw", sidecar=False)
    before = kdf_cost(db)
    stash.rotate_password("new-pw")
    kp = PyKeePass(str(db), password="new-pw")
    params = kp.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
    assert (kp.kdf_algorithm, params["I"].value, params["M"].value) == before


def test_the_default_test_fixture_really_is_cheap(tmp_path):
    """Guards the optimisation itself: if the fixture stops working the suite silently becomes 50x slower."""
    db = tmp_path / "x.kdbx"
    MattStash.create(str(db), password="pw", sidecar=False)
    _algorithm, iterations, memory = kdf_cost(db)
    assert iterations * memory <= 8 * MIB
