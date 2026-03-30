"""Tests for app.dependencies — get_mattstash() integration."""
import threading

import pytest
from pykeepass import create_database

from app.config import Config
from app.dependencies import _mattstash_lock, get_mattstash


def test_get_mattstash_constructs_with_real_kdbx(tmp_path, monkeypatch):
    """get_mattstash() must pass `path=` (not `db_path=`) to MattStash().

    Regression test for the db_path→path kwarg bug that caused a TypeError
    and silent 503 on every credential endpoint.
    """
    db_file = tmp_path / "test.kdbx"
    password = "regression-test-pw"
    create_database(str(db_file), password=password)

    monkeypatch.setattr(Config, "DB_PATH", str(db_file))
    monkeypatch.setattr(Config, "KDBX_PASSWORD", password)
    monkeypatch.setattr(Config, "KDBX_PASSWORD_FILE", None)

    # Reset the cached singleton so get_mattstash() creates a fresh instance
    import app.dependencies as deps
    deps._mattstash_instance = None

    instance = get_mattstash()

    assert instance is not None
    assert instance.path == str(db_file)
