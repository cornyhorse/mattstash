# tests/test_core.py
import json
import os
import sys
import subprocess
from pathlib import Path

import pytest

# Import from installed package or src layout
try:
    from mattstash.core import (
        MattStash,
        DEFAULT_KDBX_SIDECAR_BASENAME,
    )
    from pykeepass import PyKeePass
except Exception as e:  # pragma: no cover - helpful error if import fails
    raise


def _read_sidecar(db_path: Path) -> str:
    sidecar = db_path.parent / DEFAULT_KDBX_SIDECAR_BASENAME
    return sidecar.read_text().strip()


@pytest.fixture()
def temp_db(tmp_path: Path) -> Path:
    """Create an isolated directory for each test to hold DB + sidecar."""
    d = tmp_path / "mattstash"
    d.mkdir()
    return d / "test.kdbx"


def test_bootstrap_creates_db_and_sidecar(temp_db: Path):
    assert not temp_db.exists()
    sidecar = temp_db.parent / DEFAULT_KDBX_SIDECAR_BASENAME
    assert not sidecar.exists()

    ms = MattStash(path=str(temp_db))  # triggers bootstrap when both missing

    assert temp_db.exists(), "KDBX database should be created"
    assert sidecar.exists(), "Sidecar password file should be created"

    # Password should resolve from the sidecar
    assert ms.password == _read_sidecar(temp_db)


def test_get_and_list_roundtrip(temp_db: Path):
    ms = MattStash(path=str(temp_db))

    # Open the new DB and add entries
    kp = PyKeePass(str(temp_db), password=ms.password)
    grp = kp.root_group
    kp.add_entry(grp, title="ServiceA", username="alice", password="alicepw", url="https://a.example", notes="n1")
    kp.add_entry(grp, title="ServiceB", username="bob", password="bobpw", url="https://b.example", notes="n2")
    kp.save()

    # list
    creds = ms.list()
    names = {c.credential_name for c in creds}
    assert {"ServiceA", "ServiceB"}.issubset(names)

    # get
    a = ms.get("ServiceA", show_password=True)
    assert a is not None
    assert a.username == "alice"
    assert a.password == "alicepw"
    assert a.url == "https://a.example"


def test_simple_secret_put_get_api(temp_db: Path):
    ms = MattStash(path=str(temp_db))
    # store a simple secret (credstash-like)
    result = ms.put("api-token", value="sekrit")
    assert isinstance(result, dict)
    assert result["name"] == "api-token"
    assert result["value"] == "*****"  # masked by default

    masked = ms.get("api-token")
    assert isinstance(masked, dict)
    assert masked["name"] == "api-token"
    assert masked["value"] == "*****"

    revealed = ms.get("api-token", show_password=True)
    assert isinstance(revealed, dict)
    assert revealed["value"] == "sekrit"


def test_hydrate_env_sets_vars(temp_db: Path, monkeypatch: pytest.MonkeyPatch):
    ms = MattStash(path=str(temp_db))

    kp = PyKeePass(str(temp_db), password=ms.password)
    grp = kp.root_group
    e = kp.add_entry(grp, title="AWS-Creds", username="AKIA_TEST", password="SECRET_TEST", url=None, notes=None)
    # add a custom property via pykeepass API
    e.set_custom_property("REGION", "us-east-1")
    kp.save()

    # ensure env is clean
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    monkeypatch.delenv("AWS_REGION", raising=False)

    ms.hydrate_env({
        "AWS-Creds:AWS_ACCESS_KEY_ID": "AWS_ACCESS_KEY_ID",
        "AWS-Creds:AWS_SECRET_ACCESS_KEY": "AWS_SECRET_ACCESS_KEY",
        "AWS-Creds:REGION": "AWS_REGION",
    })

    assert os.environ.get("AWS_ACCESS_KEY_ID") == "AKIA_TEST"
    assert os.environ.get("AWS_SECRET_ACCESS_KEY") == "SECRET_TEST"
    assert os.environ.get("AWS_REGION") == "us-east-1"


@pytest.mark.parametrize("as_module", [True, False])
def test_cli_list_and_get(temp_db: Path, as_module: bool):
    # Pre-populate DB with one entry
    ms = MattStash(path=str(temp_db))
    kp = PyKeePass(str(temp_db), password=ms.password)
    grp = kp.root_group
    kp.add_entry(grp, title="CLI-Test", username="u", password="p", url="https://cli.example", notes="note")
    kp.save()

    if as_module:
        cmd = [sys.executable, "-m", "mattstash.core", "--db", str(temp_db), "list"]
    else:
        # console-script path (requires pyproject entry point). Still valid to attempt here.
        cmd = ["mattstash", "--db", str(temp_db), "list"]

    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert "CLI-Test" in proc.stdout

    # Now test `get` JSON output
    if as_module:
        cmd = [sys.executable, "-m", "mattstash.core", "--db", str(temp_db), "get", "CLI-Test", "--json"]
    else:
        cmd = ["mattstash", "--db", str(temp_db), "get", "CLI-Test", "--json"]

    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["credential_name"] == "CLI-Test"
    assert payload["username"] == "u"


@pytest.mark.parametrize("as_module", [True, False])
def test_cli_get_simple_secret_json(temp_db: Path, as_module: bool):
    ms = MattStash(path=str(temp_db))
    # create simple secret via API
    ms.put("k", value="v")

    if as_module:
        cmd = [sys.executable, "-m", "mattstash.core", "--db", str(temp_db), "get", "k", "--json"]
    else:
        cmd = ["mattstash", "--db", str(temp_db), "get", "k", "--json"]

    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["name"] == "k"
    assert payload["value"] == "*****"

    # show-password path
    if as_module:
        cmd = [sys.executable, "-m", "mattstash.core", "--db", str(temp_db), "get", "k", "--json", "--show-password"]
    else:
        cmd = ["mattstash", "--db", str(temp_db), "get", "k", "--json", "--show-password"]

    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["name"] == "k"
    assert payload["value"] == "v"


@pytest.mark.skipif("boto3" not in sys.modules and __import__("importlib").util.find_spec("boto3") is None,
                    reason="boto3 not installed")
def test_get_s3_client_builds_without_network(temp_db: Path):
    ms = MattStash(path=str(temp_db))

    # Create an S3 credential entry (endpoint in URL field, key in username, secret in password)
    kp = PyKeePass(str(temp_db), password=ms.password)
    grp = kp.root_group
    kp.add_entry(
        grp,
        title="objectstore",
        username="test-key",
        password="test-secret",
        url="http://127.0.0.1:9000",
        notes=None,
    )
    kp.save()

    client = ms.get_s3_client("objectstore", region="us-east-1", addressing="path", verbose=False)
    # botocore client should have a meta attribute
    assert hasattr(client, "meta")
