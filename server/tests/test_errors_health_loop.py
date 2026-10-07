"""Error mapping (H-4c), health vs readiness (H-6a), event-loop responsiveness (M-2) and the key tool."""

import asyncio
import json
import logging
import time

import httpx
import pytest
from mattstash import MattStash
from mattstash.utils.exceptions import (
    DatabaseAccessError,
    DatabaseLockError,
    DatabaseNotFoundError,
    InvalidCredentialError,
)

from .conftest import FULL_KEY, auth

H = auth()


# ---------------------------------------------------------------------------
# error mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("error", [DatabaseNotFoundError("x"), DatabaseAccessError("y"), DatabaseLockError("z")])
def test_database_problems_are_503_never_404(rw_client, monkeypatch, error):
    """A wrong password/missing DB/lock timeout used to look like 'secret not found'."""
    for method in ("get", "list", "list_versions", "put", "delete", "get_entry_with_properties"):
        monkeypatch.setattr(MattStash, method, lambda *a, _e=error, **k: (_ for _ in ()).throw(_e))
    responses = [
        rw_client.get("/api/v1/credentials/x", headers=H),
        rw_client.get("/api/v1/credentials", headers=H),
        rw_client.get("/api/v1/credentials/x/versions", headers=H),
        rw_client.post("/api/v1/credentials/x", json={"value": "v"}, headers=H),
        rw_client.delete("/api/v1/credentials/x", headers=H),
        rw_client.get("/api/v1/db-url/x?database=d", headers=H),
    ]
    for response in responses:
        assert response.status_code == 503
        assert response.json() == {"detail": "Service temporarily unavailable"}
        assert response.headers["retry-after"] == "5"


def test_invalid_credential_data_is_400_with_the_validation_message(rw_client, monkeypatch):
    monkeypatch.setattr(
        MattStash, "put", lambda *a, **k: (_ for _ in ()).throw(InvalidCredentialError("Username too long"))
    )
    response = rw_client.post("/api/v1/credentials/x", json={"value": "v"}, headers=H)
    assert response.status_code == 400 and response.json() == {"detail": "Username too long"}


def test_unexpected_errors_are_500_without_leaking_details(rw_client, monkeypatch, caplog):
    monkeypatch.setattr(MattStash, "get", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("internal-secret-detail")))
    caplog.set_level(logging.ERROR, logger="mattstash.api")
    response = rw_client.get("/api/v1/credentials/x", headers=H)
    assert response.status_code == 500
    assert response.json() == {"detail": "Internal server error"}
    assert "internal-secret-detail" not in response.text + caplog.text
    assert "RuntimeError" in caplog.text  # the type is logged for operators


def test_key_store_failure_is_503_not_500(make_client, monkeypatch):
    client = make_client()
    import app.dependencies as deps

    monkeypatch.setattr(deps, "authenticate", lambda key: (_ for _ in ()).throw(OSError("disk")))
    assert client.get("/api/v1/credentials", headers=H).status_code == 503


def test_database_replaced_with_wrong_password_is_503_and_recovers(client, db_path, seed):
    """If someone swaps in a database with a different password the server reports 503, then recovers."""
    seed(x={"value": "1"})
    assert client.get("/api/v1/credentials/x", headers=H).status_code == 200
    good = db_path.read_bytes()

    MattStash.create(str(db_path), password="a-completely-different-password", force=True, backup=False)
    assert client.get("/api/v1/credentials/x", headers=H).status_code == 503

    db_path.write_bytes(good)
    assert client.get("/api/v1/credentials/x", headers=H).status_code == 200


# ---------------------------------------------------------------------------
# health / readiness
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/health", "/api/health"])
def test_health_at_both_paths(client, path):
    """k8s probes and the README use /health; the historic path was /api/health only."""
    response = client.get(path)
    assert response.status_code == 200 and response.json() == {"status": "healthy", "version": "v1"}


@pytest.mark.parametrize("path", ["/ready", "/api/ready"])
def test_ready_reflects_database_access(client, path):
    assert client.get(path).json() == {"status": "ready", "version": "v1"}


def test_ready_is_503_without_details_when_the_database_fails(client, monkeypatch, caplog):
    monkeypatch.setattr(MattStash, "list_versions", lambda *a, **k: (_ for _ in ()).throw(DatabaseAccessError("nope")))
    caplog.set_level(logging.ERROR, logger="mattstash.api")
    response = client.get("/ready")
    assert response.status_code == 503 and response.json() == {"detail": "Not ready"}
    assert "nope" not in response.text


def test_health_never_touches_the_database(client, monkeypatch):
    def boom(*_a, **_k):
        raise AssertionError("liveness must not touch the database")

    monkeypatch.setattr(MattStash, "list_versions", boom)
    monkeypatch.setattr(MattStash, "get", boom)
    assert client.get("/health").status_code == 200


# ---------------------------------------------------------------------------
# event loop stays responsive while a write is in progress
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_slow_writes_do_not_block_health_probes(configure, monkeypatch):
    """Each real write takes ~0.5 s (re-encrypting the database); it used to freeze the whole server."""
    configure(ALLOW_WRITES=True)
    from app.main import create_app

    def slow_put(self, *args, **kwargs):
        time.sleep(1.2)
        return {"name": args[0], "version": "0000000001", "value": "*****", "notes": None}

    monkeypatch.setattr(MattStash, "put", slow_put)
    transport = httpx.ASGITransport(app=create_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        write = asyncio.create_task(http.post("/api/v1/credentials/slow", json={"value": "v"}, headers=H))
        await asyncio.sleep(0.2)  # the write is now running
        latencies = []
        for _ in range(10):
            started = time.monotonic()
            assert (await http.get("/health")).status_code == 200
            latencies.append(time.monotonic() - started)
            await asyncio.sleep(0.05)
        assert not write.done(), "the write should still be in flight while we probe"
        assert max(latencies) < 0.3, f"health probe stalled for {max(latencies):.2f}s"
        assert (await write).status_code == 201


# ---------------------------------------------------------------------------
# key tool
# ---------------------------------------------------------------------------


def test_keytool_generates_a_strong_key_and_hashed_entry(capsys):
    from app.keytool import main
    from app.security.api_keys import _parse_policy_entry

    assert main(["--id", "billing", "--ops", "read,write", "--prefix", "billing-", "--prefix", "shared-"]) == 0
    captured = capsys.readouterr()
    key = captured.err.split("give it to the client): ")[1].strip()
    entry = json.loads(captured.out)

    assert len(key) >= 32 and key not in captured.out  # the key is never in the policy output
    assert (
        entry["id"] == "billing" and entry["ops"] == ["read", "write"] and entry["prefixes"] == ["billing-", "shared-"]
    )
    record = _parse_policy_entry(entry, 1)  # the generated entry is valid policy
    assert record.principal.allows_name("billing-db") and not record.principal.allows_name("other")


def test_keytool_hashes_an_existing_key_from_stdin(monkeypatch, capsys):
    import hashlib
    import io

    from app.keytool import main

    monkeypatch.setattr("sys.stdin", io.StringIO(FULL_KEY + "\n"))
    assert main(["--id", "ci", "--stdin"]) == 0
    entry = json.loads(capsys.readouterr().out)
    assert entry["key_sha256"] == hashlib.sha256(FULL_KEY.encode()).hexdigest() and entry["ops"] == ["read"]


def test_keytool_rejects_bad_ops(capsys):
    from app.keytool import main

    with pytest.raises(SystemExit):
        main(["--id", "x", "--ops", "read,root"])
    with pytest.raises(SystemExit):
        main(["--id", "x", "--ops", ""])


def test_keytool_output_works_end_to_end(make_client, tmp_path, seed, capsys):
    from app.keytool import main

    seed(app__db={"value": "v"})
    assert main(["--id", "app", "--ops", "read", "--prefix", "app-"]) == 0
    out = capsys.readouterr()
    key = out.err.split("give it to the client): ")[1].strip()
    policy = tmp_path / "generated.json"
    policy.write_text(json.dumps({"keys": [json.loads(out.out)]}))

    client = make_client(API_KEY=None, API_KEYS_FILE=str(policy))
    assert client.get("/api/v1/credentials/app-db", headers=auth(key)).status_code == 200
    assert client.get("/api/v1/credentials/zzz", headers=auth(key)).status_code == 404
