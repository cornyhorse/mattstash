"""``delete --version N`` and ``prune --keep N`` (docs/security-review.md L-4)."""

import shutil
from pathlib import Path
from typing import Optional

import pytest
from fake_server import FakeServer

from mattstash import MattStash
from mattstash.cli import exit_codes
from mattstash.cli.main import main

SERVER = "http://localhost:8000"
KEY = "api-key-value"


@pytest.fixture(scope="module")
def template(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A database holding k@1..k@4, an unrelated k2@1 and other@1 (built once, copied per test)."""
    directory = tmp_path_factory.mktemp("versions-template")
    ms = MattStash.create(str(directory / "v.kdbx"), sidecar=True)
    for n in range(1, 5):
        ms.put("k", value=f"k-v{n}")
    ms.put("k2", value="k2-v1")
    ms.put("other", value="other-v1")
    return directory


@pytest.fixture()
def db(template: Path, tmp_path: Path) -> Path:
    target = tmp_path / "copy"
    shutil.copytree(template, target)
    return target / "v.kdbx"


def versions(db: Path, title: str = "k") -> list[str]:
    return MattStash(path=str(db)).list_versions(title)


def value(db: Path, title: str, version: Optional[int] = None) -> Optional[str]:
    found = MattStash(path=str(db)).get(title, show_password=True, version=version)
    if found is None:
        return None
    return found["value"] if isinstance(found, dict) else found.password


def run(db: Path, *argv: str) -> int:
    return main(["--db", str(db), *argv])


# ---------------------------------------------------------------------------
# delete --version
# ---------------------------------------------------------------------------


def test_delete_one_version_keeps_the_others(db: Path, capsys: pytest.CaptureFixture[str]):
    assert run(db, "delete", "k", "--version", "2") == 0
    assert capsys.readouterr().out.strip() == "k@0000000002: deleted"
    assert versions(db) == ["0000000001", "0000000003", "0000000004"]
    assert value(db, "k", 2) is None
    assert value(db, "k", 1) == "k-v1" and value(db, "k") == "k-v4"
    assert versions(db, "k2") == ["0000000001"], "similarly named secrets are untouched"


def test_delete_latest_version_makes_the_previous_one_current(db: Path):
    assert run(db, "delete", "k", "--version", "4") == 0
    assert value(db, "k") == "k-v3"


def test_delete_missing_version_is_exit_2_and_deletes_nothing(
    db: Path, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
):
    assert run(db, "delete", "k", "--version", "9") == exit_codes.NOT_FOUND
    assert capsys.readouterr().out == ""
    assert "not found: k@0000000009" in caplog.text
    assert len(versions(db)) == 4


def test_delete_without_version_still_removes_every_version(db: Path, capsys: pytest.CaptureFixture[str]):
    assert run(db, "delete", "k") == 0
    assert capsys.readouterr().out.strip() == "k: deleted"
    assert versions(db) == [] and value(db, "k") is None
    assert versions(db, "k2") == ["0000000001"]


def test_delete_missing_secret_reports_not_found(db: Path, caplog: pytest.LogCaptureFixture):
    assert run(db, "delete", "nope") == exit_codes.NOT_FOUND
    assert "not found: nope" in caplog.text


@pytest.mark.parametrize("bad", ["-1", "abc", "1.5", ""])
def test_delete_version_must_be_a_non_negative_integer(db: Path, bad: str):
    with pytest.raises(SystemExit):
        run(db, "delete", "k", "--version", bad)
    assert len(versions(db)) == 4


# ---------------------------------------------------------------------------
# prune --keep
# ---------------------------------------------------------------------------


def test_prune_keeps_the_newest_versions(db: Path, capsys: pytest.CaptureFixture[str]):
    assert run(db, "prune", "k", "--keep", "2") == 0
    out = capsys.readouterr().out
    assert "pruned 2 version(s), kept 2" in out
    assert "deleted 0000000001" in out and "deleted 0000000002" in out
    assert versions(db) == ["0000000003", "0000000004"]
    assert value(db, "k") == "k-v4"
    assert versions(db, "k2") == ["0000000001"] and versions(db, "other") == ["0000000001"]


def test_prune_with_nothing_to_do(db: Path, capsys: pytest.CaptureFixture[str]):
    assert run(db, "prune", "k", "--keep", "4") == 0
    assert "nothing to prune" in capsys.readouterr().out
    assert run(db, "prune", "k", "--keep", "10") == 0
    assert len(versions(db)) == 4


def test_prune_keep_one_leaves_only_the_latest(db: Path):
    assert run(db, "prune", "k", "--keep", "1") == 0
    assert versions(db) == ["0000000004"]


@pytest.mark.parametrize("keep", ["0", "-1"])
def test_prune_keep_must_be_at_least_one(db: Path, keep: str, caplog: pytest.LogCaptureFixture):
    assert run(db, "prune", "k", "--keep", keep) == exit_codes.ERROR
    assert "at least 1" in caplog.text
    assert len(versions(db)) == 4


def test_prune_requires_keep_and_a_number(db: Path):
    with pytest.raises(SystemExit):
        run(db, "prune", "k")
    with pytest.raises(SystemExit):
        run(db, "prune", "k", "--keep", "many")
    assert len(versions(db)) == 4


def test_prune_unknown_secret_is_exit_2(db: Path, caplog: pytest.LogCaptureFixture):
    assert run(db, "prune", "nope", "--keep", "1") == exit_codes.NOT_FOUND
    assert "not found" in caplog.text


def test_prune_with_wrong_password_is_a_db_error(db: Path):
    assert run(db, "--password", "wrong", "prune", "k", "--keep", "1") == exit_codes.DB_ACCESS
    assert len(versions(db)) == 4


def test_prune_is_not_supported_in_server_mode(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
):
    server = FakeServer(api_key=KEY).install(monkeypatch)
    server.add("k", "v")
    rc = main(["--server-url", SERVER, "--api-key", KEY, "prune", "k", "--keep", "1"])
    assert rc == exit_codes.ERROR
    assert "not supported in server mode" in caplog.text
    assert server.requests == [], "no request may be sent for an unsupported command"
    assert capsys.readouterr().out == ""


def test_prune_server_mode_via_environment_variable(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture):
    monkeypatch.setenv("MATTSTASH_SERVER_URL", SERVER)
    assert main(["prune", "k", "--keep", "1"]) == exit_codes.ERROR
    assert "not supported in server mode" in caplog.text


# ---------------------------------------------------------------------------
# server mode: delete --version
# ---------------------------------------------------------------------------


@pytest.fixture()
def server(monkeypatch: pytest.MonkeyPatch) -> FakeServer:
    fake = FakeServer(api_key=KEY).install(monkeypatch)
    for n in range(1, 4):
        fake.add("k", f"v{n}")
    return fake


def server_run(*argv: str) -> int:
    return main(["--server-url", SERVER, "--api-key", KEY, *argv])


def test_server_delete_version_sends_the_version(server: FakeServer, capsys: pytest.CaptureFixture[str]):
    assert server_run("delete", "k", "--version", "2") == 0
    request = server.requests[-1]
    assert request.method == "DELETE"
    assert request.url.raw_path.decode() == "/api/v1/credentials/k?version=2"
    assert sorted(server.store["k"]) == [1, 3]
    assert capsys.readouterr().out.strip() == "k@0000000002: deleted"


def test_server_delete_missing_version_is_exit_2(server: FakeServer, caplog: pytest.LogCaptureFixture):
    assert server_run("delete", "k", "--version", "9") == exit_codes.NOT_FOUND
    assert "not found: k@0000000009" in caplog.text
    assert sorted(server.store["k"]) == [1, 2, 3]


def test_server_delete_without_version_sends_no_query(server: FakeServer):
    assert server_run("delete", "k") == 0
    assert server.requests[-1].url.query == b""
    assert "k" not in server.store


def test_server_delete_in_read_only_mode_is_a_clean_error(monkeypatch: pytest.MonkeyPatch, caplog):
    fake = FakeServer(api_key=KEY, allow_writes=False).install(monkeypatch)
    fake.add("k", "v")
    assert server_run("delete", "k", "--version", "1") == exit_codes.ERROR
    assert "HTTP 405" in caplog.text and "read-only" in caplog.text
    assert "secret-looking detail" not in caplog.text
