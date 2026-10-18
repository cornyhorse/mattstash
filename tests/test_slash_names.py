"""``/`` in names is opt-in for writing (MATTSTASH_ALLOW_SLASH_NAMES); existing '/' entries always stay usable."""

import json
from pathlib import Path

import pytest
from dbhelpers import create_db
from fake_server import FakeServer

import mattstash
from mattstash import MattStash
from mattstash.cli import exit_codes
from mattstash.cli.main import main
from mattstash.utils.exceptions import InvalidCredentialError

PW = "test-master-pw"
KEY = "k" * 40


@pytest.fixture()
def db(tmp_path: Path) -> Path:
    """A database that already holds entries with '/' (made by another tool, or before the opt-in rule)."""
    path = create_db(tmp_path / "slash.kdbx", [], password=PW)
    stash = MattStash(path=str(path), password=PW)
    stash.put("cloud/hetzner/s3-key", value="s3-secret", allow_slash=True)
    stash.put("cloud/other", value="o", allow_slash=True)
    stash.put("plain", value="p")
    return path


def run(db: Path, *argv: str) -> int:
    return main(["--db", str(db), "--password", PW, *argv])


def test_put_refuses_a_slash_by_default_and_suggests_a_dot(db: Path):
    stash = MattStash(path=str(db), password=PW)
    with pytest.raises(InvalidCredentialError, match=r"myapp\.db-password"):
        stash.put("myapp/db-password", value="x")
    with pytest.raises(InvalidCredentialError, match="MATTSTASH_ALLOW_SLASH_NAMES"):
        mattstash.put("myapp/db-password", path=str(db), db_password=PW, value="x")
    assert stash.get("myapp/db-password") is None  # nothing was written


def test_put_also_refuses_a_new_version_of_an_existing_slash_entry(db: Path):
    with pytest.raises(InvalidCredentialError):
        MattStash(path=str(db), password=PW).put("cloud/hetzner/s3-key", value="new")


def test_put_with_the_environment_variable_or_argument(db: Path, monkeypatch: pytest.MonkeyPatch):
    stash = MattStash(path=str(db), password=PW)
    stash.put("a/b", value="v1", allow_slash=True)
    monkeypatch.setenv("MATTSTASH_ALLOW_SLASH_NAMES", "true")
    stash.put("a/b", value="v2")
    assert stash.list_versions("a/b") == ["0000000001", "0000000002"]
    with pytest.raises(InvalidCredentialError):  # the segment rules still apply
        stash.put("a//b", value="x")
    with pytest.raises(InvalidCredentialError):
        stash.put("a/../b", value="x")
    with pytest.raises(InvalidCredentialError):
        stash.put("/a", value="x")
    monkeypatch.setenv("MATTSTASH_ALLOW_SLASH_NAMES", "false")
    with pytest.raises(InvalidCredentialError):
        stash.put("a/b", value="v3")


def test_existing_slash_entries_can_be_read_listed_versioned_and_deleted_without_the_flag(db: Path):
    stash = MattStash(path=str(db), password=PW)
    assert stash.get("cloud/hetzner/s3-key", show_password=True)["value"] == "s3-secret"  # type: ignore[index]
    assert {c.credential_name for c in stash.list(latest_only=True)} == {"cloud/hetzner/s3-key", "cloud/other", "plain"}
    assert stash.list_versions("cloud/hetzner/s3-key")
    assert stash.delete("cloud/other") is True
    assert stash.get("cloud/other") is None


def test_cli_local_mode(db: Path, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture):
    assert run(db, "get", "cloud/hetzner/s3-key", "--raw") == 0
    assert capsys.readouterr().out == "s3-secret\n"
    assert run(db, "list", "--json") == 0
    assert "cloud/hetzner/s3-key" in capsys.readouterr().out
    assert run(db, "put", "new/name", "--value", "x") == exit_codes.ERROR
    assert "use '.' as the separator" in caplog.text
    assert MattStash(path=str(db), password=PW).get("new/name") is None  # not written


def test_cli_delete_of_an_existing_slash_entry(db: Path):
    assert run(db, "delete", "cloud/other") == 0
    assert MattStash(path=str(db), password=PW).get("cloud/other") is None


def test_cli_put_with_the_variable(db: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("MATTSTASH_ALLOW_SLASH_NAMES", "1")
    assert run(db, "put", "new/name", "--value", "x") == 0
    assert MattStash(path=str(db), password=PW).get("new/name", show_password=True)["value"] == "x"  # type: ignore[index]


def test_cli_server_mode_refuses_before_sending_anything(monkeypatch: pytest.MonkeyPatch, caplog):
    server = FakeServer(api_key=KEY).install(monkeypatch)
    base = ["--server-url", "http://localhost:8000", "--api-key", KEY]
    assert main([*base, "put", "cloud/new", "--value", "x"]) == exit_codes.ERROR
    assert "use '.' as the separator" in caplog.text
    assert "SERVER must also have MATTSTASH_ALLOW_SLASH_NAMES" in caplog.text
    assert server.requests == [] and server.store == {}


def test_cli_server_mode_with_the_variable_uses_path_routes(monkeypatch: pytest.MonkeyPatch, capsys):
    server = FakeServer(api_key=KEY).install(monkeypatch)
    monkeypatch.setenv("MATTSTASH_ALLOW_SLASH_NAMES", "true")
    base = ["--server-url", "http://localhost:8000", "--api-key", KEY]
    assert main([*base, "put", "cloud/hetzner/s3-key", "--value", "x"]) == 0
    assert list(server.store) == ["cloud/hetzner/s3-key"]
    server.store["cloud/versions"] = server.store["cloud/hetzner/s3-key"]  # an entry that predates the rule
    capsys.readouterr()
    assert main([*base, "versions", "cloud/versions", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == ["0000000001"]
    paths = [r.url.raw_path.decode() for r in server.requests]
    assert paths[0] == "/api/v1/credentials/cloud/hetzner/s3-key"
    assert "/api/v1/versions/cloud/versions" in paths


def _seed_reserved(db: Path) -> None:
    """An entry whose last segment is 'versions', as one made before the rule (or by another tool) would be."""
    from unittest import mock

    with (
        mock.patch("mattstash.core.entry_manager.validate_credential_title"),
        mock.patch("mattstash.core.mattstash.validate_credential_title"),
    ):
        MattStash(path=str(db), password=PW).put("cloud/versions", value="old", allow_slash=True)


def test_a_last_segment_of_versions_is_refused_for_writing(db: Path, monkeypatch: pytest.MonkeyPatch, caplog):
    monkeypatch.setenv("MATTSTASH_ALLOW_SLASH_NAMES", "true")
    stash = MattStash(path=str(db), password=PW)
    for name in ("cloud/versions", "versions/versions", "a/b/versions"):
        with pytest.raises(InvalidCredentialError, match="versions route"):
            stash.put(name, value="x")
        assert stash.get(name) is None
    assert run(db, "put", "cloud/versions", "--value", "x") == exit_codes.ERROR
    assert "versions route" in caplog.text
    # only the exact, case-sensitive LAST segment is reserved
    for name in ("versions", "versions/x", "cloud/Versions", "cloud/versions2", "cloud/my-versions"):
        stash.put(name, value="ok")


def test_an_existing_entry_named_versions_stays_listable_readable_and_deletable(
    db: Path, monkeypatch: pytest.MonkeyPatch, capsys
):
    _seed_reserved(db)
    stash = MattStash(path=str(db), password=PW)
    assert stash.get("cloud/versions", show_password=True)["value"] == "old"  # type: ignore[index]
    assert "cloud/versions@0000000001" in {c.credential_name for c in stash.list()}
    assert run(db, "get", "cloud/versions", "--raw") == 0
    assert capsys.readouterr().out == "old\n"
    with pytest.raises(InvalidCredentialError):  # but it cannot get a new version
        monkeypatch.setenv("MATTSTASH_ALLOW_SLASH_NAMES", "true")
        stash.put("cloud/versions", value="new")
    assert run(db, "delete", "cloud/versions") == 0
    assert stash.get("cloud/versions") is None
