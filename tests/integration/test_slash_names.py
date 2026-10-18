"""``/`` in names over HTTP: opt-in on both sides (MATTSTASH_ALLOW_SLASH_NAMES), against a real server subprocess."""

from typing import Dict, Generator, NamedTuple

import pytest

from mattstash import MattStash
from mattstash.authz import edit_policy

from .conftest import DB_PASSWORD, _require_server_dependencies, _running_server, _scrubbed_environment, run_cli


class Slash(NamedTuple):
    url: str
    token: str


def _start(tmp_path_factory: pytest.TempPathFactory, allow: bool) -> Generator[Slash, None, None]:
    _require_server_dependencies()
    workdir = tmp_path_factory.mktemp("slash-on" if allow else "slash-off")
    db_path = workdir / "slash.kdbx"
    MattStash.create(str(db_path), password=DB_PASSWORD, sidecar=False)
    policy = workdir / "policy.json"
    with edit_policy(policy, create=True) as editor:
        editor.add_principal("writer", "agent", "slash tests")
        editor.add_grant("writer", key="cloud/*", actions=["list", "read", "write", "delete"])
        editor.add_grant("writer", key="plain", actions=["list", "read", "write", "delete"])
        _, token = editor.issue_token("writer")
    extra = {"MATTSTASH_POLICY_FILE": str(policy)}
    if allow:
        extra["MATTSTASH_ALLOW_SLASH_NAMES"] = "true"
    with _running_server(workdir, db_path, extra) as url:
        yield Slash(url, token)


@pytest.fixture(scope="module")
def slash_on(tmp_path_factory: pytest.TempPathFactory) -> Generator[Slash, None, None]:
    yield from _start(tmp_path_factory, True)


@pytest.fixture(scope="module")
def slash_off(tmp_path_factory: pytest.TempPathFactory) -> Generator[Slash, None, None]:
    yield from _start(tmp_path_factory, False)


def env(server: Slash, client_flag: bool) -> Dict[str, str]:
    out = {**_scrubbed_environment(), "MATTSTASH_SERVER_URL": server.url, "MATTSTASH_API_KEY": server.token}
    if client_flag:
        out["MATTSTASH_ALLOW_SLASH_NAMES"] = "true"
    return out


def test_slash_names_round_trip_through_the_cli_when_both_sides_opt_in(slash_on: Slash):
    e = env(slash_on, True)
    assert run_cli(["put", "cloud/hetzner/s3-key", "--value", "s3-secret"], e).returncode == 0
    assert run_cli(["put", "cloud/hetzner/s3-key", "--value", "s3-secret-2"], e).returncode == 0
    got = run_cli(["get", "cloud/hetzner/s3-key", "--raw"], e)
    assert got.returncode == 0 and got.stdout == "s3-secret-2\n"
    listed = run_cli(["list", "--json"], e)
    assert "cloud/hetzner/s3-key" in listed.stdout
    versions = run_cli(["versions", "cloud/hetzner/s3-key", "--json"], e)
    assert versions.returncode == 0 and '"0000000002"' in versions.stdout
    assert run_cli(["put", "cloud/versions", "--value", "named-versions"], e).returncode == 0
    ambiguous = run_cli(["versions", "cloud/versions", "--json"], e)
    assert ambiguous.returncode == 0 and "0000000001" in ambiguous.stdout
    assert run_cli(["delete", "cloud/hetzner/s3-key"], e).returncode == 0
    assert run_cli(["get", "cloud/hetzner/s3-key", "--raw"], e).returncode != 0


def test_the_cli_refuses_a_slash_name_without_its_own_opt_in(slash_on: Slash):
    result = run_cli(["put", "cloud/nope", "--value", "x"], env(slash_on, False))
    assert result.returncode != 0 and "use '.' as the separator" in result.stderr
    assert run_cli(["get", "cloud/nope", "--raw"], env(slash_on, True)).returncode != 0  # and nothing was stored


def test_a_server_without_the_opt_in_keeps_slash_names_invalid(slash_off: Slash):
    result = run_cli(["put", "cloud/nope", "--value", "x"], env(slash_off, True))
    assert result.returncode != 0 and "ALLOW_SLASH_NAMES" in result.stderr  # the 404 hint names the server setting
    assert run_cli(["put", "plain", "--value", "x"], env(slash_off, False)).returncode == 0
    assert run_cli(["versions", "plain", "--json"], env(slash_off, False)).returncode == 0
    assert "cloud/nope" not in run_cli(["list", "--json"], env(slash_off, True)).stdout
