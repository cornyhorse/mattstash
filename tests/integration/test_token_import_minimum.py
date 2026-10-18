"""``token import`` against a real server whose MATTSTASH_MIN_KEY_LENGTH is higher than the CLI's own default."""

from typing import Generator, NamedTuple

import pytest

from mattstash import MattStash
from mattstash.authz import edit_policy

from .conftest import DB_PASSWORD, _require_server_dependencies, _running_server, _scrubbed_environment, run_cli


class Strict(NamedTuple):
    url: str
    admin_token: str


@pytest.fixture(scope="module")
def strict(tmp_path_factory: pytest.TempPathFactory) -> Generator[Strict, None, None]:
    _require_server_dependencies()
    workdir = tmp_path_factory.mktemp("strict-min")
    db_path = workdir / "strict.kdbx"
    MattStash.create(str(db_path), password=DB_PASSWORD, sidecar=False)
    policy = workdir / "policy.json"
    with edit_policy(policy, create=True) as editor:
        editor.add_principal("matt", "human-device", "admin", admin=True)
        editor.add_principal("bot", "agent", "client to migrate")
        editor.add_grant("bot", key="app.*", actions=["list", "read"])
        _, token = editor.issue_token("matt")
    extra = {"MATTSTASH_POLICY_FILE": str(policy), "MATTSTASH_MIN_KEY_LENGTH": "40"}
    with _running_server(workdir, db_path, extra) as url:
        yield Strict(url, token)


def _import(strict: Strict, key: str, *args: str):
    env = {**_scrubbed_environment(), "MATTSTASH_SERVER_URL": strict.url, "MATTSTASH_API_KEY": strict.admin_token}
    return run_cli(["admin", "token", "import", "bot", *args], env, input=key + "\n")


def test_the_servers_higher_minimum_applies_without_and_with_a_lower_min_length_option(strict: Strict):
    key = "client-key-" + "m" * 29  # 40 characters: exactly the server's minimum
    short = "client-key-" + "m" * 25  # 36 characters: fine for the CLI's old default of 32
    for args in ((), ("--min-length", "20"), ("--min-length", "36")):
        refused = _import(strict, short, *args)
        assert refused.returncode != 0 and "shorter than 40" in refused.stderr, args
        assert short not in refused.stdout + refused.stderr
    accepted = _import(strict, key)
    assert accepted.returncode == 0, accepted.stderr
    env = {**_scrubbed_environment(), "MATTSTASH_SERVER_URL": strict.url, "MATTSTASH_API_KEY": key}
    assert run_cli(["list", "--json"], env).returncode == 0  # the imported key authenticates as bot
    stricter = _import(strict, "q" * 45, "--min-length", "50")  # a request can raise the minimum
    assert stricter.returncode != 0 and "shorter than 50" in stricter.stderr
