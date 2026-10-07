"""Coverage for the configuration layer (models/config.py, utils/config_loader.py, utils/logging_config.py), the
S3 builder's simple-secret refusal and the remaining corners of the CLI's HTTP client.

Nothing here touches the developer's real configuration: ``HOME`` is redirected to a temporary directory for every test
(``Path.home()`` is what the config loader searches), and every ``MATTSTASH_*`` variable the config reads is cleared.
"""

import dataclasses
import json
import logging
import sys
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Optional

import httpx
import pytest
from fake_server import FakeServer

from mattstash import MattStash
from mattstash.cli import http_client
from mattstash.cli.http_client import MattStashServerClient
from mattstash.models.config import MattStashConfig
from mattstash.utils import config_loader, logging_config
from mattstash.utils.config_loader import create_example_config, get_config_value, load_yaml_config, merge_config
from mattstash.utils.exceptions import ServerError

KEY = "k3y-s3cret-AAAA"
URL = "http://localhost:8000"

_CONFIG_ENV = (
    "MATTSTASH_DB_PATH",
    "MATTSTASH_SIDECAR_BASENAME",
    "MATTSTASH_VERSION_PAD_WIDTH",
    "MATTSTASH_PASSWORD_MASK",
    "MATTSTASH_S3_REGION",
    "MATTSTASH_S3_ADDRESSING",
    "MATTSTASH_S3_SIGNATURE_VERSION",
    "MATTSTASH_S3_RETRIES",
    "MATTSTASH_ENABLE_CACHE",
    "MATTSTASH_CACHE_TTL",
    "MATTSTASH_LOG_LEVEL",
)


@pytest.fixture(autouse=True)
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A private, empty home directory; ``Path.home()`` (and so the config search path) points at it."""
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("USERPROFILE", str(fake_home))  # Path.home() on Windows
    for name in _CONFIG_ENV:
        monkeypatch.delenv(name, raising=False)
    assert Path.home() == fake_home
    return fake_home


def write_config(home: Path, text: str, *, dotfile: bool = False) -> Path:
    """Write ``text`` to one of the two places ``load_yaml_config`` searches under ``home``."""
    path = home / ".mattstash.yml" if dotfile else home / ".config" / "mattstash" / "config.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


@pytest.fixture()
def yaml_installed() -> None:
    """PyYAML is the optional ``config`` extra; the tests that really parse YAML need it."""
    pytest.importorskip("yaml")


FULL_FILE = """\
database:
  path: /data/stash.kdbx
  sidecar_basename: .side.txt
versioning:
  pad_width: "7"
logging:
  level: DEBUG
  verbose: true
s3:
  region: eu-central-1
  addressing: virtual
  retries: 2
cache:
  enabled: true
  ttl: 60
"""


# ---------------------------------------------------------------------------
# models/config.py: defaults and environment variables
# ---------------------------------------------------------------------------

DEFAULTS: dict[str, Any] = {
    "default_db_path": "~/.config/mattstash/mattstash.kdbx",
    "sidecar_basename": ".mattstash.txt",
    "version_pad_width": 10,
    "password_mask": "*****",
    "default_region": "us-east-1",
    "default_addressing": "path",
    "default_signature_version": "s3v4",
    "default_retries": 10,
    "cache_enabled": False,
    "cache_ttl": 300,
    "log_level": "INFO",
    "verbose": False,
}


def test_defaults_without_environment_or_file():
    assert dataclasses.asdict(MattStashConfig()) == DEFAULTS


@pytest.mark.parametrize(
    ("var", "attr", "raw", "expected"),
    [
        ("MATTSTASH_DB_PATH", "default_db_path", "/tmp/elsewhere.kdbx", "/tmp/elsewhere.kdbx"),
        ("MATTSTASH_SIDECAR_BASENAME", "sidecar_basename", ".side.txt", ".side.txt"),
        ("MATTSTASH_VERSION_PAD_WIDTH", "version_pad_width", "6", 6),
        ("MATTSTASH_PASSWORD_MASK", "password_mask", "####", "####"),
        ("MATTSTASH_S3_REGION", "default_region", "eu-west-2", "eu-west-2"),
        ("MATTSTASH_S3_ADDRESSING", "default_addressing", "virtual", "virtual"),
        ("MATTSTASH_S3_SIGNATURE_VERSION", "default_signature_version", "s3", "s3"),
        ("MATTSTASH_S3_RETRIES", "default_retries", "3", 3),
        ("MATTSTASH_ENABLE_CACHE", "cache_enabled", "true", True),
        ("MATTSTASH_CACHE_TTL", "cache_ttl", "42", 42),
        ("MATTSTASH_LOG_LEVEL", "log_level", "DEBUG", "DEBUG"),
    ],
)
def test_each_environment_variable_sets_exactly_its_setting(
    monkeypatch: pytest.MonkeyPatch, var: str, attr: str, raw: str, expected: object
):
    monkeypatch.setenv(var, raw)
    loaded = dataclasses.asdict(MattStashConfig())
    assert loaded.pop(attr) == expected
    assert loaded == {k: v for k, v in DEFAULTS.items() if k != attr}


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("true", True), ("1", True), ("yes", True), ("YES", True), ("no", False), ("0", False), ("off", False)],
)
def test_cache_flag_spellings(monkeypatch: pytest.MonkeyPatch, raw: str, expected: bool):
    monkeypatch.setenv("MATTSTASH_ENABLE_CACHE", raw)
    assert MattStashConfig().cache_enabled is expected


def test_empty_environment_variables_are_ignored(monkeypatch: pytest.MonkeyPatch):
    for name in _CONFIG_ENV:
        monkeypatch.setenv(name, "")
    assert dataclasses.asdict(MattStashConfig()) == DEFAULTS


# ---------------------------------------------------------------------------
# models/config.py: the configuration file
# ---------------------------------------------------------------------------


def test_config_file_values_are_applied(home: Path, yaml_installed: None):
    write_config(home, FULL_FILE)
    assert dataclasses.asdict(MattStashConfig()) == {
        **DEFAULTS,
        "default_db_path": "/data/stash.kdbx",
        "sidecar_basename": ".side.txt",
        "version_pad_width": 7,  # a quoted number in the file is still an int
        "log_level": "DEBUG",
        "verbose": True,
        "default_region": "eu-central-1",
        "default_addressing": "virtual",
        "default_retries": 2,
        "cache_enabled": True,
        "cache_ttl": 60,
    }


def test_environment_beats_the_config_file(home: Path, monkeypatch: pytest.MonkeyPatch, yaml_installed: None):
    write_config(home, FULL_FILE)
    monkeypatch.setenv("MATTSTASH_DB_PATH", "/env/stash.kdbx")
    monkeypatch.setenv("MATTSTASH_SIDECAR_BASENAME", ".env.txt")
    monkeypatch.setenv("MATTSTASH_VERSION_PAD_WIDTH", "3")
    monkeypatch.setenv("MATTSTASH_LOG_LEVEL", "ERROR")
    monkeypatch.setenv("MATTSTASH_S3_REGION", "ap-south-1")
    monkeypatch.setenv("MATTSTASH_S3_ADDRESSING", "path")
    monkeypatch.setenv("MATTSTASH_S3_RETRIES", "9")
    monkeypatch.setenv("MATTSTASH_ENABLE_CACHE", "false")
    monkeypatch.setenv("MATTSTASH_CACHE_TTL", "5")
    cfg = MattStashConfig()
    assert cfg.default_db_path == "/env/stash.kdbx"
    assert cfg.sidecar_basename == ".env.txt"
    assert cfg.version_pad_width == 3
    assert cfg.log_level == "ERROR"
    assert cfg.default_region == "ap-south-1"
    assert cfg.default_addressing == "path"
    assert cfg.default_retries == 9
    assert cfg.cache_enabled is False
    assert cfg.cache_ttl == 5
    assert cfg.verbose is True, "there is no environment variable for verbose, so the file's value applies"


def test_dotfile_in_home_is_read_when_the_xdg_style_file_is_absent(home: Path, yaml_installed: None):
    write_config(home, "s3:\n  region: us-west-1\n", dotfile=True)
    assert MattStashConfig().default_region == "us-west-1"


def test_empty_or_non_mapping_config_files_change_nothing(home: Path, yaml_installed: None):
    path = write_config(home, "")
    assert dataclasses.asdict(MattStashConfig()) == DEFAULTS
    path.write_text("- just\n- a list\n")
    assert dataclasses.asdict(MattStashConfig()) == DEFAULTS
    path.write_text("# only a comment\n\ndatabase:\n  path:\n")  # a key without a value is None: keep the default
    assert dataclasses.asdict(MattStashConfig()) == DEFAULTS


def test_a_broken_config_file_is_skipped_with_a_warning(
    home: Path, caplog: pytest.LogCaptureFixture, yaml_installed: None
):
    write_config(home, "database: [unclosed\n")
    with caplog.at_level(logging.WARNING, logger=config_loader.logger.name):
        assert dataclasses.asdict(MattStashConfig()) == DEFAULTS
    assert "Failed to load config from" in caplog.text


def test_unavailable_config_loader_falls_back_to_defaults(home: Path, monkeypatch: pytest.MonkeyPatch):
    write_config(home, FULL_FILE)
    monkeypatch.delattr(
        config_loader, "load_yaml_config"
    )  # ``from ... import load_yaml_config`` now raises ImportError
    monkeypatch.setenv("MATTSTASH_S3_REGION", "eu-north-1")
    cfg = MattStashConfig()
    assert cfg.default_region == "eu-north-1", "the environment still applies"
    assert cfg.default_db_path == DEFAULTS["default_db_path"], "the file is not consulted"


# ---------------------------------------------------------------------------
# utils/config_loader.py
# ---------------------------------------------------------------------------


def test_no_config_file_gives_an_empty_mapping():
    assert load_yaml_config() == {}


def test_load_reads_the_xdg_style_file(home: Path, yaml_installed: None):
    write_config(home, "database:\n  path: /a.kdbx\nlist: [1, 2]\n")
    assert load_yaml_config() == {"database": {"path": "/a.kdbx"}, "list": [1, 2]}


def test_load_falls_back_to_the_dotfile(home: Path, yaml_installed: None):
    write_config(home, "database:\n  path: /dot.kdbx\n", dotfile=True)
    assert load_yaml_config() == {"database": {"path": "/dot.kdbx"}}


def test_the_xdg_style_file_wins_over_the_dotfile(home: Path, yaml_installed: None):
    write_config(home, "name: xdg\n")
    write_config(home, "name: dot\nonly_in_dot: 1\n", dotfile=True)
    assert load_yaml_config() == {"name": "xdg"}


def test_an_empty_file_is_an_empty_mapping(home: Path, yaml_installed: None):
    write_config(home, "")
    assert load_yaml_config() == {}


def test_a_broken_first_file_is_logged_and_the_next_one_is_tried(
    home: Path, caplog: pytest.LogCaptureFixture, yaml_installed: None
):
    broken = write_config(home, "key: [unclosed\n")
    write_config(home, "name: dot\n", dotfile=True)
    with caplog.at_level(logging.WARNING, logger=config_loader.logger.name):
        assert load_yaml_config() == {"name": "dot"}
    assert f"Failed to load config from {broken}" in caplog.text


def test_an_unreadable_config_path_is_logged_and_skipped(home: Path, caplog: pytest.LogCaptureFixture):
    # A directory where the file should be: exists() is true, open() fails the same way for root and for everyone else.
    (home / ".config" / "mattstash" / "config.yml").mkdir(parents=True)
    with caplog.at_level(logging.WARNING, logger=config_loader.logger.name):
        assert load_yaml_config() == {}
    assert "Failed to load config from" in caplog.text


def test_without_pyyaml_the_file_is_ignored(
    home: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
):
    write_config(home, FULL_FILE)
    monkeypatch.setitem(sys.modules, "yaml", None)  # makes ``import yaml`` raise ImportError
    with caplog.at_level(logging.INFO, logger=config_loader.logger.name):
        assert load_yaml_config() == {}
        assert config_loader._load_yaml_file(home / ".config" / "mattstash" / "config.yml") == {}
        assert dataclasses.asdict(MattStashConfig()) == DEFAULTS
    assert "PyYAML not installed" in caplog.text


def test_merge_config_precedence_and_deep_merge():
    file_cfg = {"database": {"path": "/file", "sidecar_basename": ".file"}, "cache": {"ttl": 1}, "only_file": True}
    env_cfg = {"database": {"path": "/env"}, "s3": {"region": "env-region"}}
    cli_cfg = {"database": {"path": "/cli"}, "cache": {"enabled": True}, "scalar_over_dict": 1}
    merged = merge_config(file_cfg, env_cfg, cli_cfg)
    assert merged == {
        "database": {"path": "/cli", "sidecar_basename": ".file"},
        "cache": {"ttl": 1, "enabled": True},
        "s3": {"region": "env-region"},
        "only_file": True,
        "scalar_over_dict": 1,
    }


def test_merge_config_replaces_a_mapping_with_a_scalar_and_the_reverse():
    assert merge_config({"a": {"x": 1}}, {"a": "text"}, {}) == {"a": "text"}
    assert merge_config({"a": "text"}, {"a": {"x": 1}}, {}) == {"a": {"x": 1}}
    assert merge_config({}, {}, {}) == {}


def test_get_config_value_walks_nested_keys():
    cfg = {"database": {"path": "/db", "empty": None}, "flat": 3}
    assert get_config_value(cfg, "database", "path") == "/db"
    assert get_config_value(cfg, "flat") == 3
    assert get_config_value(cfg, "database", "empty", default="fallback") is None, "a present None is a value"
    assert get_config_value(cfg, "missing", "key", default="fallback") == "fallback"
    assert get_config_value(cfg, "database", "nope") is None
    assert get_config_value(cfg, "flat", "deeper", default="fallback") == "fallback", "cannot descend into a scalar"
    assert get_config_value(cfg) == cfg, "no keys: the whole mapping"


def test_example_config_is_returned_and_not_written_without_a_path(home: Path):
    text = create_example_config()
    assert text.startswith("# MattStash Configuration File")
    assert list(home.iterdir()) == []


def test_example_config_is_written_creating_parent_directories(tmp_path: Path):
    target = tmp_path / "new" / "dirs" / "config.yml"
    text = create_example_config(target)
    assert target.read_text() == text
    # An existing file is overwritten, not appended to.
    target.write_text("stale")
    assert create_example_config(target) == text
    assert target.read_text() == text


def test_example_config_is_valid_yaml_and_matches_the_defaults(home: Path, tmp_path: Path, yaml_installed: None):
    import yaml

    text = create_example_config()
    parsed = yaml.safe_load(text)
    assert set(parsed) == {"database", "versioning", "logging", "s3", "cache"}
    assert parsed["database"]["path"] == DEFAULTS["default_db_path"]
    assert parsed["s3"]["region"] == DEFAULTS["default_region"]
    # Installing the example as the user's config must not change any setting.
    create_example_config(home / ".config" / "mattstash" / "config.yml")
    assert dataclasses.asdict(MattStashConfig()) == DEFAULTS


# ---------------------------------------------------------------------------
# utils/logging_config.py
# ---------------------------------------------------------------------------


@pytest.fixture()
def logger_state(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """Let a test create loggers and change levels without leaking into the rest of the suite.

    ``get_logger`` caches the last logger it handed out in a module global and attaches a handler bound to the
    *current* ``sys.stderr`` (a pytest capture stream that is closed after the test), so all of it is put back.
    Yields the list of logger names the test created.
    """
    package_logger = logging.getLogger("mattstash")
    saved_level = package_logger.level
    saved_handlers = list(package_logger.handlers)
    monkeypatch.setattr(logging_config, "_logger", None)
    created: list[str] = []
    yield created
    package_logger.setLevel(saved_level)
    package_logger.handlers[:] = saved_handlers
    for name in created:
        logging.getLogger(name).handlers.clear()
        logging.Logger.manager.loggerDict.pop(name, None)


def test_get_logger_defaults_to_warning(logger_state: list[str], monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("MATTSTASH_LOG_LEVEL", raising=False)
    logger_state.append("mattstash.covtest.default")
    log = logging_config.get_logger("mattstash.covtest.default")
    assert log.level == logging.WARNING
    assert len(log.handlers) == 1
    assert log.handlers[0].formatter is not None and log.handlers[0].formatter._fmt == "[%(name)s] %(message)s"
    assert logging_config.get_logger("mattstash.covtest.default") is log, "the same name is served from the cache"
    assert len(log.handlers) == 1


def test_get_logger_level_comes_from_the_environment(logger_state: list[str], monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("MATTSTASH_LOG_LEVEL", "debug")
    logger_state.append("mattstash.covtest.env")
    assert logging_config.get_logger("mattstash.covtest.env").level == logging.DEBUG


def test_get_logger_ignores_an_unknown_level_in_the_environment(
    logger_state: list[str], monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("MATTSTASH_LOG_LEVEL", "LOUD")
    logger_state.append("mattstash.covtest.bad")
    assert logging_config.get_logger("mattstash.covtest.bad").level == logging.WARNING


def test_get_logger_does_not_stack_handlers_on_an_already_configured_logger(
    logger_state: list[str], monkeypatch: pytest.MonkeyPatch
):
    logger_state.append("mattstash.covtest.twice")
    first = logging_config.get_logger("mattstash.covtest.twice")
    monkeypatch.setattr(logging_config, "_logger", None)  # forget the cache: the logging module still has the logger
    second = logging_config.get_logger("mattstash.covtest.twice")
    assert second is first
    assert len(first.handlers) == 1


def test_configure_logging_sets_the_package_logger_level(logger_state: list[str]):
    logging_config.configure_logging("debug")
    assert logging.getLogger("mattstash").level == logging.DEBUG
    logging_config.configure_logging("ERROR")
    assert logging.getLogger("mattstash").level == logging.ERROR


def test_configure_logging_falls_back_to_warning_for_an_unknown_level(logger_state: list[str]):
    logging_config.configure_logging("DEBUG")
    logging_config.configure_logging("shouting")
    assert logging.getLogger("mattstash").level == logging.WARNING


def test_configure_logging_default_is_warning(logger_state: list[str]):
    logging_config.configure_logging("DEBUG")
    logging_config.configure_logging()
    assert logging.getLogger("mattstash").level == logging.WARNING


def test_security_warning_is_prefixed(logger_state: list[str], caplog: pytest.LogCaptureFixture):
    logger = logging_config.get_logger()
    logger.setLevel(logging.WARNING)
    with caplog.at_level(logging.WARNING, logger="mattstash"):
        logging_config.security_warning("key file is world readable")
    assert "[SECURITY] key file is world readable" in caplog.text


# ---------------------------------------------------------------------------
# builders/s3_client.py
# ---------------------------------------------------------------------------


def test_get_s3_client_refuses_a_simple_secret(temp_db: Path):
    ms = MattStash(path=str(temp_db))
    ms.put("just-a-value", value="opaque")
    with pytest.raises(ValueError, match="simple secret, cannot use for S3 client"):
        ms.get_s3_client("just-a-value")


# ---------------------------------------------------------------------------
# cli/http_client.py
# ---------------------------------------------------------------------------


@pytest.fixture()
def server(monkeypatch: pytest.MonkeyPatch) -> FakeServer:
    return FakeServer(api_key=KEY).install(monkeypatch)


@pytest.fixture()
def client(server: FakeServer) -> Iterator[MattStashServerClient]:
    with MattStashServerClient(URL, KEY) as c:
        yield c


class Chunked(httpx.SyncByteStream):
    """A response body without a Content-Length: only counting the bytes can bound it."""

    def __init__(self, *chunks: bytes) -> None:
        self.chunks = chunks

    def __iter__(self) -> Iterator[bytes]:
        yield from self.chunks


def test_unusable_proxy_settings_count_as_a_proxy(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture):
    monkeypatch.setattr(urllib.request, "getproxies", lambda: {"http": "http://proxy.invalid:3128"})

    def unreadable(host: str) -> bool:
        raise OSError("proxy settings are unreadable")

    monkeypatch.setattr(urllib.request, "proxy_bypass", unreadable)
    assert http_client._http_proxy_applies("localhost") is True
    with caplog.at_level(logging.WARNING, logger=http_client.logger.name):
        assert http_client.warn_if_insecure("http://localhost:8000") is True, "loopback is not safe behind a proxy"
    assert "clear text" in caplog.text


def test_client_is_a_context_manager_that_closes_the_pool(server: FakeServer):
    server.add("x", "v")
    with MattStashServerClient(URL, KEY) as c:
        assert c.get("x", show_password=True) is not None
        assert c._client is not None
    assert c._client is None

    with pytest.raises(RuntimeError, match="boom"), MattStashServerClient(URL, KEY) as c2:
        raise RuntimeError("boom")  # the exit hook must not swallow the exception
    assert c2._client is None


def test_a_400_with_a_body_that_is_not_json_has_no_detail(server: FakeServer, client: MattStashServerClient):
    server.override = lambda r: httpx.Response(400, content=b"<html>Bad Request: secret-looking text</html>")
    with pytest.raises(ServerError) as excinfo:
        client.get("x")
    assert excinfo.value.status_code == 400
    assert str(excinfo.value).endswith("(the server rejected the request (invalid name or parameter))")
    assert "secret-looking" not in str(excinfo.value)


def test_an_oversized_error_page_is_cut_off_but_still_reported(
    server: FakeServer, client: MattStashServerClient, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(http_client, "_MAX_ERROR_BODY_BYTES", 100)
    server.override = lambda r: httpx.Response(502, stream=Chunked(b"a" * 60, b"SECRET" * 20, b"c" * 60))
    with pytest.raises(ServerError) as excinfo:
        client.list()
    assert excinfo.value.status_code == 502
    assert str(excinfo.value) == "server returned HTTP 502 for GET /api/v1/credentials (server-side error)"


def test_the_part_of_an_oversized_404_that_was_read_still_identifies_a_missing_secret(
    server: FakeServer, client: MattStashServerClient, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(http_client, "_MAX_ERROR_BODY_BYTES", 100)
    first = b'{"detail": "Credential not found: x"}'
    server.override = lambda r: httpx.Response(404, stream=Chunked(first, b"z" * 200))
    assert client.get("x") is None


def test_put_sends_url_and_tags(server: FakeServer, client: MattStashServerClient):
    result = client.put("svc", username="u", password="p", url="https://svc.example.com", tags=["prod", "db"])
    assert result["name"] == "svc"
    body = json.loads(server.requests[-1].content)
    assert body == {"username": "u", "password": "p", "url": "https://svc.example.com", "tags": ["prod", "db"]}
    assert server.store["svc"][1]["url"] == "https://svc.example.com"


def test_put_leaves_out_empty_tags_and_a_missing_url(server: FakeServer, client: MattStashServerClient):
    client.put("svc", password="p", tags=[])
    assert json.loads(server.requests[-1].content) == {"password": "p"}


def test_db_url_with_an_empty_url_is_an_error(server: FakeServer, client: MattStashServerClient):
    def empty(request: httpx.Request) -> Optional[httpx.Response]:
        return httpx.Response(200, json={"url": ""}) if "/db-url/" in request.url.path else None

    server.override = empty
    with pytest.raises(ServerError, match=r"empty 'url'"):
        client.db_url("db")
