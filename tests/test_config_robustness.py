"""Regression tests for defects found while covering the configuration layer: a settings file must never be able to
stop ``import mattstash``, every documented key must be read, and values mean what their YAML spelling says."""

import logging
from pathlib import Path

import pytest

from mattstash.models.config import MattStashConfig
from mattstash.utils import config_loader, logging_config
from mattstash.utils.config_loader import merge_config

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
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    for name in _CONFIG_ENV:
        monkeypatch.delenv(name, raising=False)
    return fake_home


def write_config(home: Path, text: str) -> None:
    path = home / ".config" / "mattstash" / "config.yml"
    path.parent.mkdir(parents=True)
    path.write_text(text)


def test_the_documented_s3_signature_version_key_is_read(home: Path):
    write_config(home, "s3:\n  signature_version: s3\n")
    assert MattStashConfig().default_signature_version == "s3"


def test_the_environment_still_beats_the_file_for_the_signature_version(home: Path, monkeypatch: pytest.MonkeyPatch):
    write_config(home, "s3:\n  signature_version: s3\n")
    monkeypatch.setenv("MATTSTASH_S3_SIGNATURE_VERSION", "s3v4")
    assert MattStashConfig().default_signature_version == "s3v4"


@pytest.mark.parametrize(
    ("section", "key", "attribute", "default"),
    [
        ("versioning", "pad_width", "version_pad_width", 10),
        ("s3", "retries", "default_retries", 10),
        ("cache", "ttl", "cache_ttl", 300),
    ],
)
def test_a_malformed_number_in_the_file_is_ignored_with_a_warning_not_an_import_error(
    home: Path, caplog: pytest.LogCaptureFixture, section: str, key: str, attribute: str, default: int
):
    write_config(home, f"{section}:\n  {key}: lots\n")
    with caplog.at_level(logging.WARNING, logger="mattstash.models.config"):
        config = MattStashConfig()
    assert getattr(config, attribute) == default
    assert f"{section}.{key}" in caplog.text and "expected an integer" in caplog.text


def test_numbers_written_as_strings_in_the_file_still_work(home: Path):
    write_config(home, 'versioning:\n  pad_width: "7"\ncache:\n  ttl: "60"\n')
    config = MattStashConfig()
    assert (config.version_pad_width, config.cache_ttl) == (7, 60)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("true", True),
        ("false", False),
        ('"false"', False),
        ('"no"', False),
        ('"Yes"', True),
        ('"on"', True),
        ("0", False),
    ],
)
def test_booleans_in_the_file_mean_what_they_say_even_when_quoted(home: Path, text: str, expected: bool):
    write_config(home, f"cache:\n  enabled: {text}\nlogging:\n  verbose: {text}\n")
    config = MattStashConfig()
    assert config.cache_enabled is expected and config.verbose is expected


def test_a_boolean_that_is_not_one_is_ignored_with_a_warning(home: Path, caplog: pytest.LogCaptureFixture):
    write_config(home, "cache:\n  enabled: maybe\nlogging:\n  verbose: sometimes\n")
    with caplog.at_level(logging.WARNING, logger="mattstash.models.config"):
        config = MattStashConfig()
    assert config.cache_enabled is False and config.verbose is False
    assert "cache.enabled" in caplog.text and "logging.verbose" in caplog.text


def test_a_top_level_list_or_scalar_is_not_a_configuration(home: Path, caplog: pytest.LogCaptureFixture):
    for text in ("- a\n- b\n", "just a string\n", "42\n"):
        write_config_path = home / ".mattstash.yml"
        write_config_path.write_text(text)
        with caplog.at_level(logging.WARNING, logger="mattstash.utils.config_loader"):
            assert config_loader.load_yaml_config() == {}
        assert "must contain a mapping" in caplog.text
        caplog.clear()


def test_merge_config_does_not_alias_or_modify_its_inputs():
    file_config = {"database": {"path": "/file"}, "s3": {"region": "eu"}}
    env_config = {"database": {"path": "/env"}}
    cli_config = {"s3": {"retries": 3}}
    merged = merge_config(file_config, env_config, cli_config)
    assert merged == {"database": {"path": "/env"}, "s3": {"region": "eu", "retries": 3}}
    assert file_config == {"database": {"path": "/file"}, "s3": {"region": "eu"}}, "the inputs are left as they were"
    merged["s3"]["region"] = "changed"
    assert file_config["s3"]["region"] == "eu"


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("debug", logging.DEBUG),
        (" Warn ", logging.WARNING),
        ("fatal", logging.CRITICAL),
        ("basic_format", logging.WARNING),  # a string constant of the logging module, not a level
        ("verbose", logging.WARNING),
        ("", logging.WARNING),
    ],
)
def test_log_level_names_that_are_not_levels_fall_back_to_warning(name: str, expected: int):
    assert logging_config._parse_level(name) == expected


def test_a_log_level_variable_that_is_not_a_level_does_not_break_the_logger(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(logging_config, "_logger", None)
    monkeypatch.setenv("MATTSTASH_LOG_LEVEL", "BASIC_FORMAT")
    name = "mattstash.test-robustness-logger"
    try:
        assert logging_config.get_logger(name).level == logging.WARNING
    finally:
        logger = logging.getLogger(name)
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
