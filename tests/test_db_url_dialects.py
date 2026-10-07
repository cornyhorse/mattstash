"""``db-url`` for MySQL/MariaDB as well as PostgreSQL (docs/security-review.md L-8)."""

from pathlib import Path
from typing import Dict, Optional
from urllib.parse import unquote, urlsplit

import pytest
from dbhelpers import create_db
from fake_server import FakeServer

from mattstash import MattStash, get_db_url
from mattstash.builders.db_url import (
    AUTO_DRIVER,
    DIALECT_DRIVERS,
    DatabaseUrlBuilder,
    build_db_url,
    normalize_dialect,
    resolve_driver,
)
from mattstash.cli import exit_codes
from mattstash.cli.main import main
from mattstash.models.credential import Credential

SERVER = "http://localhost:8000"
KEY = "api-key-value"


class FakeStash:
    """Just enough of MattStash for the URL builder: one credential plus its custom properties."""

    def __init__(self, props: Optional[Dict[str, str]] = None, **cred_overrides: Optional[str]) -> None:
        fields: Dict[str, Optional[str]] = {"username": "app", "password": "pw", "url": "db.internal:3306"}
        fields.update(cred_overrides)
        self.cred = Credential(
            credential_name="db",
            username=fields["username"],
            password=fields["password"],
            url=fields["url"],
            notes=None,
            tags=[],
        )
        self.props: Dict[str, str] = {"database": "orders", **(props or {})}

    def get_entry_with_properties(self, title: str, names: tuple[str, ...] = ()):
        return self.cred, {n: self.props.get(n) for n in names}


def url_of(stash: FakeStash, **kwargs) -> str:
    kwargs.setdefault("mask_password", False)
    return DatabaseUrlBuilder(stash).build_url("db", **kwargs)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# backward compatibility: PostgreSQL stays the default
# ---------------------------------------------------------------------------


def test_default_dialect_is_postgresql_without_driver():
    assert url_of(FakeStash()) == "postgresql://app:pw@db.internal:3306/orders"


@pytest.mark.parametrize("driver", sorted(DIALECT_DRIVERS["postgresql"]))
def test_postgresql_drivers(driver: str):
    assert url_of(FakeStash(), driver=driver) == f"postgresql+{driver}://app:pw@db.internal:3306/orders"


def test_build_db_url_default_driver_is_still_psycopg_for_postgresql():
    assert AUTO_DRIVER == "auto"
    assert build_db_url(FakeStash(), "db", mask_password=False) == "postgresql+psycopg://app:pw@db.internal:3306/orders"  # type: ignore[arg-type]


def test_sslmode_on_postgresql_is_unchanged():
    assert url_of(FakeStash({"sslmode": "require"})).endswith("/orders?sslmode=require")
    assert url_of(FakeStash(), sslmode_override="verify-full").endswith("?sslmode=verify-full")
    assert url_of(FakeStash({"sslmode": "require"}), sslmode_override="disable").endswith("?sslmode=disable")
    with pytest.raises(ValueError, match="Invalid sslmode"):
        url_of(FakeStash({"sslmode": "bogus"}))


# ---------------------------------------------------------------------------
# dialect + driver allow-list
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "dialect,driver",
    [(d, drv) for d, drivers in sorted(DIALECT_DRIVERS.items()) for drv in sorted(drivers)],
)
def test_every_allowed_combination_builds(dialect: str, driver: str):
    assert url_of(FakeStash(), dialect=dialect, driver=driver) == f"{dialect}+{driver}://app:pw@db.internal:3306/orders"


@pytest.mark.parametrize("dialect", ["mysql", "mariadb"])
def test_no_driver_gives_a_plain_scheme(dialect: str):
    assert url_of(FakeStash(), dialect=dialect) == f"{dialect}://app:pw@db.internal:3306/orders"


@pytest.mark.parametrize(
    "dialect,driver",
    [
        ("mysql", "psycopg"),
        ("mysql", "mariadbconnector"),
        ("mysql", "asyncpg"),
        ("mariadb", "aiomysql"),
        ("mariadb", "mysqlconnector"),
        ("postgresql", "pymysql"),
        ("postgresql", "mariadbconnector"),
    ],
)
def test_driver_must_belong_to_the_dialect(dialect: str, driver: str):
    with pytest.raises(ValueError, match="not valid") as excinfo:
        url_of(FakeStash(), dialect=dialect, driver=driver)
    assert dialect in str(excinfo.value) and "expected one of" in str(excinfo.value)


@pytest.mark.parametrize(
    "driver", ["psycopg@evil.com/x", "psy copg", "psycopg3", "x?y=1", "../etc", "mysql", "psycopg;"]
)
def test_unknown_or_hostile_drivers_are_rejected(driver: str):
    with pytest.raises(ValueError, match="not valid"):
        url_of(FakeStash(), driver=driver)


@pytest.mark.parametrize("dialect", ["sqlite", "oracle", "postgres", "mssql", "mysql://evil/", "pg+psycopg", "'; drop"])
def test_unknown_dialects_are_rejected(dialect: str):
    with pytest.raises(ValueError, match="Unsupported dialect"):
        url_of(FakeStash(), dialect=dialect)


def test_unknown_dialect_is_rejected_before_any_lookup():
    class Exploding:
        def get_entry_with_properties(self, *args, **kwargs):
            raise AssertionError("the database must not be consulted for an invalid argument")

    with pytest.raises(ValueError, match="Unsupported dialect"):
        DatabaseUrlBuilder(Exploding()).build_url("db", dialect="oracle")  # type: ignore[arg-type]


def test_dialect_and_driver_are_case_and_whitespace_insensitive():
    assert (
        url_of(FakeStash(), dialect=" MySQL ", driver=" PyMySQL ") == "mysql+pymysql://app:pw@db.internal:3306/orders"
    )


def test_auto_driver():
    assert url_of(FakeStash(), driver="auto") == "postgresql+psycopg://app:pw@db.internal:3306/orders"
    assert url_of(FakeStash(), driver="auto", dialect="mysql") == "mysql://app:pw@db.internal:3306/orders"
    assert url_of(FakeStash(), driver="auto", dialect="mariadb") == "mariadb://app:pw@db.internal:3306/orders"
    assert url_of(FakeStash(), driver="") == "postgresql://app:pw@db.internal:3306/orders"


def test_dialect_helpers():
    assert normalize_dialect(None) == normalize_dialect("") == normalize_dialect("  ") == "postgresql"
    assert normalize_dialect("MariaDB") == "mariadb"
    assert resolve_driver("mysql", None) is None
    assert resolve_driver("mysql", "PyMySQL") == "pymysql"
    with pytest.raises(ValueError):
        resolve_driver("mysql", "psycopg")


# ---------------------------------------------------------------------------
# the entry's `dialect` custom property
# ---------------------------------------------------------------------------


def test_dialect_property_is_used():
    assert url_of(FakeStash({"dialect": "mysql"}), driver="pymysql") == "mysql+pymysql://app:pw@db.internal:3306/orders"
    assert url_of(FakeStash({"dialect": "mariadb"})) == "mariadb://app:pw@db.internal:3306/orders"


def test_dialect_argument_overrides_the_property():
    stash = FakeStash({"dialect": "mysql"})
    assert url_of(stash, dialect="mariadb") == "mariadb://app:pw@db.internal:3306/orders"
    assert url_of(stash, dialect="postgresql", driver="psycopg2").startswith("postgresql+psycopg2://")


def test_invalid_dialect_property_is_a_clear_error():
    with pytest.raises(ValueError, match="'dialect' property"):
        url_of(FakeStash({"dialect": "oracle"}))


def test_driver_is_validated_against_the_dialect_from_the_property():
    with pytest.raises(ValueError, match="not valid for mysql"):
        url_of(FakeStash({"dialect": "mysql"}), driver="psycopg")


# ---------------------------------------------------------------------------
# sslmode is PostgreSQL-only
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("dialect", ["mysql", "mariadb"])
def test_sslmode_override_is_rejected_for_other_dialects(dialect: str):
    with pytest.raises(ValueError, match="only supported for postgresql"):
        url_of(FakeStash(), dialect=dialect, sslmode_override="require")


def test_sslmode_property_is_rejected_for_other_dialects_instead_of_silently_dropped():
    with pytest.raises(ValueError, match="only supported for postgresql"):
        url_of(FakeStash({"dialect": "mysql", "sslmode": "require"}))
    with pytest.raises(ValueError, match="only supported for postgresql"):
        url_of(FakeStash({"sslmode": "require"}), dialect="mysql")


def test_empty_sslmode_property_is_ignored_for_other_dialects():
    assert url_of(FakeStash({"sslmode": ""}), dialect="mysql") == "mysql://app:pw@db.internal:3306/orders"


# ---------------------------------------------------------------------------
# encoding and masking are unchanged for the new dialects
# ---------------------------------------------------------------------------


def test_special_characters_are_percent_encoded_for_mysql():
    stash = FakeStash(username="ap p@corp", password="p@ss/w:rd#1?x=y%")
    parts = urlsplit(url_of(stash, dialect="mysql", driver="pymysql", database="my db/prod"))
    assert (parts.scheme, parts.hostname, parts.port) == ("mysql+pymysql", "db.internal", 3306)
    assert unquote(parts.username or "") == "ap p@corp" and unquote(parts.password or "") == "p@ss/w:rd#1?x=y%"
    assert unquote(parts.path) == "/my db/prod"
    assert parts.query == "" and parts.fragment == ""


def test_masking_styles_for_mysql():
    stash = FakeStash()
    assert url_of(stash, dialect="mysql", mask_password=True) == "mysql://app:*****@db.internal:3306/orders"
    assert (
        url_of(stash, dialect="mysql", mask_password=True, mask_style="omit") == "mysql://app@db.internal:3306/orders"
    )
    assert "pw" not in url_of(stash, dialect="mysql", mask_password=True)


# ---------------------------------------------------------------------------
# real database, Python API, CLI
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def dbs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    cred = {"username": "app", "password": "s3cret", "url": "db.internal:3306"}
    return create_db(
        tmp_path_factory.mktemp("dialects") / "d.kdbx",
        [
            {"title": "pg", **cred, "url": "db.internal:5432", "props": {"database": "orders", "sslmode": "require"}},
            {"title": "my", **cred, "props": {"database": "shop", "dialect": "mysql"}},
            {"title": "maria", **cred, "props": {"dbname": "blog", "dialect": "MariaDB"}},
            {"title": "my-ssl", **cred, "props": {"database": "shop", "dialect": "mysql", "sslmode": "require"}},
            {"title": "bad-dialect", **cred, "props": {"database": "x", "dialect": "oracle"}},
        ],
    )


def run(db: Path, *argv: str) -> int:
    return main(["--db", str(db), *argv])


def test_python_api_dialect_argument_and_property(dbs: Path):
    ms = MattStash(path=str(dbs))
    assert ms.get_db_url("pg", mask_password=False) == "postgresql://app:s3cret@db.internal:5432/orders?sslmode=require"
    assert ms.get_db_url("my", driver="pymysql") == "mysql+pymysql://app:*****@db.internal:3306/shop"
    assert ms.get_db_url("maria", mask_password=False) == "mariadb://app:s3cret@db.internal:3306/blog"
    assert ms.get_db_url("my", dialect="mariadb", driver="mariadbconnector").startswith("mariadb+mariadbconnector://")
    with pytest.raises(ValueError, match="only supported for postgresql"):
        ms.get_db_url("my-ssl")
    with pytest.raises(ValueError, match="'dialect' property"):
        ms.get_db_url("bad-dialect")


def test_module_level_get_db_url_passes_dialect_through(dbs: Path):
    with pytest.raises(ValueError, match="only supported for postgresql"):
        get_db_url("pg", path=str(dbs), dialect="mysql")  # pg carries an sslmode property
    url = get_db_url("my", path=str(dbs), dialect="mysql", driver="aiomysql", mask_password=False)
    assert url == "mysql+aiomysql://app:s3cret@db.internal:3306/shop"


def test_build_db_url_function_with_dialect(dbs: Path):
    ms = MattStash(path=str(dbs))
    assert build_db_url(ms, "my", dialect="mysql", mask_password=False) == "mysql://app:s3cret@db.internal:3306/shop"
    assert build_db_url(ms, "pg", mask_password=False).startswith("postgresql+psycopg://")


def test_cli_dialect_flag_and_driver(dbs: Path, capsys: pytest.CaptureFixture[str]):
    assert run(dbs, "db-url", "my", "--dialect", "mysql", "--driver", "pymysql", "--mask-password", "false") == 0
    assert capsys.readouterr().out.strip() == "mysql+pymysql://app:s3cret@db.internal:3306/shop"
    assert run(dbs, "db-url", "my", "--dialect", "mariadb", "--driver", "mariadbconnector") == 0
    assert capsys.readouterr().out.strip() == "mariadb+mariadbconnector://app@db.internal:3306/shop"


def test_cli_default_driver_is_dialect_aware(dbs: Path, capsys: pytest.CaptureFixture[str]):
    assert run(dbs, "db-url", "pg") == 0  # unchanged default: psycopg for PostgreSQL
    assert capsys.readouterr().out.strip() == "postgresql+psycopg://app@db.internal:5432/orders?sslmode=require"
    assert run(dbs, "db-url", "my") == 0  # the entry's dialect property; no driver for MySQL
    assert capsys.readouterr().out.strip() == "mysql://app@db.internal:3306/shop"
    assert run(dbs, "db-url", "maria") == 0
    assert capsys.readouterr().out.strip() == "mariadb://app@db.internal:3306/blog"
    assert run(dbs, "db-url", "pg", "--driver", "") == 0
    assert capsys.readouterr().out.strip() == "postgresql://app@db.internal:5432/orders?sslmode=require"


def test_cli_dialect_overrides_the_property(dbs: Path, capsys: pytest.CaptureFixture[str]):
    assert run(dbs, "db-url", "my", "--dialect", "mariadb") == 0
    assert capsys.readouterr().out.strip() == "mariadb://app@db.internal:3306/shop"


@pytest.mark.parametrize(
    "argv,fragment",
    [
        (["db-url", "pg", "--dialect", "oracle"], "Unsupported dialect"),
        (["db-url", "my", "--driver", "psycopg"], "not valid for mysql"),
        (["db-url", "pg", "--driver", "psycopg@evil/"], "not valid for postgresql"),
        (["db-url", "my-ssl"], "only supported for postgresql"),
        (["db-url", "bad-dialect"], "'dialect' property"),
    ],
)
def test_cli_errors_exit_5_with_a_message(
    dbs: Path, argv: list[str], fragment: str, caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
):
    assert run(dbs, *argv) == exit_codes.DB_URL_FAILED
    assert fragment in caplog.text
    assert capsys.readouterr().out == "", "no URL may be printed on error"


def test_cli_help_lists_dialects_and_drivers(capsys: pytest.CaptureFixture[str]):
    with pytest.raises(SystemExit):
        main(["db-url", "--help"])
    text = " ".join(capsys.readouterr().out.split())
    for expected in ("--dialect", "mysql", "mariadb", "pymysql", "mariadbconnector", "PostgreSQL-only"):
        assert expected in text, expected


# ---------------------------------------------------------------------------
# server mode (the server is wired separately; the CLI just forwards the options)
# ---------------------------------------------------------------------------


@pytest.fixture()
def server(monkeypatch: pytest.MonkeyPatch) -> FakeServer:
    return FakeServer(api_key=KEY).install(monkeypatch)


def sent_params(server: FakeServer) -> Dict[str, str]:
    return dict(server.requests[-1].url.params)


def test_server_mode_forwards_dialect_and_driver(server: FakeServer, capsys: pytest.CaptureFixture[str]):
    base = ["--server-url", SERVER, "--api-key", KEY]
    assert main([*base, "db-url", "m", "--dialect", "mysql", "--driver", "pymysql", "--database", "shop"]) == 0
    assert sent_params(server) == {"mask_password": "true", "driver": "pymysql", "dialect": "mysql", "database": "shop"}
    assert capsys.readouterr().out.startswith("fake://m?")


def test_server_mode_default_sends_no_driver_or_dialect(server: FakeServer):
    base = ["--server-url", SERVER, "--api-key", KEY]
    assert main([*base, "db-url", "pg"]) == 0
    assert sent_params(server) == {"mask_password": "true"}, (
        "the server resolves the defaults (psycopg / entry dialect)"
    )
    assert main([*base, "db-url", "pg", "--driver", "psycopg2"]) == 0
    assert sent_params(server) == {"mask_password": "true", "driver": "psycopg2"}
