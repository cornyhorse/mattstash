"""
Regression tests for the findings in docs/security-review.md (library side).

Each test documents the defect it guards in its docstring/ID so a failure points straight at
the relevant section of the review.
"""

import os
import stat
import subprocess
import sys
import threading
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

import pytest
from pykeepass import PyKeePass

from mattstash import MattStash
from mattstash.credential_store import CredentialStore
from mattstash.utils.exceptions import (
    DatabaseAccessError,
    DatabaseLockError,
    InvalidCredentialError,
)
from mattstash.utils.filelock import FileLock
from mattstash.version_manager import parse_version_suffix

INJECTIONS = [
    'zz" or "a"="a',
    'nope" or contains(.,"prod") or "a"="b',
    '" or ""="',
    "zz' or 'a'='a",
    ".*",
    "prod-db-.*",
    "[",
]


def titles(ms: MattStash) -> list[str]:
    return sorted(c.credential_name for c in ms.list())


@pytest.fixture()
def stash(temp_db: Path) -> MattStash:
    ms = MattStash(path=str(temp_db))
    ms.put("prod-db-password", value="TOP-SECRET-1", autoincrement=False)
    ms.put("other", value="x", autoincrement=False)
    return ms


# ---------------------------------------------------------------------------
# H-1 XPath injection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("payload", INJECTIONS)
def test_h1_get_with_injection_payload_finds_nothing(stash: MattStash, payload: str):
    assert stash.get(payload, show_password=True) is None


@pytest.mark.parametrize("payload", INJECTIONS)
def test_h1_delete_with_injection_payload_deletes_nothing(stash: MattStash, payload: str):
    before = titles(stash)
    assert stash.delete(payload) is False
    assert titles(stash) == before


@pytest.mark.parametrize("payload", INJECTIONS)
def test_h1_versions_with_injection_payload_is_empty(stash: MattStash, payload: str):
    assert stash.list_versions(payload) == []


@pytest.mark.parametrize("payload", INJECTIONS)
def test_h1_db_url_and_hydrate_ignore_injection(stash: MattStash, payload: str, monkeypatch):
    with pytest.raises(ValueError, match="not found"):
        stash.get_db_url(payload)
    monkeypatch.delenv("H1_PROBE", raising=False)
    stash.hydrate_env({f"{payload}:AWS_SECRET_ACCESS_KEY": "H1_PROBE"})
    assert "H1_PROBE" not in os.environ


def test_h1_quote_characters_in_titles_round_trip(stash: MattStash):
    """pykeepass' own add_entry() duplicate check also builds XPath; creation must not use it."""
    for title in ['quo"te', "apo'strophe", 'x" or "a"="a', "[brackets]", "plain"]:
        stash.put(title, value=f"v-{title}", autoincrement=False)
        assert stash.get(title, show_password=True)["value"] == f"v-{title}"
    # previously-existing entries were never touched
    assert stash.get("prod-db-password", show_password=True)["value"] == "TOP-SECRET-1"


def test_h1_versioned_title_with_quote(stash: MattStash):
    stash.put('we"ird', value="1")
    stash.put('we"ird', value="2")
    assert stash.list_versions('we"ird') == ["0000000001", "0000000002"]
    assert stash.get('we"ird', show_password=True)["value"] == "2"
    assert stash.delete('we"ird') is True
    assert stash.get('we"ird') is None


def test_h1_custom_property_names_are_not_interpolated(temp_db: Path, monkeypatch):
    ms = MattStash(path=str(temp_db))
    ms.put("svc", username="u", password="p", url="h:1")
    monkeypatch.delenv("H1_PROP", raising=False)
    ms.hydrate_env({'svc:x"] | //Value | //*[@a="': "H1_PROP"})  # must not raise, must not match
    assert "H1_PROP" not in os.environ


def test_h1_externally_created_titles_remain_reachable(temp_db: Path):
    """Lookups are validated lightly so titles made by other KeePass tools still work."""
    ms = MattStash(path=str(temp_db))
    kp = PyKeePass(str(temp_db), password=ms.password)
    kp.add_entry(kp.root_group, title="AWS/prod/readonly", username="u", password="p", url="x")
    kp.add_entry(kp.root_group, title=".hidden title", username="", password="s")
    kp.save()
    assert ms.get("AWS/prod/readonly", show_password=True).password == "p"
    assert ms.get(".hidden title", show_password=True)["value"] == "s"
    assert ms.delete("AWS/prod/readonly") is True


@pytest.mark.parametrize("bad", ["", "x" * 256, "nul\0byte"])
def test_h1_lookup_titles_are_sanity_checked(stash: MattStash, bad: str):
    for call in (stash.get, stash.delete, stash.list_versions):
        with pytest.raises(InvalidCredentialError):
            call(bad)


# ---------------------------------------------------------------------------
# H-4c typed errors vs "not found"
# ---------------------------------------------------------------------------


def test_h4c_missing_secret_is_none_but_database_errors_raise(temp_db: Path):
    good = MattStash(path=str(temp_db))
    assert good.get("nope") is None
    assert good.delete("nope") is False
    assert good.list_versions("nope") == []

    bad = MattStash(path=str(temp_db), password="WRONG")
    for call in (lambda: bad.get("x"), lambda: bad.delete("x"), bad.list, lambda: bad.list_versions("x")):
        with pytest.raises(DatabaseAccessError):
            call()
    with pytest.raises(DatabaseAccessError):
        bad.put("x", value="v")


def test_h4c_corrupt_file_is_an_access_error(tmp_path: Path):
    db = tmp_path / "corrupt.kdbx"
    db.write_bytes(b"definitely not a keepass file")
    with pytest.raises(DatabaseAccessError):
        MattStash(path=str(db), password="x").get("a")


# ---------------------------------------------------------------------------
# H-5 lost updates, rollback, thread / process safety
# ---------------------------------------------------------------------------


def test_h5_two_instances_do_not_lose_each_others_writes(temp_db: Path):
    a, b = MattStash(path=str(temp_db)), MattStash(path=str(temp_db))
    a.put("seed", value="s")
    a.get("seed")  # A now holds the DB in memory
    b.put("written-by-B", value="B")  # B writes behind A's back
    a.put("written-by-A", value="A")  # A must reload before writing, not overwrite

    final = MattStash(path=str(temp_db))
    assert titles(final) == ["seed@0000000001", "written-by-A@0000000001", "written-by-B@0000000001"]


def test_h5_reads_see_external_writes_without_polling(temp_db: Path):
    a, b = MattStash(path=str(temp_db)), MattStash(path=str(temp_db))
    assert a.get("late") is None
    b.put("late", value="here")
    assert a.get("late", show_password=True)["value"] == "here"


def test_h5_change_detection_survives_identical_mtime(temp_db: Path):
    """Detection uses (inode, mtime_ns, size), not float-mtime equality."""
    a, b = MattStash(path=str(temp_db)), MattStash(path=str(temp_db))
    a.put("one", value="1")
    stat_before = os.stat(temp_db)
    b.put("two", value="2")
    os.utime(temp_db, ns=(stat_before.st_atime_ns, stat_before.st_mtime_ns))  # pretend nothing changed
    assert a.get("two", show_password=True)["value"] == "2"


def _fail_next_save(ms: MattStash):
    store = ms._credential_store
    assert store is not None and store._kp is not None

    def boom(*args, **kwargs):
        raise OSError(30, "Read-only file system")

    store._kp.save = boom


def test_h5_failed_put_leaves_no_phantom_entry(temp_db: Path):
    ms = MattStash(path=str(temp_db))
    ms.put("keep", value="1")
    _fail_next_save(ms)
    with pytest.raises(DatabaseAccessError, match="Could not save"):  # typed, not a raw OSError
        ms.put("phantom", value="never-persisted")

    assert ms.get("phantom") is None  # not visible in memory...
    assert titles(MattStash(path=str(temp_db))) == ["keep@0000000001"]  # ...nor on disk
    ms.put("after", value="ok")  # the instance recovers on its own
    assert titles(ms) == ["after@0000000001", "keep@0000000001"]


def test_h5_failed_delete_does_not_hide_a_secret_that_is_still_on_disk(temp_db: Path):
    ms = MattStash(path=str(temp_db))
    ms.put("keep", value="1")
    _fail_next_save(ms)
    with pytest.raises(DatabaseAccessError, match="Could not save"):
        ms.delete("keep")
    assert ms.get("keep", show_password=True)["value"] == "1"


def test_h5_validation_errors_do_not_need_disk_state_reset(temp_db: Path):
    ms = MattStash(path=str(temp_db))
    ms.put("ok", value="1")
    store_before = ms._credential_store
    with pytest.raises(InvalidCredentialError):
        ms.put("bad/title", value="x")
    assert ms._credential_store is store_before  # validated before any lock/state was touched


_WRITER = """
import sys
from mattstash import MattStash
db, tag, count = sys.argv[1], sys.argv[2], int(sys.argv[3])
ms = MattStash(path=db, password=sys.argv[4])
for i in range(count):
    ms.put(f"{tag}-{i}", value="v", autoincrement=False)
"""


def test_h5_concurrent_processes_do_not_lose_writes(temp_db: Path):
    password = MattStash(path=str(temp_db)).password
    procs = [subprocess.Popen([sys.executable, "-c", _WRITER, str(temp_db), f"p{n}", "2", password]) for n in range(3)]
    assert [p.wait(timeout=120) for p in procs] == [0, 0, 0]
    assert titles(MattStash(path=str(temp_db))) == sorted(f"p{n}-{i}" for n in range(3) for i in range(2))


def test_h5_one_instance_is_thread_safe(temp_db: Path):
    ms = MattStash(path=str(temp_db))
    errors: list[BaseException] = []

    def worker(n: int) -> None:
        try:
            for i in range(2):
                ms.put(f"t{n}-{i}", value="v", autoincrement=False)
                ms.get(f"t{n}-{i}")
                ms.list()
        except BaseException as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(3)]
    [t.start() for t in threads]
    [t.join(timeout=120) for t in threads]
    assert not errors
    assert titles(ms) == sorted(f"t{n}-{i}" for n in range(3) for i in range(2))


def test_h5_lock_timeout_is_a_typed_error(temp_db: Path):
    ms = MattStash(path=str(temp_db), lock_timeout=0.2)
    with FileLock(str(temp_db) + ".lock"):
        with pytest.raises(DatabaseLockError, match="Timed out"):
            ms.put("x", value="v")
    ms.put("x", value="v")  # works again once released


def test_h5_reads_do_not_take_the_lock(temp_db: Path):
    ms = MattStash(path=str(temp_db), lock_timeout=0.2)
    ms.put("x", value="v")
    with FileLock(str(temp_db) + ".lock"):
        assert ms.get("x") is not None  # a writer holding the lock must not block readers


# ---------------------------------------------------------------------------
# H-7 file modes survive saves
# ---------------------------------------------------------------------------


def _mode(p: Path) -> int:
    return stat.S_IMODE(os.stat(p).st_mode)


def test_h7_database_stays_0600_across_saves(temp_db: Path):
    ms = MattStash(path=str(temp_db))
    for i in range(2):
        ms.put(f"k{i}", value="v")
        assert _mode(temp_db) == 0o600
    assert not list(temp_db.parent.glob("*.tmp")) and not list(temp_db.parent.glob("*.new"))


def test_h7_existing_mode_is_preserved(temp_db: Path):
    os.chmod(temp_db, 0o640)
    MattStash(path=str(temp_db)).put("k", value="v")
    assert _mode(temp_db) == 0o640  # we restore, never widen


# ---------------------------------------------------------------------------
# M-7 / M-8 / M-8b / M-4 versions
# ---------------------------------------------------------------------------


def test_m7_delete_removes_unversioned_and_all_versions(temp_db: Path):
    ms = MattStash(path=str(temp_db))
    ms.put("api", value="old", autoincrement=False)
    ms.put("api", value="v1")
    ms.put("api", value="v2")
    assert ms.delete("api") is True
    assert ms.get("api") is None
    assert titles(ms) == []


def test_m7_delete_single_version_and_prune(temp_db: Path):
    ms = MattStash(path=str(temp_db))
    for i in range(1, 5):
        ms.put("k", value=f"v{i}")
    assert ms.delete("k", version=2) is True
    assert ms.list_versions("k") == ["0000000001", "0000000003", "0000000004"]
    assert ms.delete("k", version=2) is False
    assert ms.prune("k", keep=1) == ["0000000001", "0000000003"]
    assert ms.get("k", show_password=True)["value"] == "v4"
    with pytest.raises(InvalidCredentialError):
        ms.prune("k", keep=0)


def test_m8_hydrate_env_works_with_versioned_entries(temp_db: Path, monkeypatch):
    ms = MattStash(path=str(temp_db))
    ms.put("aws-prod", username="AKIAEXAMPLE", password="old-secret")
    ms.put("aws-prod", username="AKIAEXAMPLE", password="new-secret")  # default put => versioned
    for var in ("H8_KEY", "H8_SECRET"):
        monkeypatch.delenv(var, raising=False)
    ms.hydrate_env({"aws-prod:AWS_ACCESS_KEY_ID": "H8_KEY", "aws-prod:AWS_SECRET_ACCESS_KEY": "H8_SECRET"})
    assert (os.environ["H8_KEY"], os.environ["H8_SECRET"]) == ("AKIAEXAMPLE", "new-secret")


def test_m8b_all_lookups_agree_when_versioned_and_unversioned_coexist(temp_db: Path):
    ms = MattStash(path=str(temp_db))
    ms.put("db", username="old", password="old", url="h:1", autoincrement=False)
    ms.put("db", username="new", password="new", url="h:1")
    cred, props = ms.get_entry_with_properties("db", ("database",))
    assert cred.username == "new" == ms.get("db", show_password=True).username
    assert props == {"database": None}


def test_m4_full_credential_put_reports_its_real_version(temp_db: Path):
    ms = MattStash(path=str(temp_db))
    versions = [ms.put("svc", username="u", password=f"p{i}").version for i in range(3)]
    assert versions == ["0000000001", "0000000002", "0000000003"]
    assert ms.get("svc", show_password=True).version == "0000000003"
    assert ms.get("svc", version=2, show_password=True).password == "p1"


def test_list_latest_only_collapses_versions(temp_db: Path):
    ms = MattStash(path=str(temp_db))
    ms.put("svc", username="u", password="p1")
    ms.put("svc", username="u", password="p2")
    ms.put("plain", value="x", autoincrement=False)
    assert [(c.credential_name, c.version) for c in ms.list(latest_only=True)] == [
        ("plain", None),
        ("svc", "0000000002"),
    ]
    assert len(ms.list()) == 3  # default listing is unchanged: every stored entry


@pytest.mark.parametrize("version", [-1, True, 1.5, "2"])
def test_versions_must_be_non_negative_ints(temp_db: Path, version):
    with pytest.raises(InvalidCredentialError):
        MattStash(path=str(temp_db)).put("k", value="v", version=version)


def test_unicode_digits_are_not_versions():
    assert parse_version_suffix("a@²", "a") is None
    assert parse_version_suffix("a@١٢٣", "a") is None  # arabic-indic digits
    assert parse_version_suffix("a@0000000012", "a") == 12
    assert parse_version_suffix("a@b@0000000012", "a@b") == 12
    assert parse_version_suffix("a@b@0000000012", "a") is None


# ---------------------------------------------------------------------------
# M-3 db-url encoding
# ---------------------------------------------------------------------------


def _db_cred(ms: MattStash, **overrides):
    fields = {"username": "app", "password": "p@ss/w:rd#1?x=y%", "url": "db.internal:5432", "notes": "n"}
    fields.update(overrides)
    ms.put("pg", **fields)


def test_m3_special_characters_in_password_cannot_change_the_url_structure(temp_db: Path):
    ms = MattStash(path=str(temp_db))
    _db_cred(ms)
    url = ms.get_db_url("pg", driver="psycopg", database="orders", mask_password=False)
    parts = urlsplit(url)
    assert (parts.hostname, parts.port, parts.path) == ("db.internal", 5432, "/orders")
    assert unquote(parts.username) == "app" and unquote(parts.password) == "p@ss/w:rd#1?x=y%"


def test_m3_user_and_database_are_encoded_too(temp_db: Path):
    ms = MattStash(path=str(temp_db))
    _db_cred(ms, username="ap p@corp", password="x")
    url = ms.get_db_url("pg", database="my db/prod", mask_password=False)
    parts = urlsplit(url)
    assert parts.hostname == "db.internal"
    assert unquote(parts.username) == "ap p@corp"
    assert unquote(parts.path) == "/my db/prod"


@pytest.mark.parametrize("host", ["evil.com/x", "a b:5432", "h@x:5432", "h?q=1:5432", "h#f:5432", ":5432"])
def test_m3_hostile_host_in_url_field_is_rejected(temp_db: Path, host: str):
    ms = MattStash(path=str(temp_db))
    _db_cred(ms, url=host)
    with pytest.raises(ValueError):
        ms.get_db_url("pg", database="d", mask_password=False)


def test_m3_sslmode_is_allow_listed_and_encoded(temp_db: Path):
    ms = MattStash(path=str(temp_db))
    _db_cred(ms)
    assert parse_qs(urlsplit(ms.get_db_url("pg", database="d", sslmode_override="verify-full")).query) == {
        "sslmode": ["verify-full"]
    }
    with pytest.raises(ValueError, match="sslmode"):
        ms.get_db_url("pg", database="d", sslmode_override="disable&target_session_attrs=any")


def test_m3_masked_url_never_contains_the_password(temp_db: Path):
    ms = MattStash(path=str(temp_db))
    _db_cred(ms)
    for style in ("stars", "omit"):
        masked = ms.get_db_url("pg", database="d", mask_password=True, mask_style=style)
        assert "p%40ss" not in masked and "p@ss" not in masked


# ---------------------------------------------------------------------------
# CredentialStore specifics
# ---------------------------------------------------------------------------


def test_store_find_entry_by_title_is_exact(temp_db: Path):
    ms = MattStash(path=str(temp_db))
    ms.put("alpha", value="1", autoincrement=False)
    store = CredentialStore(str(temp_db), ms.password)
    assert store.find_entry_by_title("alpha") is not None
    assert store.find_entry_by_title('alpha" or "a"="a') is None
    assert store.find_entry_by_title("al.*") is None


def test_store_create_entry_survives_quotes(temp_db: Path):
    ms = MattStash(path=str(temp_db))
    store = CredentialStore(str(temp_db), ms.password)
    store.create_entry('q"uote', password="p")
    store.save()
    assert MattStash(path=str(temp_db)).get('q"uote', show_password=True)["value"] == "p"


# ---------------------------------------------------------------------------
# L-10 malformed integer environment variables
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("var", ["MATTSTASH_VERSION_PAD_WIDTH", "MATTSTASH_S3_RETRIES", "MATTSTASH_CACHE_TTL"])
def test_l10_bad_integer_env_var_names_the_variable(var: str, monkeypatch):
    from mattstash.models.config import MattStashConfig

    monkeypatch.setenv(var, "not-a-number")
    with pytest.raises(ValueError, match=var):
        MattStashConfig()
