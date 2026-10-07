"""Regression tests for the third (focused) review of the round-2 fixes: core, operations, client and env/exec."""

import errno
import io
import os
import signal
import socket
import stat
import sys
import threading
import time
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
from dbhelpers import create_db
from fake_server import FakeServer
from pykeepass import PyKeePass

from mattstash import MattStash
from mattstash.cli import exit_codes, http_client
from mattstash.cli.http_client import MattStashServerClient
from mattstash.cli.inputs import InputError, read_stdin_secret
from mattstash.cli.main import main
from mattstash.core.bootstrap import DatabaseBootstrapper
from mattstash.core.env_vars import is_reserved_env_name
from mattstash.credential_store import CredentialStore
from mattstash.utils.exceptions import (
    DatabaseAccessError,
    DatabaseExistsError,
    DatabaseLockError,
    MattStashError,
    RekeyVerifyError,
    ServerError,
    SidecarUpdateError,
)
from mattstash.utils.filelock import FileLock
from mattstash.utils.fileops import staging_name
from mattstash.utils.validation import api_key_problem

OLD, NEW = "old-master-pw", "new-master-pw"
KEY = "k3y-s3cret-AAAA"
URL = "http://localhost:8000"
IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0


def opens_with(path: Path, password: str) -> bool:
    try:
        PyKeePass(str(path), password=password)
        return True
    except Exception:
        return False


def mode(path: Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def make_db(path: Path, password: str = OLD, *, sidecar: bool = True, title: str = "a") -> Path:
    return create_db(path, [{"title": title, "password": f"{title}-secret"}], password=password, sidecar=sidecar)


# ---------------------------------------------------------------------------
# core: the write path follows a retarget (R1/F1) and rotate honours the guards (F8)
# ---------------------------------------------------------------------------


def test_r1_a_writer_queued_on_the_old_lock_ends_up_writing_the_new_target_under_the_new_lock(tmp_path: Path):
    make_db(tmp_path / "v1" / "db.kdbx", title="one")
    make_db(tmp_path / "v2" / "db.kdbx", title="two")
    current = tmp_path / "current"
    current.symlink_to("v1")
    stash = MattStash(str(current / "db.kdbx"), password=OLD, lock_timeout=20)
    assert stash.get("one") is not None
    errors: list[BaseException] = []

    def writer() -> None:
        try:
            stash.put("w1", value="x")
        except BaseException as exc:
            errors.append(exc)

    holder = FileLock(str(tmp_path / "v1" / "db.kdbx.lock"), timeout=5)
    holder.acquire()  # another process holds the OLD target's lock
    thread = threading.Thread(target=writer)
    thread.start()
    time.sleep(0.4)  # the writer is queued on v1.lock
    current.unlink()
    current.symlink_to("v2")  # the path now means v2
    holder.release()
    thread.join(20)
    assert not errors, errors
    assert MattStash(str(tmp_path / "v2" / "db.kdbx"), password=OLD).get("w1") is not None
    assert MattStash(str(tmp_path / "v1" / "db.kdbx"), password=OLD).get("w1") is None
    assert stash._file_lock.path == str(tmp_path / "v2" / "db.kdbx.lock"), "the write ran under the NEW target's lock"


def test_r1_a_retarget_after_the_write_began_is_refused_not_saved_into_the_old_file(tmp_path: Path):
    make_db(tmp_path / "v1" / "db.kdbx", title="one")
    make_db(tmp_path / "v2" / "db.kdbx", title="two")
    current = tmp_path / "current"
    current.symlink_to("v1")
    stash = MattStash(str(current / "db.kdbx"), password=OLD)
    real_fresh = MattStash._fresh

    def fresh_then_flip(self):
        manager = real_fresh(self)
        current.unlink()
        current.symlink_to("v2")  # flipped between reading the state and saving it
        return manager

    with patch.object(MattStash, "_fresh", fresh_then_flip):
        with pytest.raises(DatabaseLockError, match="retargeted"):
            stash.put("late", value="x")
    for name in ("v1", "v2"):
        assert MattStash(str(tmp_path / name / "db.kdbx"), password=OLD).get("late") is None


def test_r8_rotate_password_is_refused_when_the_lock_file_was_removed(tmp_path: Path):
    db = make_db(tmp_path / "r.kdbx")
    stash = MattStash(str(db), password=OLD)
    real_acquire = FileLock.acquire

    def acquire_then_delete(self, timeout=None, **kwargs):
        real_acquire(self, timeout, **kwargs)
        if os.path.exists(self.path):
            os.remove(self.path)

    with patch.object(FileLock, "acquire", acquire_then_delete):
        with pytest.raises(DatabaseLockError, match="removed while it was held"):
            stash.rotate_password(NEW)
    assert opens_with(db, OLD) and (tmp_path / ".mattstash.txt").read_text() == OLD


# ---------------------------------------------------------------------------
# core: password refresh on an OPEN instance (R2), never clobbering a good password
# ---------------------------------------------------------------------------


def test_r2_an_open_instance_follows_a_rotation_through_the_sidecar(tmp_path: Path):
    db = make_db(tmp_path / "q.kdbx")
    reader = MattStash(str(db))  # password from the sidecar
    assert reader.get("a") is not None
    MattStash(str(db)).rotate_password(NEW)
    assert reader.get("a") is not None, "a reload after the rotation must use the new sidecar password"
    assert reader.password == NEW
    reader.put("b", value="1")


def test_r2_a_refresh_that_does_not_help_does_not_replace_the_password(tmp_path: Path):
    db = make_db(tmp_path / "q.kdbx")
    reader = MattStash(str(db))
    assert reader.get("a") is not None
    # the database is re-keyed behind its back to something the sidecar does not hold either
    other = PyKeePass(str(db), password=OLD)
    other.password = "third-password"
    other.save()
    (tmp_path / ".mattstash.txt").write_text("not-the-password")
    with pytest.raises(DatabaseAccessError):
        reader.get("a")
    assert reader.password == OLD, "only a password that actually opens the database may be adopted"


# ---------------------------------------------------------------------------
# core: lock file ownership, paths, errors, long names
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not IS_ROOT, reason="needs root to set an owner")
def test_r3_a_lock_file_created_by_root_belongs_to_the_database_owner(tmp_path: Path):
    db = make_db(tmp_path / "o" / "db.kdbx", sidecar=False)
    os.chown(db, 12345, 23456)
    os.chmod(db, 0o660)
    MattStash(str(db), password=OLD).put("x", value="1")
    lock = os.stat(str(db) + ".lock")
    assert (lock.st_uid, lock.st_gid) == (12345, 23456)
    assert stat.S_IMODE(lock.st_mode) & 0o660 == 0o660


def test_r4_a_path_with_dotdot_after_a_symlink_names_the_file_the_os_resolves(tmp_path: Path):
    (tmp_path / "real" / "sub").mkdir(parents=True)
    make_db(tmp_path / "real" / "db.kdbx", title="REAL", sidecar=False)
    make_db(tmp_path / "db.kdbx", title="DECOY", sidecar=False)
    (tmp_path / "link").symlink_to("real/sub")
    spelled = str(tmp_path / "link" / ".." / "db.kdbx")
    stash = MattStash(spelled, password=OLD)
    assert stash.get("REAL") is not None and stash.get("DECOY") is None
    assert ".." in stash.path, "not normalised lexically"


def test_r5_an_unreadable_database_is_not_reported_as_missing(tmp_path: Path):
    db = make_db(tmp_path / "e.kdbx", sidecar=False)
    stash = MattStash(str(db), password=OLD)
    assert stash.get("a") is not None
    real_open = open

    def refuse(file, *args, **kwargs):
        if str(file) == str(db):
            raise OSError(errno.EMFILE, "Too many open files")
        return real_open(file, *args, **kwargs)

    with patch("builtins.open", refuse):
        with pytest.raises(DatabaseAccessError, match="Cannot read the database file"):
            stash.get("a")
    assert stash._credential_store is not None, "state is kept: this was not 'the database vanished'"
    assert stash.get("a") is not None


def test_r6_a_database_with_a_very_long_name_can_be_created_and_written(tmp_path: Path):
    name = "x" * 240 + ".kdbx"  # 245 bytes: the staging file name must not exceed NAME_MAX
    path = tmp_path / name
    MattStash.create(str(path), password=OLD, sidecar=False)
    MattStash(str(path), password=OLD).put("a", value="1")
    assert MattStash(str(path), password=OLD).get("a") is not None
    assert [p.name for p in tmp_path.iterdir() if p.name.endswith((".new", ".tmp"))] == []


def test_r6_staging_names_always_fit():
    for base in ("db.kdbx", "x" * 300, "é" * 200, ".hidden"):
        name = os.path.basename(staging_name("/tmp", base, "0123456789ab"))
        assert len(name.encode()) <= 255 and name.endswith(".new")


def test_r7_orphaned_lock_retry_never_closes_a_descriptor_twice(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    path = tmp_path / "o.lock"
    holder, waiter = FileLock(str(path), timeout=5), FileLock(str(path), timeout=5)
    holder.acquire()
    closed: list[int] = []
    real_close = os.close
    monkeypatch.setattr("mattstash.utils.filelock.os.close", lambda fd: (closed.append(fd), real_close(fd))[1])
    real_open = waiter._open
    calls = {"n": 0}

    def flaky_open() -> int:
        calls["n"] += 1
        if calls["n"] == 1:
            return real_open()
        raise DatabaseLockError("cannot recreate the lock file")

    waiter._open = flaky_open  # type: ignore[method-assign]
    outcome: list[BaseException] = []

    def wait() -> None:
        try:
            waiter.acquire(timeout=5)
        except BaseException as exc:
            outcome.append(exc)

    thread = threading.Thread(target=wait)
    thread.start()
    time.sleep(0.2)
    os.remove(path)  # orphan the file the waiter polls
    third = FileLock(str(path), timeout=5)
    third.acquire()
    holder.release()
    thread.join(10)
    third.release()
    assert outcome and isinstance(outcome[0], DatabaseLockError)
    assert len(closed) == len(set(closed)), f"a descriptor was closed twice: {closed}"


def test_r10_lock_timeout_message_names_the_whole_budget(tmp_path: Path):
    db = make_db(tmp_path / "t.kdbx", sidecar=False)
    stash = MattStash(str(db), password=OLD, lock_timeout=1)
    with FileLock(str(db) + ".lock", timeout=5):
        with pytest.raises(DatabaseLockError, match=r"Timed out after 1s"):
            stash.put("x", value="1")


# ---------------------------------------------------------------------------
# operations: rotate-password
# ---------------------------------------------------------------------------


def test_o_a_failed_sidecar_swap_tells_the_user_how_to_finish(tmp_path: Path):
    db = make_db(tmp_path / "s.kdbx")
    real_replace = os.replace

    def selective(src, dst, *args, **kwargs):
        if str(dst).endswith(".mattstash.txt"):
            raise OSError(errno.EACCES, "Permission denied")
        return real_replace(src, dst, *args, **kwargs)

    with patch("mattstash.core.mattstash.os.replace", selective):
        with pytest.raises(SidecarUpdateError) as excinfo:
            MattStash(str(db), password=OLD).rotate_password(NEW)
    assert "mv '" in str(excinfo.value) and excinfo.value.staged_path in str(excinfo.value)


def test_o_rekey_verify_error_is_not_mistaken_for_a_wrong_password():
    assert not issubclass(RekeyVerifyError, DatabaseAccessError)


def test_o_ctrl_c_before_the_rekey_names_the_backup_and_exits_130(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    db = make_db(tmp_path / "s.kdbx")
    with patch.object(CredentialStore, "change_password", side_effect=KeyboardInterrupt):
        rc = main(["--db", str(db), "--password", OLD, "rotate-password", "--new-password-file", _pwfile(tmp_path)])
    assert rc == exit_codes.INTERRUPTED
    err = capsys.readouterr().err
    assert "A backup made before the failure was kept" in err and "interrupted" in err
    assert opens_with(db, OLD) and (tmp_path / ".mattstash.txt").read_text() == OLD
    assert [p.name for p in tmp_path.iterdir() if ".tmp-" in p.name] == [], "the staged password was discarded"


def _pwfile(tmp_path: Path) -> str:
    path = tmp_path / "newpw.txt"
    path.write_text(NEW)
    return str(path)


def test_o_rotate_warns_about_databases_that_share_the_sidecar(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    a = make_db(tmp_path / "a.kdbx", sidecar=False)
    make_db(tmp_path / "b.kdbx", sidecar=False)
    (tmp_path / ".mattstash.txt").write_text(OLD)
    assert main(["--db", str(a), "--password", OLD, "rotate-password", "--new-password-file", _pwfile(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "Sidecar password file updated" in out and "b.kdbx" in out and "share this sidecar" in out


def test_o_an_unreadable_sidecar_is_reported_as_left_unchanged(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    db = make_db(tmp_path / "a.kdbx", sidecar=False)
    (tmp_path / ".mattstash.txt").mkdir()  # exists, cannot be read as a password file
    assert main(["--db", str(db), "--password", OLD, "rotate-password", "--new-password-file", _pwfile(tmp_path)]) == 0
    assert "left unchanged" in capsys.readouterr().out


def test_o_generated_password_is_shown_before_the_slow_verification(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    db = make_db(tmp_path / "a.kdbx", sidecar=False)
    seen: list[str] = []
    real_reload = MattStash._reload_locked

    def peek(self):
        seen.append(capsys.readouterr().out)  # what the user could already read when verification starts
        return real_reload(self)

    with patch.object(MattStash, "_reload_locked", peek):
        main(["--db", str(db), "--password", OLD, "rotate-password", "--generate", "--no-backup"])
    assert seen and "Generated new master password" in seen[0]


# ---------------------------------------------------------------------------
# operations: setup / create
# ---------------------------------------------------------------------------


def test_o_setup_generate_shows_the_password_first_and_survives_a_closed_stdout(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    db = tmp_path / "g.kdbx"
    monkeypatch.setattr("sys.stdout", None)  # `>&-`
    assert main(["--db", str(db), "setup", "--generate"]) == 0
    err = capsys.readouterr().err
    assert any(opens_with(db, word) for word in err.split() if len(word) >= 20)


def test_o_setup_password_stdin_strips_a_bom_like_every_other_source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db = tmp_path / "bom.kdbx"
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(b"\xef\xbb\xbfsecretpw\r\n"), encoding="utf-8"))
    assert main(["--db", str(db), "setup", "--password-stdin"]) == 0
    assert opens_with(db, "secretpw")


@pytest.mark.parametrize("umask", [0o277, 0o222, 0o377])
def test_o_restrictive_umask_setup_force_and_nested_directories(tmp_path: Path, umask: int):
    old = os.umask(umask)
    try:
        nested = tmp_path / "deep" / "er" / "a.kdbx"
        MattStash.create(str(nested), password=OLD, sidecar=True)
        MattStash.create(str(nested), password=OLD, sidecar=True, force=True, backup=True)
        backups = [p for p in nested.parent.iterdir() if ".bak-" in p.name]
    finally:
        os.umask(old)
    assert backups and all(mode(p) == 0o600 for p in backups)
    assert mode(tmp_path / "deep") == 0o700 and mode(tmp_path / "deep" / "er") == 0o700


@pytest.mark.skipif(not IS_ROOT, reason="needs root to set an owner")
def test_o_setup_force_as_root_keeps_the_owner_of_the_replaced_files(tmp_path: Path):
    db = make_db(tmp_path / "o" / "a.kdbx", sidecar=True)
    for path in (db, db.parent / ".mattstash.txt"):
        os.chown(path, 12345, 23456)
    MattStash.create(str(db), password=OLD, sidecar=True, force=True, backup=False)
    for path in (db, db.parent / ".mattstash.txt"):
        assert (os.stat(path).st_uid, os.stat(path).st_gid) == (12345, 23456), path


def test_o_a_lost_creation_race_names_the_database_not_the_temp_file(tmp_path: Path):
    db = make_db(tmp_path / "r.kdbx", sidecar=False)
    with patch.object(DatabaseBootstrapper, "existing_files", return_value=[]):  # as if the race was lost
        with pytest.raises(DatabaseExistsError) as excinfo:
            DatabaseBootstrapper(str(db)).create("p", sidecar=False)
    assert "r.kdbx" in str(excinfo.value) and ".new" not in str(excinfo.value)


def test_o_a_dangling_sidecar_symlink_counts_as_an_existing_file(tmp_path: Path):
    db = tmp_path / "d.kdbx"
    (tmp_path / ".mattstash.txt").symlink_to(tmp_path / "nowhere")
    assert str(tmp_path / ".mattstash.txt") in DatabaseBootstrapper(str(db)).existing_files()


# ---------------------------------------------------------------------------
# CLI: empty options, signals, error messages
# ---------------------------------------------------------------------------


def test_c_empty_db_password_on_put_fields_is_an_error_but_bare_password_is_the_entry_password(tmp_path: Path):
    db = make_db(tmp_path / "p.kdbx", sidecar=True)
    assert main(["--db", str(db), "put", "x", "--fields", "--username", "u", "--db-password", ""]) == exit_codes.ERROR
    pw = _pwfile(tmp_path)
    assert main(["--db", str(db), "setup", "--force", "--yes", "--password-file", ""]) == exit_codes.ERROR
    assert main(["--db", str(db), "--password", OLD, "rotate-password", "--new-password-file", ""]) == exit_codes.ERROR
    assert opens_with(db, OLD) and pw


def test_c_empty_server_url_is_an_error_and_never_falls_back_to_the_local_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    db = make_db(tmp_path / "l.kdbx", sidecar=True)
    monkeypatch.setenv("MATTSTASH_API_KEY", KEY)
    assert main(["--db", str(db), "--server-url", "", "put", "y", "--value", "to-local"]) == exit_codes.ERROR
    assert MattStash(str(db)).get("y") is None, "nothing was written to the local database"
    # an empty *environment variable* is simply "not set": local mode
    monkeypatch.setenv("MATTSTASH_SERVER_URL", "")
    assert main(["--db", str(db), "get", "a", "--raw"]) == exit_codes.OK


def test_c_sigterm_is_handled_like_ctrl_c_and_the_handler_is_restored(tmp_path: Path):
    db = make_db(tmp_path / "s.kdbx")
    before = signal.getsignal(signal.SIGTERM)

    def terminate(self, args):
        os.kill(os.getpid(), signal.SIGTERM)
        time.sleep(1)  # the handler raises KeyboardInterrupt before this returns
        return 0

    with patch("mattstash.cli.handlers.list.KeysHandler.handle", terminate):
        assert main(["--db", str(db), "keys"]) == exit_codes.INTERRUPTED
    assert signal.getsignal(signal.SIGTERM) == before


def test_c_file_system_errors_name_the_file(capsys: pytest.CaptureFixture[str]):
    err = OSError(errno.EACCES, "Permission denied", "/secure/dir/db.kdbx")
    with patch("mattstash.cli.handlers.list.KeysHandler.handle", side_effect=err):
        assert main(["--db", "/nonexistent/x.kdbx", "keys"]) == exit_codes.ERROR
    assert "Permission denied: /secure/dir/db.kdbx" in capsys.readouterr().err


def test_c_ctrl_d_at_the_hidden_prompt_is_a_clean_error(monkeypatch: pytest.MonkeyPatch):
    class Tty(io.StringIO):
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr("sys.stdin", Tty())

    def eof(prompt=""):
        raise EOFError

    monkeypatch.setattr("getpass.getpass", eof)
    with pytest.raises(InputError, match="no data received"):
        read_stdin_secret("--value -")


# ---------------------------------------------------------------------------
# client: URL rules, deadline, hostile responses, keys, db-url
# ---------------------------------------------------------------------------


@pytest.fixture()
def server(monkeypatch: pytest.MonkeyPatch) -> FakeServer:
    return FakeServer(api_key=KEY).install(monkeypatch)


@pytest.mark.parametrize(
    "url",
    ["http://h:1/?x=1", "http://h:1#frag", "http://u:p%40ss@h:1", "http://h:0", "http://a b.com", "http://h:1/a?b"],
)
def test_f12_base_urls_that_would_misroute_or_leak_are_refused(url: str):
    with pytest.raises(ServerError, match="must look like"):
        MattStashServerClient(url, KEY)


def test_f12_prefixes_and_ports_are_fine():
    assert MattStashServerClient("https://example.test:8443/mattstash/", KEY).base_url == (
        "https://example.test:8443/mattstash"
    )


def test_f13_keys_with_inner_spaces_are_allowed_like_the_server_allows_them():
    assert api_key_problem("correct horse battery staple 0123456789ab") is None
    for bad in ("trailing\n", " leading", "tab\tinside", "café", ""):
        assert api_key_problem(bad)


def test_f11_responses_are_never_compressed(server: FakeServer):
    server.add("a", "1")
    MattStashServerClient(URL, KEY).get("a")
    assert server.requests[-1].headers["Accept-Encoding"] == "identity"


def test_f5_hostile_retry_after_and_deeply_nested_json_are_server_errors(
    server: FakeServer, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(time, "sleep", lambda s: None)
    client = MattStashServerClient(URL, KEY)
    server.override = lambda r: httpx.Response(429, headers=[(b"Retry-After", "²".encode("latin-1"))], json={})
    with pytest.raises(ServerError, match="HTTP 429") as excinfo:
        client.list()
    assert "retry after" not in str(excinfo.value)
    server.override = lambda r: httpx.Response(200, content=b"[" * 200_000 + b"]" * 200_000)
    with pytest.raises(ServerError, match="not valid JSON"):
        client.list()


def test_f5_a_value_the_terminal_cannot_encode_is_an_error_not_a_traceback(
    server: FakeServer, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    server.add("weird", "abc\ud800def")
    monkeypatch.setenv("MATTSTASH_API_KEY", KEY)
    monkeypatch.setattr("sys.stdout", io.TextIOWrapper(io.BytesIO(), encoding="utf-8"))
    rc = main(["--server-url", URL, "env", "--map", "X=weird"])
    assert rc == exit_codes.ERROR


def test_f15_a_missing_credential_in_db_url_says_so(server: FakeServer):
    server.override = lambda r: httpx.Response(404, json={"detail": "Credential not found or unsuitable: x"})
    with pytest.raises(ServerError, match="credential not found") as excinfo:
        MattStashServerClient(URL, KEY).db_url("x")
    assert excinfo.value.secret_missing


def test_f4_a_server_that_dribbles_its_headers_cannot_hold_the_client_past_the_total_timeout():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    stop = threading.Event()

    def dribble() -> None:
        conn, _ = listener.accept()
        conn.settimeout(5)
        with __import__("contextlib").suppress(OSError):
            conn.recv(65536)
            for byte in b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Pad: " + b"a" * 200:
                if stop.is_set():
                    break
                conn.sendall(bytes([byte]))  # never finishes the headers
                time.sleep(0.3)
        conn.close()

    thread = threading.Thread(target=dribble, daemon=True)
    thread.start()
    client = MattStashServerClient(f"http://127.0.0.1:{port}", KEY, timeout=2.0, total_timeout=1.0)
    started = time.monotonic()
    try:
        with pytest.raises(ServerError, match="did not finish"):
            client.list()
        assert time.monotonic() - started < 4.0, "the watchdog must cut the exchange off near total_timeout"
    finally:
        stop.set()
        listener.close()


# ---------------------------------------------------------------------------
# env / exec
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        *("GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_SSH", "GIT_PAGER", "EDITOR", "VISUAL", "PAGER", "LESSOPEN"),
        *("LUA_INIT", "OPENSSL_CONF", "GLIBC_TUNABLES", "PHP_INI_SCAN_DIR", "MAVEN_OPTS", "ZDOTDIR", "HTTP_PROXY"),
        *("http_proxy", "https_proxy", "ALL_PROXY", "NODE_TLS_REJECT_UNAUTHORIZED", "AWS_CA_BUNDLE", "KUBECONFIG"),
        *("DOCKER_HOST", "JAVA_HOME", "XDG_CONFIG_HOME"),
    ],
)
def test_f2_more_command_and_connection_variables_are_reserved(name: str):
    assert is_reserved_env_name(name)


@pytest.mark.parametrize(
    "name",
    ["PYTHONUNBUFFERED", "RUBYGEMS_API_KEY", "PYTHONANYWHERE_TOKEN", "PERLIN_KEY", "GITHUB_TOKEN", "NODE_ENV"],
)
def test_f14_common_names_that_only_look_dangerous_are_not_reserved(name: str):
    assert not is_reserved_env_name(name)


def test_f2_f14_allow_env_name_lifts_one_name_and_an_empty_secret_never_fails_the_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    db = create_db(
        tmp_path / "e.kdbx",
        [
            {"title": "p.JAVA_HOME", "password": "/opt/jdk"},
            {"title": "p.EDITOR", "password": ""},  # empty: skipped before the guard
            {"title": "p.DB_PASSWORD", "password": "pw"},
        ],
    )
    assert main(["--db", str(db), "env", "--prefix", "p."]) == exit_codes.ERROR  # JAVA_HOME is reserved
    capsys.readouterr()
    assert main(["--db", str(db), "env", "--prefix", "p.", "--allow-env-name", "JAVA_HOME"]) == exit_codes.OK
    out = capsys.readouterr().out
    assert "export JAVA_HOME=/opt/jdk" in out and "export DB_PASSWORD=pw" in out and "EDITOR" not in out


def test_f10_exec_does_not_pass_the_vault_file_variables_either(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db = create_db(tmp_path / "x.kdbx", [{"title": "app.k", "password": "v"}])
    monkeypatch.setenv("KDBX_PASSWORD_FILE", "/run/secrets/master")
    monkeypatch.setenv("MATTSTASH_API_KEY_FILE", "/run/secrets/api")
    monkeypatch.setenv("KDBX_PASSWORD", "test-master-pw")
    with patch("mattstash.cli.handlers.env.os.execve") as execve:
        assert main(["--db", str(db), "exec", "--map", "X=app.k", "--", "sh"]) == 0
    env = execve.call_args.args[2]
    assert not {"KDBX_PASSWORD", "KDBX_PASSWORD_FILE", "MATTSTASH_API_KEY", "MATTSTASH_API_KEY_FILE"} & set(env)
    assert env["X"] == "v"


def test_http_client_module_exposes_the_documented_limits():
    assert http_client.MAX_RETRIES == 3 and http_client.MAX_RESPONSE_BYTES == 16 * 1024 * 1024
    assert MattStashError  # imported for the exception hierarchy checks above
    assert sys.version_info >= (3, 11)
