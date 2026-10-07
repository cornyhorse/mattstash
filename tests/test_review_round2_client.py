"""Regression tests for the second independent review: the CLI's HTTP client, server mode and secret input.

Finding ids (F1..F12) are the reviewer's. Server-side halves live in server/tests/test_review_findings.py.
"""

import errno
import io
import logging
import sys
import time
from pathlib import Path

import httpx
import pytest
from fake_server import FakeServer

from mattstash.builders.db_url import DbUrlError
from mattstash.cli import exit_codes, http_client
from mattstash.cli.http_client import MattStashServerClient
from mattstash.cli.inputs import InputError, read_credential_file, read_secret_file, read_stdin_line
from mattstash.cli.main import main
from mattstash.core.password_resolver import MAX_PASSWORD_FILE_BYTES, read_password_file
from mattstash.utils.exceptions import ServerError

KEY = "k3y-s3cret-AAAA"
URL = "http://localhost:8000"


@pytest.fixture()
def server(monkeypatch: pytest.MonkeyPatch) -> FakeServer:
    return FakeServer(api_key=KEY).install(monkeypatch)


@pytest.fixture()
def client(server: FakeServer) -> MattStashServerClient:
    return MattStashServerClient(URL, KEY)


def cli(*argv: str) -> int:
    return main(["--server-url", URL, *argv])


# ---------------------------------------------------------------------------
# F1 / F8: the API key is cleaned up, validated, and never shown
# ---------------------------------------------------------------------------


def test_f1_api_key_from_the_environment_is_stripped(server: FakeServer, monkeypatch: pytest.MonkeyPatch):
    server.add("x", "v")
    monkeypatch.setenv("MATTSTASH_API_KEY", KEY + "\n")  # a Kubernetes Secret made with --from-file
    assert cli("get", "x", "--raw") == exit_codes.OK
    assert server.requests[-1].headers["X-API-Key"] == KEY


@pytest.mark.parametrize("bad", ["abc\ndef", "abc def", "café-key-123", "﻿abc"])
def test_f1_unusable_api_keys_are_refused_without_echoing_them(
    server: FakeServer, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, bad: str
):
    monkeypatch.setenv("MATTSTASH_API_KEY", bad)
    with caplog.at_level(logging.DEBUG):
        assert cli("get", "x") != exit_codes.OK
    assert not server.requests, "nothing is sent with a key that cannot be a header value"
    shown = caplog.text
    assert bad.strip() not in shown and "abc" not in shown and "caf" not in shown


def test_f1_client_constructor_rejects_bad_keys_and_urls():
    for key in ("a\nb", "café", ""):
        with pytest.raises(ServerError) as excinfo:
            MattStashServerClient(URL, key)
        assert key.strip() not in str(excinfo.value) or key == ""
    for url in ("localhost:8000", "ftp://host", "http://", "http://host:notaport", "http://ho\x00st"):
        with pytest.raises(ServerError, match="not a valid"):
            MattStashServerClient(url, KEY)


def test_f1_redaction_covers_the_escaped_form():
    c = MattStashServerClient(URL, KEY)
    assert KEY not in c._redact(f"bad header {KEY!r} and {KEY}")
    assert c._redact(repr("x\n" + KEY)).count(KEY) == 0


def test_f8_bom_in_credential_files_is_ignored(tmp_path: Path):
    f = tmp_path / "key"
    f.write_bytes(b"\xef\xbb\xbf" + KEY.encode() + b"\r\n")
    assert read_credential_file("--api-key-file", str(f)) == KEY
    v = tmp_path / "val"
    v.write_bytes(b"\xef\xbb\xbfsecret\n")
    assert read_secret_file("--value-file", str(v)) == "secret"
    p = tmp_path / "pw"
    p.write_bytes(b"\xef\xbb\xbfhunter2\r\n")
    assert read_password_file(str(p)) == "hunter2"


@pytest.mark.parametrize(
    "argv", [["--api-key", ""], ["--api-key", "  "], ["--api-key-file", ""], ["--api-key-file", "  "]]
)
def test_l5_empty_api_key_options_are_errors_not_fallbacks(
    server: FakeServer, monkeypatch: pytest.MonkeyPatch, argv: list[str]
):
    monkeypatch.setenv("MATTSTASH_API_KEY", KEY)  # a valid fallback exists; it must NOT be used silently
    assert cli(*argv, "get", "x") != exit_codes.OK
    assert not server.requests


# ---------------------------------------------------------------------------
# F2: only the server's own "Credential not found" means "no such secret"
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "response",
    [
        lambda r: httpx.Response(404, json={"detail": "Not Found"}),  # route-level 404 (wrong --server-url path)
        lambda r: httpx.Response(404, text="<html>404 from a proxy</html>"),
        lambda r: httpx.Response(404, json={"detail": "no such route"}),
        lambda r: httpx.Response(404, json=["Credential not found"]),
    ],
)
def test_f2_other_404s_are_errors_for_get_delete_and_versions(server: FakeServer, client, response):
    server.override = response
    for call in (lambda: client.get("x"), lambda: client.delete("x"), lambda: client.versions("x")):
        with pytest.raises(ServerError) as excinfo:
            call()
        assert excinfo.value.status_code == 404 and not excinfo.value.secret_missing


def test_f2_the_servers_own_not_found_still_means_missing(server: FakeServer, client):
    assert client.get("nope") is None
    assert client.delete("nope") is False
    assert client.versions("nope") == []


def test_f2_cli_delete_with_a_wrong_url_is_not_reported_as_already_gone(server: FakeServer, monkeypatch):
    server.override = lambda r: httpx.Response(404, json={"detail": "Not Found"})
    monkeypatch.setenv("MATTSTASH_API_KEY", KEY)
    assert cli("delete", "x") == exit_codes.ERROR  # not NOT_FOUND (2): a script must not treat it as "gone"
    assert cli("get", "x", "--raw") == exit_codes.ERROR


# ---------------------------------------------------------------------------
# F6 / F7: odd URLs and proxies
# ---------------------------------------------------------------------------


def test_f6_url_with_trailing_newline_is_cleaned_and_invalid_urls_never_traceback(
    server: FakeServer, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("MATTSTASH_API_KEY", KEY)
    server.add("x", "v")
    assert main(["--server-url", URL + "\n", "get", "x", "--raw"]) == exit_codes.OK

    def boom(**kwargs):
        raise httpx.InvalidURL("Invalid non-printable ASCII character in URL, '\\n' at position 22.")

    monkeypatch.setattr(httpx, "Client", boom)
    c = MattStashServerClient(URL, KEY)
    with pytest.raises(ServerError) as excinfo:
        c.list()
    assert "position" not in str(excinfo.value)


def test_f7_loopback_http_through_a_proxy_still_warns(monkeypatch: pytest.MonkeyPatch, caplog):
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.example:3128")
    with caplog.at_level(logging.WARNING, logger="mattstash.cli.http_client"):
        assert http_client.warn_if_insecure("http://127.0.0.1:9") is True
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    with caplog.at_level(logging.WARNING, logger="mattstash.cli.http_client"):
        assert http_client.warn_if_insecure("http://127.0.0.1:9") is False
    for var in ("HTTP_PROXY", "NO_PROXY"):
        monkeypatch.delenv(var, raising=False)
    assert http_client.warn_if_insecure("http://127.0.0.1:9") is False


# ---------------------------------------------------------------------------
# F9: a success response must look like one
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "call",
    [
        lambda c: c.get("x"),
        lambda c: c.put("x", value="v"),
        lambda c: c.delete("x"),
        lambda c: c.list(),
        lambda c: c.versions("x"),
        lambda c: c.db_url("x"),
    ],
)
@pytest.mark.parametrize("payload", [{"message": "ok"}, {}])
def test_f9_unexpected_success_bodies_are_errors(server: FakeServer, client, call, payload):
    server.override = lambda r: httpx.Response(200, json=payload)
    with pytest.raises(ServerError, match="unexpected response"):
        call(client)


def test_f9_wrong_list_shape(server: FakeServer, client):
    server.override = lambda r: httpx.Response(200, json={"credentials": ["a-string"]})
    with pytest.raises(ServerError, match="unexpected response"):
        client.list()


# ---------------------------------------------------------------------------
# F10: bounded responses, reused connection, 429 retry
# ---------------------------------------------------------------------------


def test_f10_oversized_responses_are_refused(server: FakeServer, client, monkeypatch):
    monkeypatch.setattr(http_client, "MAX_RESPONSE_BYTES", 1000)
    server.override = lambda r: httpx.Response(200, content=b'{"credentials": [], "pad": "' + b"x" * 5000 + b'"}')
    with pytest.raises(ServerError, match="too large"):
        client.list()
    server.override = lambda r: httpx.Response(
        200, headers={"Content-Length": "999999999"}, content=b'{"credentials": []}'
    )
    with pytest.raises(ServerError, match="too large"):
        client.list()


def test_f10_a_slow_drip_response_hits_the_total_deadline(server: FakeServer, monkeypatch):
    class Drip(httpx.SyncByteStream):
        def __iter__(self):
            for _ in range(50):
                time.sleep(0.03)
                yield b" "

    server.override = lambda r: httpx.Response(200, stream=Drip())
    slow = MattStashServerClient(URL, KEY, total_timeout=0.15)
    started = time.monotonic()
    with pytest.raises(ServerError, match="did not finish"):
        slow.list()
    assert time.monotonic() - started < 1.0


def test_f10_one_connection_pool_is_reused(server: FakeServer, client, monkeypatch):
    created = []
    real = httpx.Client  # the fake server's factory (it adds the mock transport itself)

    def counting(**kwargs):
        created.append(1)
        return real(**kwargs)

    monkeypatch.setattr(httpx, "Client", counting)
    server.add("a", "1")
    for _ in range(5):
        client.get("a")
    client.close()
    assert len(created) == 1


def test_f10_rate_limited_gets_are_retried_with_retry_after(server: FakeServer, client, monkeypatch):
    sleeps: list[float] = []
    monkeypatch.setattr(time, "sleep", lambda s: sleeps.append(s))
    server.add("a", "1")
    answers = iter([429, 429, 200])

    def flaky(request):
        code = next(answers)
        return httpx.Response(429, headers={"Retry-After": "7"}, json={"error": "slow down"}) if code == 429 else None

    server.override = flaky
    assert client.get("a")["name"] == "a"
    assert sleeps == [7.0, 7.0]


def test_f10_retries_stop_and_writes_are_never_retried(server: FakeServer, client, monkeypatch):
    sleeps: list[float] = []
    monkeypatch.setattr(time, "sleep", lambda s: sleeps.append(s))
    server.override = lambda r: httpx.Response(429, headers={"Retry-After": "1"}, json={})
    with pytest.raises(ServerError, match="HTTP 429"):
        client.get("a")
    assert len(sleeps) == http_client.MAX_RETRIES
    sleeps.clear()
    with pytest.raises(ServerError, match="HTTP 429"):
        client.put("a", value="v")
    with pytest.raises(ServerError, match="HTTP 429"):
        client.delete("a")
    assert sleeps == [], "POST/DELETE could be applied twice: never retried"


# ---------------------------------------------------------------------------
# F4 / F5 / F11 / F12
# ---------------------------------------------------------------------------


def test_f4_driver_parameter_semantics(server: FakeServer, client):
    client.db_url("x", driver="")
    assert "driver=" in server.requests[-1].url.query.decode()  # "no driver suffix" is sent, not dropped
    client.db_url("x", driver=None)
    assert "driver" not in server.requests[-1].url.params
    client.db_url("x", dialect="")
    assert "dialect" not in server.requests[-1].url.params


def test_f5_safe_server_detail_is_shown_for_400(server: FakeServer, client):
    text = "Entry cannot be used for a database URL: the entry's URL has no port"
    server.override = lambda r: httpx.Response(400, json={"detail": text})
    with pytest.raises(ServerError, match="has no port"):
        client.db_url("x")
    server.override = lambda r: httpx.Response(400, json={"detail": f"echo {KEY}"})
    with pytest.raises(ServerError) as excinfo:
        client.db_url("x")
    assert KEY not in str(excinfo.value) and "echo" not in str(excinfo.value)


def test_f11_notes_win_over_comment_like_the_local_database(server: FakeServer, client):
    client.put("n", value="v", notes="NOTES", comment="COMMENT")
    assert b"NOTES" in server.requests[-1].content and b"COMMENT" not in server.requests[-1].content
    client.put("n", value="v", comment="COMMENT")
    assert b"COMMENT" in server.requests[-1].content


def test_f12_stored_urls_give_clear_errors(temp_db: Path):
    from mattstash import MattStash

    builder = MattStash(str(temp_db))._db_url_builder
    for endpoint, reason in [
        ("postgres://u:p@host/db", "missing-port"),  # userinfo colon used to be mistaken for the port
        ("host:²", "invalid-port"),  # superscript two: isdigit() but not an int
        ("host:" + "".join(chr(0xFF10 + d) for d in (5, 4, 3, 2)), "invalid-port"),  # fullwidth digits
        ("[::1]", "missing-port"),
        ("", "missing-url"),
    ]:
        with pytest.raises(DbUrlError) as excinfo:
            builder._parse_host_port(endpoint)
        assert excinfo.value.reason == reason, endpoint
    assert builder._parse_host_port("postgres://u:p@host:5432/db") == ("host", 5432)


def test_f4_empty_dialect_argument_means_not_given(temp_db: Path):
    from mattstash import MattStash

    stash = MattStash(str(temp_db))
    stash.put("my", username="u", password="p", url="mysql.internal:3306", notes="")
    # the entry says mysql through its custom property: an empty --dialect must not override it with the default
    from pykeepass import PyKeePass

    kp = PyKeePass(str(temp_db), password=stash.password)
    entry = next(e for e in kp.entries if e.title and e.title.startswith("my"))
    entry.set_custom_property("dialect", "mysql")
    kp.save()
    fresh = MattStash(str(temp_db), password=stash.password)
    assert fresh.get_db_url("my", database="shop", dialect="").startswith("mysql://")


# ---------------------------------------------------------------------------
# secret input: L-5 (empty values), L-8 (size cap), L-9 (strict UTF-8)
# ---------------------------------------------------------------------------


def test_l5_empty_database_password_options_are_errors(temp_db: Path, monkeypatch: pytest.MonkeyPatch, caplog):
    monkeypatch.setenv("KDBX_PASSWORD", "would-be-used-silently")
    for argv in (["--db-password-file", ""], ["--password", ""], ["--db-password", ""]):
        assert main(["--db", str(temp_db), *argv, "keys"]) == exit_codes.ERROR, argv


def test_l8_password_files_are_size_capped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    big = tmp_path / "big"
    big.write_bytes(b"x" * (MAX_PASSWORD_FILE_BYTES + 1))
    with pytest.raises(OSError) as excinfo:
        read_password_file(str(big))
    assert excinfo.value.errno == errno.EFBIG

    from mattstash import MattStash
    from mattstash.utils.exceptions import DatabaseAccessError

    db = tmp_path / "x.kdbx"
    MattStash.create(str(db), password="pw", sidecar=False)
    monkeypatch.setenv("KDBX_PASSWORD_FILE", str(big))
    with pytest.raises(DatabaseAccessError, match="KDBX_PASSWORD_FILE"):
        MattStash(str(db)).list()


def test_l9_invalid_utf8_on_stdin_is_a_clean_error(monkeypatch: pytest.MonkeyPatch):
    class Stdin(io.TextIOWrapper):
        def isatty(self) -> bool:
            return False

    monkeypatch.setattr(sys, "stdin", Stdin(io.BytesIO(b"\xff\xfe\n"), encoding="utf-8", errors="surrogateescape"))
    with pytest.raises(InputError, match="not valid UTF-8"):
        read_stdin_line("--new-password-stdin")
