"""
CLI server-mode client hardening (docs/security-review.md H-6f client side, M-9, L-1 for the API key).

* path segments are percent-encoded (``db#prod`` must not become ``db``);
* a plain ``http://`` URL to a non-loopback host logs one warning (never refuses);
* error messages never contain the API key or response bodies;
* the API key can come from a file (``--api-key-file`` / ``MATTSTASH_API_KEY_FILE``).
"""

import logging
from argparse import Namespace
from pathlib import Path
from typing import Optional

import httpx
import pytest
from fake_server import FakeServer

from mattstash.cli import exit_codes
from mattstash.cli.handlers.base import BaseHandler
from mattstash.cli.http_client import (
    MattStashServerClient,
    insecure_http_allowed,
    is_loopback_host,
    segment,
    warn_if_insecure,
)
from mattstash.cli.main import main
from mattstash.utils.exceptions import ServerError

KEY = "k3y-s3cret-AAAA"
URL = "http://localhost:8000"
CLIENT_LOGGER = "mattstash.cli.http_client"


@pytest.fixture()
def server(monkeypatch: pytest.MonkeyPatch) -> FakeServer:
    return FakeServer(api_key=KEY).install(monkeypatch)


@pytest.fixture()
def client(server: FakeServer) -> MattStashServerClient:
    return MattStashServerClient(URL, KEY)


# ---------------------------------------------------------------------------
# M-9: percent-encoding of path segments
# ---------------------------------------------------------------------------

TRICKY_TITLES = ["db#prod", "a/b", "q?x=1", "100%", "sp ace", "ünï", "a@b", "x/../y", "..", "semi;colon"]


@pytest.mark.parametrize("title", TRICKY_TITLES)
def test_segment_encodes_everything_reserved(title: str):
    encoded = segment(title)
    assert "/" not in encoded and "#" not in encoded and "?" not in encoded and " " not in encoded
    assert encoded not in (".", "..")


@pytest.mark.parametrize("title", TRICKY_TITLES)
def test_put_get_delete_versions_address_the_exact_name(server: FakeServer, client: MattStashServerClient, title: str):
    client.put(title, value="v1")
    assert list(server.store) == [title], "the secret must be stored under its exact name"
    assert client.get(title, show_password=True) is not None
    assert client.versions(title) == ["0000000001"]
    assert client.delete(title) is True
    assert server.store == {}
    # every request addressed the encoded segment, exactly once, with no fragment/query leakage
    for request in server.requests:
        raw = request.url.raw_path.decode()
        assert raw.startswith("/api/v1/credentials/")
        assert "#" not in raw.split("?")[0] and " " not in raw


def test_hash_in_title_no_longer_truncates_the_name(server: FakeServer, client: MattStashServerClient):
    """Regression: 'db#prod' used to be sent as '/credentials/db#prod' i.e. the name 'db'."""
    client.put("db#prod", value="x")
    assert "db" not in server.store
    assert "db#prod" in server.store
    assert server.requests[-1].url.raw_path.decode().split("?")[0] == "/api/v1/credentials/db%23prod"


def test_db_url_title_is_encoded(server: FakeServer, client: MattStashServerClient):
    url = client.db_url("pg#1", driver="psycopg", database="app", mask_password=True)
    assert url.startswith("fake://pg#1?")
    assert server.requests[-1].url.raw_path.decode().startswith("/api/v1/db-url/pg%231")


def test_cli_server_mode_put_get_with_special_title(server: FakeServer, monkeypatch: pytest.MonkeyPatch, capsys):
    base = ["--server-url", URL, "--api-key", KEY]
    assert main([*base, "put", "db#prod", "--value", "pw"]) == 0
    assert "db#prod" in server.store
    capsys.readouterr()
    assert main([*base, "get", "db#prod", "--show-password"]) == 0
    assert "pw" in capsys.readouterr().out


def test_delete_with_version_sends_query_parameter(server: FakeServer, client: MattStashServerClient):
    server.add("k", "one")
    server.add("k", "two")
    assert client.delete("k", version=1) is True
    request = server.requests[-1]
    assert request.method == "DELETE" and dict(request.url.params) == {"version": "1"}
    assert list(server.store["k"]) == [2]
    # no version -> no query string at all
    assert client.delete("k") is True
    assert server.requests[-1].url.query == b""


# ---------------------------------------------------------------------------
# M-9 / H-6f: plain-http warning
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "host,expected",
    [
        ("localhost", True),
        ("LOCALHOST", True),
        ("localhost.", True),
        ("127.0.0.1", True),
        ("127.5.5.5", True),
        ("::1", True),
        ("[::1]", True),
        ("10.0.0.5", False),
        ("192.168.1.1", False),
        ("example.com", False),
        ("mattstash", False),
        ("127.0.0.1.evil.com", False),
        ("localhost.evil.com", False),
        ("", False),
        (None, False),
    ],
)
def test_is_loopback_host(host: Optional[str], expected: bool):
    assert is_loopback_host(host) is expected


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com",
        "http://10.1.2.3:8000",
        "http://mattstash:8000",
        "HTTP://Example.COM/",
        "http://[2001:db8::1]:80",
    ],
)
def test_warns_once_for_plain_http_to_remote_host(url: str, caplog: pytest.LogCaptureFixture):
    with caplog.at_level(logging.WARNING, logger=CLIENT_LOGGER):
        MattStashServerClient(url, KEY)
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "clear text" in warnings[0].getMessage()
    assert KEY not in caplog.text


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://127.9.9.9",
        "http://[::1]:8000",
        "https://example.com",
        "https://10.0.0.5:8443",
    ],
)
def test_no_warning_for_loopback_or_https(url: str, caplog: pytest.LogCaptureFixture):
    with caplog.at_level(logging.WARNING, logger=CLIENT_LOGGER):
        MattStashServerClient(url, KEY)
    assert caplog.records == []


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "Yes", " 1 "])
def test_warning_can_be_silenced(value: str, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture):
    monkeypatch.setenv("MATTSTASH_ALLOW_INSECURE_HTTP", value)
    assert insecure_http_allowed()
    with caplog.at_level(logging.WARNING, logger=CLIENT_LOGGER):
        MattStashServerClient("http://example.com", KEY)
    assert caplog.records == []


@pytest.mark.parametrize("value", ["0", "false", "no", "", "maybe"])
def test_other_values_do_not_silence_the_warning(
    value: str, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
):
    monkeypatch.setenv("MATTSTASH_ALLOW_INSECURE_HTTP", value)
    assert not insecure_http_allowed()
    with caplog.at_level(logging.WARNING, logger=CLIENT_LOGGER):
        MattStashServerClient("http://example.com", KEY)
    assert len(caplog.records) == 1


def test_plain_http_is_never_refused(server: FakeServer, caplog: pytest.LogCaptureFixture):
    """Plain HTTP on a compose network is the documented pattern: warn, but work."""
    server.add("x", "v")
    with caplog.at_level(logging.WARNING, logger=CLIENT_LOGGER):
        remote = MattStashServerClient("http://mattstash:8000", KEY)
        assert remote.get("x", show_password=True) is not None
    assert len(caplog.records) == 1


def test_warn_if_insecure_handles_garbage():
    assert warn_if_insecure("not a url") is False
    assert warn_if_insecure("http://[bad") is False


def test_tls_verification_stays_on(monkeypatch: pytest.MonkeyPatch):
    seen = {}
    real = httpx.Client

    def factory(**kwargs):
        seen.update(kwargs)
        return real(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"status": "ok"})), **kwargs)

    monkeypatch.setattr(httpx, "Client", factory)
    MattStashServerClient("https://example.test", KEY).health_check()
    assert seen["verify"] is True


# ---------------------------------------------------------------------------
# Error messages never leak the key or the response body
# ---------------------------------------------------------------------------


def test_http_error_messages_exclude_key_and_body(server: FakeServer, client: MattStashServerClient):
    leaky = f"debug dump: api key {KEY} password=hunter2"
    server.override = lambda r: httpx.Response(500, text=leaky)
    with pytest.raises(ServerError) as excinfo:
        client.get("x", show_password=True)
    text = str(excinfo.value)
    assert excinfo.value.status_code == 500
    assert KEY not in text and "hunter2" not in text and "debug dump" not in text
    assert "HTTP 500" in text and "/api/v1/credentials/x" in text
    assert "show_password" not in text, "the query string is not part of the message"


@pytest.mark.parametrize(
    "status,fragment",
    [(400, "rejected"), (401, "check the API key"), (403, "not allowed"), (405, "read-only"), (429, "too many")],
)
def test_status_hints(server: FakeServer, client: MattStashServerClient, status: int, fragment: str):
    server.override = lambda r: httpx.Response(status, json={"detail": f"echo {KEY}"})
    with pytest.raises(ServerError) as excinfo:
        client.list()
    assert fragment in str(excinfo.value)
    assert KEY not in str(excinfo.value) and "echo" not in str(excinfo.value)


def test_rate_limit_message_includes_numeric_retry_after_only(server: FakeServer, client: MattStashServerClient):
    server.override = lambda r: httpx.Response(429, headers={"Retry-After": "17"}, json={})
    with pytest.raises(ServerError, match="retry after 17s"):
        client.list()
    server.override = lambda r: httpx.Response(429, headers={"Retry-After": f"x{KEY}"}, json={})
    with pytest.raises(ServerError) as excinfo:
        client.list()
    assert KEY not in str(excinfo.value)


def test_wrong_api_key_is_a_clean_error(server: FakeServer):
    bad = MattStashServerClient(URL, "wrong-key")
    with pytest.raises(ServerError) as excinfo:
        bad.list()
    assert excinfo.value.status_code == 401
    assert "wrong-key" not in str(excinfo.value)


def test_redirects_are_not_followed_and_reported(server: FakeServer, client: MattStashServerClient):
    server.override = lambda r: httpx.Response(301, headers={"Location": "https://evil.example/steal"})
    with pytest.raises(ServerError, match="redirect") as excinfo:
        client.list()
    assert "evil.example" not in str(excinfo.value)
    assert len(server.requests) == 1


def test_transport_errors_are_redacted(monkeypatch: pytest.MonkeyPatch):
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"cannot connect with {KEY} to host")

    real = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kw: real(transport=httpx.MockTransport(boom), **kw))
    with pytest.raises(ServerError) as excinfo:
        MattStashServerClient(URL, KEY).list()
    assert KEY not in str(excinfo.value)
    assert "ConnectError" in str(excinfo.value)
    assert excinfo.value.__cause__ is None and excinfo.value.__suppress_context__


def test_non_json_and_non_object_responses(server: FakeServer, client: MattStashServerClient):
    server.override = lambda r: httpx.Response(200, text="<html>secret page</html>")
    with pytest.raises(ServerError, match="not valid JSON") as excinfo:
        client.list()
    assert "secret page" not in str(excinfo.value)
    server.override = lambda r: httpx.Response(200, json=["a", "b"])
    with pytest.raises(ServerError, match="unexpected response"):
        client.list()


def test_client_repr_hides_key(client: MattStashServerClient):
    assert KEY not in repr(client)


def test_cli_prints_sanitised_server_errors(
    server: FakeServer, caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
):
    server.override = lambda r: httpx.Response(500, text=f"boom {KEY} hunter2")
    rc = main(["--server-url", URL, "--api-key", KEY, "get", "x"])
    assert rc == exit_codes.ERROR
    captured = capsys.readouterr()
    combined = caplog.text + captured.err + captured.out
    assert "HTTP 500" in combined
    assert KEY not in combined and "hunter2" not in combined


# ---------------------------------------------------------------------------
# L-1: API key from a file / environment
# ---------------------------------------------------------------------------


class _Probe(BaseHandler):
    def handle(self, args: Namespace) -> int:  # pragma: no cover - never called
        return 0


def key_file(tmp_path: Path, content: str = f"{KEY}\n") -> Path:
    path = tmp_path / "api-key"
    path.write_text(content)
    path.chmod(0o600)
    return path


def test_api_key_precedence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    probe = _Probe()
    file_a = key_file(tmp_path, "from-file-flag\n")
    file_b = tmp_path / "env-file"
    file_b.write_text("from-env-file\n")
    monkeypatch.setenv("MATTSTASH_API_KEY_FILE", str(file_b))
    assert probe.resolve_api_key(Namespace()) == "from-env-file"
    monkeypatch.setenv("MATTSTASH_API_KEY", "from-env")
    assert probe.resolve_api_key(Namespace()) == "from-env"
    assert probe.resolve_api_key(Namespace(api_key=None, api_key_file=str(file_a))) == "from-file-flag"
    assert probe.resolve_api_key(Namespace(api_key="from-flag", api_key_file=None)) == "from-flag"
    monkeypatch.delenv("MATTSTASH_API_KEY")
    monkeypatch.delenv("MATTSTASH_API_KEY_FILE")
    assert probe.resolve_api_key(Namespace()) is None


def test_api_key_flag_and_file_conflict(tmp_path: Path):
    from mattstash.cli.inputs import InputError

    with pytest.raises(InputError, match="mutually exclusive"):
        _Probe().resolve_api_key(Namespace(api_key="a", api_key_file=str(key_file(tmp_path))))


def test_cli_uses_api_key_file(server: FakeServer, tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    server.add("x", "the-value")
    path = key_file(tmp_path, f"  {KEY}  \n\n")
    assert main(["--server-url", URL, "--api-key-file", str(path), "get", "x", "--show-password"]) == 0
    assert "the-value" in capsys.readouterr().out
    assert server.requests[-1].headers["X-API-Key"] == KEY  # surrounding whitespace stripped


def test_cli_uses_api_key_file_from_environment(
    server: FakeServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    server.add("x", "the-value")
    monkeypatch.setenv("MATTSTASH_API_KEY_FILE", str(key_file(tmp_path)))
    monkeypatch.setenv("MATTSTASH_SERVER_URL", URL)
    assert main(["get", "x", "--show-password"]) == 0
    assert "the-value" in capsys.readouterr().out


def test_cli_explicit_key_beats_environment_file(server: FakeServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    server.add("x", "v")
    wrong = tmp_path / "wrong"
    wrong.write_text("wrong-key\n")
    monkeypatch.setenv("MATTSTASH_API_KEY_FILE", str(wrong))
    monkeypatch.setenv("MATTSTASH_API_KEY", "also-wrong")
    assert main(["--server-url", URL, "--api-key", KEY, "get", "x"]) == 0


@pytest.mark.parametrize("content", ["", "\n  \n"])
def test_cli_rejects_empty_key_file(server: FakeServer, tmp_path: Path, content: str, caplog: pytest.LogCaptureFixture):
    rc = main(["--server-url", URL, "--api-key-file", str(key_file(tmp_path, content)), "get", "x"])
    assert rc == exit_codes.ERROR
    assert "is empty" in caplog.text
    assert server.requests == []


def test_cli_missing_key_file_is_an_error_not_a_silent_fallback(
    server: FakeServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
):
    monkeypatch.setenv("MATTSTASH_API_KEY", KEY)  # a valid env key must not mask the explicit bad flag
    rc = main(["--server-url", URL, "--api-key-file", str(tmp_path / "nope"), "get", "x"])
    assert rc == exit_codes.ERROR
    assert "cannot read" in caplog.text and KEY not in caplog.text
    assert server.requests == []


def test_cli_without_any_key_explains_options(server: FakeServer, caplog: pytest.LogCaptureFixture):
    assert main(["--server-url", URL, "get", "x"]) == exit_codes.ERROR
    assert "--api-key-file" in caplog.text and "MATTSTASH_API_KEY_FILE" in caplog.text
    assert server.requests == []


def test_cli_help_steers_away_from_argv_secrets(capsys: pytest.CaptureFixture[str]):
    with pytest.raises(SystemExit):
        main(["--help"])
    out = capsys.readouterr().out
    assert "--api-key-file" in out and "MATTSTASH_API_KEY_FILE" in out
    assert "ps" in out and "shell history" in out
