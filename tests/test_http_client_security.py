"""Security-focused tests for the MattStash server HTTP client."""

from unittest.mock import patch

import httpx

from mattstash.cli.http_client import MattStashServerClient


def test_http_client_enables_tls_verification() -> None:
    """HTTP client should explicitly verify TLS certificates (and never follow redirects with the API key)."""
    captured: dict = {}
    real_client = httpx.Client

    def factory(**kwargs):
        captured.update(kwargs)
        transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"status": "healthy"}))
        return real_client(transport=transport, **kwargs)

    with patch("mattstash.cli.http_client.httpx.Client", factory):
        client = MattStashServerClient("https://example.test", "api-key")
        assert client.health_check() == {"status": "healthy"}

    assert captured == {"timeout": 30.0, "verify": True}  # follow_redirects stays at httpx's default: off


def test_http_client_preserves_simple_value_mode() -> None:
    """Simple secrets must be sent as value, not as full-credential password."""
    client = MattStashServerClient("https://example.test", "api-key")

    with patch.object(client, "_make_request", return_value={"name": "api-token", "created": True}) as request:
        client.put("api-token", value="secret-value")

    request.assert_called_once_with(
        "POST",
        "/api/v1/credentials/api-token",
        json_data={"value": "secret-value"},
    )
