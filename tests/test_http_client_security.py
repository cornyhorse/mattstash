"""Security-focused tests for the MattStash server HTTP client."""

from unittest.mock import Mock, patch

from mattstash.cli.http_client import MattStashServerClient


def test_http_client_enables_tls_verification() -> None:
    """HTTP client should explicitly verify TLS certificates."""
    mock_response = Mock()
    mock_response.json.return_value = {"status": "healthy"}
    mock_response.raise_for_status.return_value = None

    mock_client = Mock()
    mock_client.request.return_value = mock_response

    with patch("mattstash.cli.http_client.httpx.Client") as client_cls:
        client_cls.return_value.__enter__.return_value = mock_client

        client = MattStashServerClient("https://example.test", "api-key")
        client.health_check()

    client_cls.assert_called_once_with(timeout=30.0, verify=True)


def test_http_client_preserves_simple_value_mode() -> None:
    """Simple secrets must be sent as value, not as full-credential password."""
    client = MattStashServerClient("https://example.test", "api-key")

    with patch.object(client, "_make_request", return_value={"created": True}) as request:
        client.put("api-token", value="secret-value")

    request.assert_called_once_with(
        "POST",
        "/api/v1/credentials/api-token",
        json_data={"value": "secret-value"},
    )
