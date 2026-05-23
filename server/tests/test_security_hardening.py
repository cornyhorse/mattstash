"""Security hardening regression tests."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from starlette.responses import Response

from app.middleware.logging import RequestLoggingMiddleware
from app.rate_limit import get_client_address


def test_rate_limit_key_ignores_forwarded_headers() -> None:
    """Spoofed forwarding headers must not affect rate-limit identity."""
    request = SimpleNamespace(
        client=SimpleNamespace(host="203.0.113.10"),
        headers={"x-forwarded-for": "198.51.100.99"},
    )

    assert get_client_address(request) == "203.0.113.10"


@pytest.mark.asyncio
async def test_request_body_size_limit(clean_env, monkeypatch) -> None:
    """Oversized declared request bodies are rejected before endpoint handling."""
    monkeypatch.setenv("KDBX_PASSWORD", "test-password")
    monkeypatch.setenv("MATTSTASH_API_KEY", "test-key")
    monkeypatch.setenv("MATTSTASH_MAX_REQUEST_BODY_BYTES", "10")

    from importlib import reload
    import app.config as config_module
    import app.middleware.logging as logging_module

    reload(config_module)
    reload(logging_module)

    request = Mock()
    request.headers = {"content-length": "11"}
    request.method = "POST"
    request.url.path = "/api/v1/credentials/test"
    request.client.host = "127.0.0.1"

    async def call_next(_request):
        return Response("should not run")

    middleware = logging_module.RequestLoggingMiddleware(app=Mock())
    response = await middleware.dispatch(request, call_next)

    assert response.status_code == 413
    assert response.headers["x-content-type-options"] == "nosniff"
