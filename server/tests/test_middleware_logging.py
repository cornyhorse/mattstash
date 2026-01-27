"""Tests for app.middleware.logging module."""
from unittest.mock import MagicMock, patch

import pytest

from app.middleware.logging import RequestLoggingMiddleware, mask_sensitive_data


class TestLoggingMiddleware:
    """Test request/response logging middleware."""
    
    def test_mask_sensitive_password(self):
        """Masks password in JSON."""
        text = '{"username": "admin", "password": "secret123"}'
        result = mask_sensitive_data(text)
        
        assert '"password": "*****"' in result
        assert "secret123" not in result
        assert '"username": "admin"' in result
    
    def test_mask_sensitive_value(self):
        """Masks value in JSON."""
        text = '{"name": "test", "value": "confidential_data"}'
        result = mask_sensitive_data(text)
        
        assert '"value": "*****"' in result
        assert "confidential_data" not in result
    
    def test_mask_sensitive_api_key(self):
        """Masks X-API-Key header."""
        text = 'X-API-Key: secret-key-123'
        result = mask_sensitive_data(text)
        
        assert 'X-API-Key: *****' in result
        assert 'secret-key-123' not in result
    
    def test_mask_multiple_patterns(self):
        """Masks multiple sensitive items."""
        text = 'X-API-Key: key123 {"password": "mypass", "value": "myval"}'
        result = mask_sensitive_data(text)
        
        assert 'X-API-Key: *****' in result
        assert '"password": "*****"' in result
        assert '"value": "*****"' in result
        assert 'key123' not in result
        assert 'mypass' not in result
        assert 'myval' not in result
    
    def test_mask_no_sensitive_data(self):
        """Returns unchanged if no sensitive data."""
        text = 'Normal log message without sensitive data'
        result = mask_sensitive_data(text)
        
        assert result == text
    
    @pytest.mark.asyncio
    async def test_middleware_logs_request(self, clean_env, monkeypatch):
        """Logs incoming request details."""
        from starlette.requests import Request
        from starlette.responses import JSONResponse
        
        # Create mock request
        mock_request = MagicMock(spec=Request)
        mock_request.method = "GET"
        mock_request.url.path = "/api/v1/credentials"
        mock_request.client.host = "127.0.0.1"
        
        # Create mock call_next
        async def mock_call_next(request):
            return JSONResponse({"status": "ok"})
        
        middleware = RequestLoggingMiddleware(app=MagicMock())
        
        with patch('app.middleware.logging.logger') as mock_logger:
            response = await middleware.dispatch(mock_request, mock_call_next)
            
            # Verify request was logged
            assert mock_logger.info.called
            first_call = mock_logger.info.call_args_list[0][0][0]
            assert "Request: GET /api/v1/credentials" in first_call
            assert "127.0.0.1" in first_call
    
    @pytest.mark.asyncio
    async def test_middleware_logs_response(self, clean_env, monkeypatch):
        """Logs response status and duration."""
        from starlette.requests import Request
        from starlette.responses import JSONResponse
        
        mock_request = MagicMock(spec=Request)
        mock_request.method = "POST"
        mock_request.url.path = "/api/v1/credentials"
        mock_request.client.host = "127.0.0.1"
        
        async def mock_call_next(request):
            return JSONResponse({"created": True}, status_code=201)
        
        middleware = RequestLoggingMiddleware(app=MagicMock())
        
        with patch('app.middleware.logging.logger') as mock_logger:
            response = await middleware.dispatch(mock_request, mock_call_next)
            
            # Verify response was logged
            assert mock_logger.info.call_count == 2
            second_call = mock_logger.info.call_args_list[1][0][0]
            assert "Response: POST /api/v1/credentials" in second_call
            assert "Status: 201" in second_call
            assert "Duration:" in second_call
    
    @pytest.mark.asyncio
    async def test_middleware_logs_error(self, clean_env, monkeypatch):
        """Logs exceptions properly."""
        from starlette.requests import Request
        
        mock_request = MagicMock(spec=Request)
        mock_request.method = "GET"
        mock_request.url.path = "/api/v1/error"
        mock_request.client.host = "127.0.0.1"
        
        async def mock_call_next(request):
            raise ValueError("Test error")
        
        middleware = RequestLoggingMiddleware(app=MagicMock())
        
        with patch('app.middleware.logging.logger') as mock_logger:
            with pytest.raises(ValueError):
                await middleware.dispatch(mock_request, mock_call_next)
            
            # Verify error was logged
            assert mock_logger.error.called
            error_msg = mock_logger.error.call_args[0][0]
            assert "Error: GET /api/v1/error" in error_msg
            assert "ValueError: Test error" in error_msg
            assert "Duration:" in error_msg
    
    @pytest.mark.asyncio
    async def test_middleware_handles_no_client(self, clean_env, monkeypatch):
        """Handles missing client IP."""
        from starlette.requests import Request
        from starlette.responses import JSONResponse
        
        mock_request = MagicMock(spec=Request)
        mock_request.method = "GET"
        mock_request.url.path = "/api/health"
        mock_request.client = None  # No client info
        
        async def mock_call_next(request):
            return JSONResponse({"status": "healthy"})
        
        middleware = RequestLoggingMiddleware(app=MagicMock())
        
        with patch('app.middleware.logging.logger') as mock_logger:
            response = await middleware.dispatch(mock_request, mock_call_next)
            
            # Should log "unknown" for missing client
            first_call = mock_logger.info.call_args_list[0][0][0]
            assert "unknown" in first_call
