"""Security tests for database URL router validation."""

from fastapi.testclient import TestClient


def test_db_url_rejects_unapproved_driver(test_app, mock_mattstash):
    """Driver names are allowlisted rather than accepted by regex alone."""
    from app.dependencies import get_mattstash, verify_api_key_header

    test_app.dependency_overrides[get_mattstash] = lambda: mock_mattstash
    test_app.dependency_overrides[verify_api_key_header] = lambda: "test-api-key"

    client = TestClient(test_app)
    response = client.get(
        "/api/v1/db-url/example?driver=notarealdriver",
        headers={"X-API-Key": "test-api-key"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid driver name"
    test_app.dependency_overrides.clear()
