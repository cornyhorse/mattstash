"""Full HTTP round-trip integration tests: POST → GET → DELETE."""

_API_KEY = "test-api-key"
_HEADERS = {"X-API-Key": _API_KEY}
_CRED_NAME = "roundtrip-cred"


def test_post_get_delete_roundtrip(real_kdbx_client):
    """POST a credential, GET it back, then DELETE it — verifying end-to-end HTTP flow."""
    client = real_kdbx_client

    # --- POST: create ---
    response = client.post(
        f"/api/v1/credentials/{_CRED_NAME}",
        json={"value": "my-secret-value"},
        headers=_HEADERS,
    )
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == _CRED_NAME
    assert data["created"] is True

    # --- GET: read back with password revealed ---
    response = client.get(
        f"/api/v1/credentials/{_CRED_NAME}?show_password=true",
        headers=_HEADERS,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == _CRED_NAME
    assert data["password"] == "my-secret-value"

    # --- DELETE: remove ---
    response = client.delete(
        f"/api/v1/credentials/{_CRED_NAME}",
        headers=_HEADERS,
    )
    assert response.status_code == 200

    # Verify deletion: GET should now return 404
    response = client.get(
        f"/api/v1/credentials/{_CRED_NAME}",
        headers=_HEADERS,
    )
    assert response.status_code == 404
