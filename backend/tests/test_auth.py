"""
Tests for authentication endpoints.
"""


def test_login_success(client):
    """Test login with valid credentials."""
    # TODO: Create test user, then test login
    pass


def test_login_invalid_credentials(client):
    """Test login with invalid credentials returns 401."""
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "wrong@example.com", "password": "wrongpassword"},
    )
    assert response.status_code in (401, 422)


def test_protected_route_without_token(client):
    """Test accessing protected route without token returns 401/403."""
    response = client.get("/api/v1/users/")
    assert response.status_code in (401, 403)
