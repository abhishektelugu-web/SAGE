"""Tests for SAGE Backend Health and Root endpoints."""

def test_health_check(client):
    """Verify GET /health returns 200 OK and expected status payload."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "service" in data
    assert "version" in data


def test_root_metadata(client):
    """Verify GET / returns service information and route links."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert "events_endpoint" in data
    assert "stats_endpoint" in data
