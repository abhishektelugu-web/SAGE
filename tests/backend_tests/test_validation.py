"""Tests for input validation and schema constraints."""

def test_missing_required_fields_fails(client):
    """Test that submitting an event without required fields fails with 422 Unprocessable Entity."""
    # Missing action_id and action_type
    invalid_payload = {
        "resource": "doc.txt",
    }
    resp = client.post("/api/events", json=invalid_payload)
    assert resp.status_code == 422
    errors = resp.json()["detail"]
    field_names = [e["loc"][-1] for e in errors]
    assert "action_id" in field_names
    assert "action_type" in field_names


def test_invalid_confidence_range_fails(client):
    """Test that ml_confidence outside 0.0-1.0 range triggers 422 validation error."""
    invalid_payload = {
        "action_id": "ACT-VAL-01",
        "action_type": "test_action",
        "ml_confidence": 1.5,  # Invalid: > 1.0
    }
    resp = client.post("/api/events", json=invalid_payload)
    assert resp.status_code == 422


def test_invalid_risk_score_range_fails(client):
    """Test that risk_score outside 0.0-100.0 triggers 422 validation error."""
    invalid_payload = {
        "action_id": "ACT-VAL-02",
        "action_type": "test_action",
        "risk_score": 150.0,  # Invalid: > 100.0
    }
    resp = client.post("/api/events", json=invalid_payload)
    assert resp.status_code == 422
