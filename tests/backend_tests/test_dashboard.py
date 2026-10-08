"""Tests for SAGE Dashboard Statistics calculation from database events."""

def test_dashboard_stats_empty(client):
    """Verify stats on an empty database return zeros."""
    resp = client.get("/api/dashboard/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_events"] == 0
    assert data["allowed"] == 0
    assert data["blocked"] == 0
    assert data["approval_required"] == 0
    assert data["threats_detected"] == 0


def test_dashboard_stats_aggregation(client):
    """Verify stats accurately aggregate across stored security events."""
    events = [
        {"action_id": "A1", "action_type": "read", "decision": "ALLOW", "is_malicious": False, "threat_type": "none"},
        {"action_id": "A2", "action_type": "read", "decision": "ALLOW", "is_malicious": False, "threat_type": "none"},
        {"action_id": "A3", "action_type": "exec", "decision": "BLOCK", "is_malicious": True, "threat_type": "prompt_injection"},
        {"action_id": "A4", "action_type": "exec", "decision": "BLOCK", "is_malicious": True, "threat_type": "sensitive_resource"},
        {"action_id": "A5", "action_type": "transfer", "decision": "APPROVAL_REQUIRED", "is_malicious": False, "threat_type": "external_transfer"},
    ]
    for ev in events:
        resp = client.post("/api/events", json=ev)
        assert resp.status_code == 201

    resp = client.get("/api/dashboard/stats")
    assert resp.status_code == 200
    stats = resp.json()

    assert stats["total_events"] == 5
    assert stats["allowed"] == 2
    assert stats["blocked"] == 2
    assert stats["approval_required"] == 1
    assert stats["threats_detected"] == 3  # A3 (prompt_injection), A4 (sensitive_resource), A5 (external_transfer)

    # Check breakdown dictionaries
    assert stats["decision_breakdown"]["ALLOW"] == 2
    assert stats["decision_breakdown"]["BLOCK"] == 2
    assert stats["decision_breakdown"]["APPROVAL_REQUIRED"] == 1

    assert stats["threat_breakdown"]["prompt_injection"] == 1
    assert stats["threat_breakdown"]["sensitive_resource"] == 1
    assert stats["threat_breakdown"]["external_transfer"] == 1
