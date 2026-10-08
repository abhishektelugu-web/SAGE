"""Tests for SAGE Backend Event creation, retrieval, and filtering."""

def test_create_and_retrieve_event(client):
    """Test creating a security event via POST /api/events and fetching via GET /api/events/{event_id}."""
    payload = {
        "action_id": "ACT-TEST-001",
        "agent_id": "agent_alpha",
        "action_type": "query_database",
        "resource": "db:users",
        "parameters": {"limit": 10},
        "is_malicious": False,
        "threat_type": "none",
        "ml_confidence": 0.05,
        "ml_reason": "Harmless database select",
        "risk_score": 12.0,
        "decision": "ALLOW",
        "decision_reason": "Read permitted by policy",
    }
    create_resp = client.post("/api/events", json=payload)
    assert create_resp.status_code == 201
    event_data = create_resp.json()
    assert "event_id" in event_data
    event_id = event_data["event_id"]
    assert event_data["action_id"] == "ACT-TEST-001"
    assert event_data["decision"] == "ALLOW"

    # Fetch individual event
    get_resp = client.get(f"/api/events/{event_id}")
    assert get_resp.status_code == 200
    fetched = get_resp.json()
    assert fetched["event_id"] == event_id
    assert fetched["resource"] == "db:users"


def test_get_nonexistent_event_404(client):
    """Test that querying a non-existent event ID returns 404 Not Found."""
    response = client.get("/api/events/EVT-DOES-NOT-EXIST-999")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_event_filtering(client):
    """Test filtering events by decision, threat_type, and agent_id."""
    # Seed 3 distinct events
    events = [
        {
            "action_id": "ACT-F1",
            "agent_id": "agent_1",
            "action_type": "read_file",
            "threat_type": "prompt_injection",
            "decision": "BLOCK",
            "risk_score": 90.0,
            "is_malicious": True,
        },
        {
            "action_id": "ACT-F2",
            "agent_id": "agent_1",
            "action_type": "read_public",
            "threat_type": "none",
            "decision": "ALLOW",
            "risk_score": 5.0,
            "is_malicious": False,
        },
        {
            "action_id": "ACT-F3",
            "agent_id": "agent_2",
            "action_type": "send_email",
            "threat_type": "external_transfer",
            "decision": "APPROVAL_REQUIRED",
            "risk_score": 50.0,
            "is_malicious": False,
        },
    ]
    for ev in events:
        resp = client.post("/api/events", json=ev)
        assert resp.status_code == 201

    # Filter by decision=BLOCK
    resp_block = client.get("/api/events", params={"decision": "BLOCK"})
    assert resp_block.status_code == 200
    data_block = resp_block.json()
    assert len(data_block) == 1
    assert data_block[0]["decision"] == "BLOCK"
    assert data_block[0]["action_id"] == "ACT-F1"

    # Filter by threat_type=external_transfer
    resp_threat = client.get("/api/events", params={"threat_type": "external_transfer"})
    assert resp_threat.status_code == 200
    data_threat = resp_threat.json()
    assert len(data_threat) == 1
    assert data_threat[0]["threat_type"] == "external_transfer"

    # Filter by agent_id=agent_1
    resp_agent = client.get("/api/events", params={"agent_id": "agent_1"})
    assert resp_agent.status_code == 200
    data_agent = resp_agent.json()
    assert len(data_agent) == 2


def test_secret_sanitization(client):
    """Test that audit logging redacts sensitive parameters such as passwords and tokens."""
    payload = {
        "action_id": "ACT-SECRET-01",
        "agent_id": "test_agent",
        "action_type": "authenticate",
        "resource": "auth_endpoint",
        "parameters": {
            "username": "admin",
            "password": "SuperSecretPassword123!",
            "api_key": "sk-1234567890abcdef",
        },
        "decision": "ALLOW",
        "risk_score": 10.0,
    }
    resp = client.post("/api/events", json=payload)
    assert resp.status_code == 201
    event_data = resp.json()
    # Stored parameters must be sanitized
    params = event_data["parameters"]
    assert params["username"] == "admin"
    assert params["password"] == "[REDACTED_SECRET]"
    assert params["api_key"] == "[REDACTED_SECRET]"
