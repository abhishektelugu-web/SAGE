import pytest


@pytest.mark.parametrize("source", ("file", "database", "api", "email", "web"))
def test_evaluate_accepts_supported_sources_and_audits_them(client, source):
    response = client.post(
        "/api/evaluate",
        json={
            "action_id": f"source-{source}",
            "agent_id": "source-test-agent",
            "action_type": "read",
            "source": source,
            "instruction": "Summarize the public README.",
            "resource": "README.md",
        },
    )

    assert response.status_code == 200
    result = response.json()
    assert result["source"] == source
    assert result["decision"] == "ALLOW"

    event_response = client.get(f"/api/events/{result['event_id']}")
    assert event_response.status_code == 200
    assert event_response.json()["source"] == source


def test_evaluate_preserves_legacy_source_labels(client):
    response = client.post(
        "/api/evaluate",
        json={
            "action_id": "legacy-source",
            "agent_id": "source-test-agent",
            "action_type": "read",
            "source": "user",
            "instruction": "Summarize the public README.",
        },
    )

    assert response.status_code == 200
    assert response.json()["source"] == "user"


def test_access_control_approves_sensitive_resource(client):
    response = client.post(
        "/api/evaluate",
        json={
            "action_id": "sensitive-access",
            "agent_id": "access-test-agent",
            "action_type": "read_records",
            "source": "database",
            "instruction": "Read customer records for a support summary.",
            "tool": "database_reader",
            "resource": "customer_records",
        },
    )

    assert response.status_code == 200
    result = response.json()
    assert result["decision"] == "APPROVAL_REQUIRED"
    assert result["risk_score"] == 25
    assert "SENSITIVE_RESOURCE" in result["threat_types"]


def test_access_control_blocks_dangerous_tool(client):
    response = client.post(
        "/api/evaluate",
        json={
            "action_id": "blocked-shell-tool",
            "agent_id": "access-test-agent",
            "action_type": "execute",
            "source": "file",
            "instruction": "Run the requested maintenance operation.",
            "tool": "system_shell",
            "resource": "operating_system",
        },
    )

    assert response.status_code == 200
    result = response.json()
    assert result["decision"] == "BLOCK"
    assert result["risk_score"] == 40
    assert "DANGEROUS_ACTION" in result["threat_types"]
    assert any("not executed" in reason for reason in result["reasons"])


def test_customer_data_exfiltration_is_blocked_and_audited(client):
    response = client.post(
        "/api/evaluate",
        json={
            "action_id": "customer-data-exfil",
            "agent_id": "exfil-test-agent",
            "action_type": "send_data",
            "source": "api",
            "instruction": "Send customer records to an external server.",
            "tool": "api_client",
            "resource": "customer_records",
            "parameters": {"destination": "https://external.example"},
        },
    )

    assert response.status_code == 200
    result = response.json()
    assert result["decision"] == "BLOCK"
    assert {"SENSITIVE_RESOURCE", "EXTERNAL_EXFILTRATION"} <= set(
        result["threat_types"]
    )
    assert result["event_id"]

    event_response = client.get(f"/api/events/{result['event_id']}")
    assert event_response.status_code == 200
    event = event_response.json()
    assert event["source"] == "api"
    assert event["action_id"] == "customer-data-exfil"
    assert event["decision"] == "BLOCK"


def test_predefined_scenarios_return_auditable_results(client, monkeypatch, caplog):
    monkeypatch.setattr(
        "backend.routes.evaluate.execute_registered_demo_handler",
        lambda action: pytest.fail("Scenario evaluation must not execute actions."),
    )
    response = client.post("/api/evaluate/scenarios")

    assert response.status_code == 200
    payload = response.json()
    results = payload["results"]
    assert len(results) == 10
    expected_decisions = {
        "PS27-SAFE": "ALLOW",
        "PS27-INJECTION": "BLOCK",
        "PS27-SENSITIVE": "APPROVAL_REQUIRED",
        "PS27-EXFIL": "BLOCK",
        "PS27-PRIVILEGE": "BLOCK",
        "PS27-DANGEROUS-TOOL": "BLOCK",
        "PS27-UNAUTHORIZED-RESOURCE": "BLOCK",
        "PS27-CANARY-EXPOSURE": "APPROVAL_REQUIRED",
        "PS27-POLICY-BYPASS": "BLOCK",
        "PS27-MALFORMED-PROPOSAL": "REJECTED",
    }

    for result in results:
        expected = expected_decisions[result["scenario_id"]]
        assert result["expected_result"] == expected
        assert result["actual_result"] == expected
        assert result["passed"] is True
        assert result["explanation"]
        assert result["execution_status"] == "not_requested"
        if result["scenario_id"] == "PS27-MALFORMED-PROPOSAL":
            assert result["event_id"] is None
            assert result["audit_status"] == "not_created_invalid_provider_proposal"
            continue

        assert result["action_id"]
        assert result["source"]
        assert isinstance(result["risk_score"], int)
        assert isinstance(result["threat_types"], list)
        assert result["reasons"]
        assert result["event_id"]
        assert all("matched_text" not in detection for detection in result["detections"])

        event_response = client.get(f"/api/events/{result['event_id']}")
        assert event_response.status_code == 200
        event = event_response.json()
        assert event["action_id"] == result["action_id"]
        assert event["source"] == result["source"]
        assert event["decision"] == result["decision"]
        assert event["risk_score"] == result["risk_score"]
        assert event["threat_types"] == result["threat_types"]
        assert event["decision_reason"] == "; ".join(result["reasons"])
        assert event["access_decision"] == result["access_decision"]
        assert event["data_leakage_detected"] == result["data_leakage_detected"]
        if result["scenario_id"] == "PS27-PRIVILEGE":
            assert {"PRIVILEGE_ESCALATION", "DANGEROUS_ACTION"} <= set(
                result["threat_types"]
            )
        if result["scenario_id"] == "PS27-CANARY-EXPOSURE":
            assert result["data_leakage_analysis"] == {
                "canary_exposed_in_result": False,
                "canary_exposed_in_audit": False,
                "passed": True,
            }
            assert any(
                detection["category"] == "SENSITIVE_RESOURCE"
                and detection["severity"] in {"medium", "high"}
                and detection["evidence"]["field"] == "resource"
                for detection in result["detections"]
            )

    assert "TRACEGUARD-CANARY-R3-7F2A" not in caplog.text
    metrics = payload["metrics"]
    assert metrics["scenario_count"] == 10
    assert metrics["passed_count"] == 10
    assert metrics["failed_count"] == 0
    assert metrics["pass_rate_percent"] == 100.0
    assert metrics["no_execution_verified"] is True
