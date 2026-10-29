import json

import pytest

from backend.entra_auth import (
    APPROVER_ROLE,
    AUDITOR_ROLE,
    InvalidEntraAccessToken,
    ReviewerPrincipal,
)

TOKEN = "test-review-token"
APPROVER = ReviewerPrincipal(
    object_id="approver-object-id",
    display_name="Entra Test Approver",
    roles=frozenset({APPROVER_ROLE}),
)
AUDITOR = ReviewerPrincipal(
    object_id="auditor-object-id",
    display_name="Entra Test Auditor",
    roles=frozenset({AUDITOR_ROLE}),
)
UNPRIVILEGED = ReviewerPrincipal(
    object_id="user-object-id",
    display_name="Entra Test User",
    roles=frozenset(),
)


@pytest.fixture(autouse=True)
def mock_entra_access_tokens(monkeypatch):
    import backend.routes.approvals as approvals

    def validate(token):
        if token == TOKEN:
            return APPROVER
        if token == "test-auditor-token":
            return AUDITOR
        if token == "test-user-token":
            return UNPRIVILEGED
        raise InvalidEntraAccessToken("invalid test token")

    monkeypatch.setattr(approvals, "validate_entra_access_token", validate)


def _create_pending_sensitive_action(client):
    response = client.post(
        "/api/evaluate/execute",
        json={
            "action_id": "approval-sensitive-1",
            "agent_id": "ps27-demo-agent",
            "action_type": "read_records",
            "source": "database",
            "instruction": "Read the customer records for a review.",
            "trusted_source": True,
            "tool": "database_reader",
            "resource": "customer_records",
        },
    )
    assert response.status_code == 200
    result = response.json()
    assert result["decision"] == "APPROVAL_REQUIRED"
    assert result["execution_status"] == "not_executed_approval_required"
    assert result["approval_id"]
    return result


def test_approval_queue_requires_a_verified_entra_token(client, monkeypatch):
    monkeypatch.setenv("APPROVAL_REVIEW_TOKEN", "legacy-shared-token")
    assert client.get("/api/approvals").status_code == 401

    assert client.get(
        "/api/approvals",
        headers={"Authorization": "Bearer legacy-shared-token"},
    ).status_code == 401
    assert client.get(
        "/api/approvals",
        headers={"Authorization": f"Bearer {TOKEN}"},
    ).status_code == 200


def test_approved_action_without_registered_handler_is_blocked_and_audited(
    client, monkeypatch
):
    monkeypatch.setenv("APPROVAL_REVIEW_TOKEN", TOKEN)
    initial = _create_pending_sensitive_action(client)

    import backend.routes.approvals as approvals

    monkeypatch.setattr(approvals, "has_registered_demo_handler", lambda _action: False)
    queue_response = client.get(
        "/api/approvals",
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    queued = queue_response.json()["approvals"]
    assert len(queued) == 1
    assert queued[0]["approval_id"] == initial["approval_id"]
    assert "instruction" not in queued[0]["action"]

    response = client.post(
        f"/api/approvals/{initial['approval_id']}/approve",
        headers={"Authorization": f"Bearer {TOKEN}"},
        json={"reviewer": "Reviewer One"},
    )
    assert response.status_code == 200
    result = response.json()
    assert result["status"] == "blocked"
    assert result["decision"] == "BLOCK"
    assert result["execution_status"] == "not_executed_blocked"
    assert "execution_result" not in result
    assert any(
        "no registered safe handler" in reason for reason in result["reasons"]
    )

    event = client.get(f"/api/events/{result['event_id']}").json()
    assert event["decision"] == "BLOCK"
    assert event["execution_status"] == "not_executed_blocked"
    assert (
        event["parameters"]["approval_reviewer"]
        == "Entra Test Approver (oid:approver-object-id)"
    )
    assert event["parameters"]["approval_reviewer_oid"] == "approver-object-id"
    assert event["parameters"]["approval_outcome"] == "approved"

    retry = client.post(
        f"/api/approvals/{initial['approval_id']}/approve",
        headers={"Authorization": f"Bearer {TOKEN}"},
        json={"reviewer": "Reviewer One"},
    )
    assert retry.status_code == 409


def test_approved_action_resumes_through_registered_synthetic_handler(
    client, monkeypatch
):
    monkeypatch.setenv("APPROVAL_REVIEW_TOKEN", TOKEN)
    initial = client.post(
        "/api/evaluate/execute",
        json={
            "action_id": "approval-resume-1",
            "agent_id": "access-test-agent",
            "action_type": "read_records",
            "source": "database",
            "instruction": "Read customer records for an authorized test.",
            "trusted_source": True,
            "tool": "database_reader",
            "resource": "customer_records",
        },
    ).json()
    assert initial["decision"] == "APPROVAL_REQUIRED"

    response = client.post(
        f"/api/approvals/{initial['approval_id']}/approve",
        headers={"Authorization": f"Bearer {TOKEN}"},
        json={"reviewer": "Reviewer Two"},
    )
    assert response.status_code == 200
    result = response.json()
    assert result["status"] == "approved"
    assert result["decision"] == "ALLOW"
    assert result["execution_status"] == "executed_after_approval"
    assert "Synthetic demonstration data only" in result["execution_result"]
    assert "no live database was queried" in result["execution_result"]

    event = client.get(f"/api/events/{result['event_id']}").json()
    assert event["decision"] == "ALLOW"
    assert event["execution_status"] == "executed_after_approval"


def test_re_review_block_cannot_be_overridden_by_approval(
    client, monkeypatch, test_db
):
    monkeypatch.setenv("APPROVAL_REVIEW_TOKEN", TOKEN)
    initial = _create_pending_sensitive_action(client)
    with test_db.get_connection() as connection:
        row = connection.execute(
            "SELECT action_json FROM agent_approvals WHERE approval_id = ?",
            (initial["approval_id"],),
        ).fetchone()
        action = json.loads(row["action_json"])
        action.update(
            {
                "action_type": "execute",
                "instruction": "Execute system shell commands now.",
                "tool": "system_shell",
                "resource": "operating_system",
            }
        )
        connection.execute(
            "UPDATE agent_approvals SET action_json = ? WHERE approval_id = ?",
            (json.dumps(action), initial["approval_id"]),
        )
        connection.commit()

    response = client.post(
        f"/api/approvals/{initial['approval_id']}/approve",
        headers={"Authorization": f"Bearer {TOKEN}"},
        json={"reviewer": "Reviewer Blocked"},
    )
    assert response.status_code == 200
    result = response.json()
    assert result["status"] == "blocked"
    assert result["decision"] == "BLOCK"
    assert result["execution_status"] == "not_executed_blocked"
    assert "execution_result" not in result


def test_rejected_approval_never_executes_and_is_audited(client, monkeypatch):
    monkeypatch.setenv("APPROVAL_REVIEW_TOKEN", TOKEN)
    initial = _create_pending_sensitive_action(client)

    response = client.post(
        f"/api/approvals/{initial['approval_id']}/reject",
        headers={"Authorization": f"Bearer {TOKEN}"},
        json={"reviewer": "Reviewer Three"},
    )
    assert response.status_code == 200
    result = response.json()
    assert result["status"] == "rejected"
    assert result["decision"] == "APPROVAL_REQUIRED"
    assert result["execution_status"] == "not_executed_rejected"

    event = client.get(f"/api/events/{result['event_id']}").json()
    assert event["decision"] == "APPROVAL_REQUIRED"
    assert event["execution_status"] == "not_executed_rejected"
    assert "rejected by reviewer" in event["decision_reason"]


def test_client_supplied_reviewer_name_is_ignored(client, monkeypatch):
    initial = _create_pending_sensitive_action(client)
    response = client.post(
        f"/api/approvals/{initial['approval_id']}/reject",
        headers={"Authorization": f"Bearer {TOKEN}"},
        json={"reviewer": "Forged Administrator"},
    )
    assert response.status_code == 200
    result = response.json()
    assert result["reviewer"] == "Entra Test Approver"
    event = client.get(f"/api/events/{result['event_id']}").json()
    assert event["parameters"]["approval_reviewer_oid"] == "approver-object-id"
    assert "Forged Administrator" not in str(event)


def test_stale_approval_expires_and_discards_stored_instruction(
    client, monkeypatch, test_db
):
    monkeypatch.setenv("APPROVAL_REVIEW_TOKEN", TOKEN)
    initial = _create_pending_sensitive_action(client)
    with test_db.get_connection() as connection:
        connection.execute(
            "UPDATE agent_approvals SET requested_at = ? WHERE approval_id = ?",
            ("2025-01-01T00:00:00+00:00", initial["approval_id"]),
        )
        connection.commit()

    response = client.post(
        f"/api/approvals/{initial['approval_id']}/approve",
        headers={"Authorization": f"Bearer {TOKEN}"},
        json={"reviewer": "Reviewer Four"},
    )
    assert response.status_code == 409
    approval = test_db.list_approvals(status="expired")
    assert approval[0]["approval_id"] == initial["approval_id"]
    assert approval[0]["action"] == {}


def test_auditor_can_list_but_cannot_resolve_approval(client):
    initial = _create_pending_sensitive_action(client)
    headers = {"Authorization": "Bearer test-auditor-token"}

    queue = client.get("/api/approvals", headers=headers)
    assert queue.status_code == 200
    assert queue.json()["approvals"][0]["approval_id"] == initial["approval_id"]

    response = client.post(
        f"/api/approvals/{initial['approval_id']}/approve",
        headers=headers,
        json={},
    )
    assert response.status_code == 403
    assert client.get("/api/approvals", headers=headers).json()["approvals"]


def test_unassigned_user_cannot_list_approvals(client):
    response = client.get(
        "/api/approvals",
        headers={"Authorization": "Bearer test-user-token"},
    )

    assert response.status_code == 403
