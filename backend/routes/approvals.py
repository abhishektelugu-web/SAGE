"""Human review and one-time resumption of approval-required demo actions."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from dataclasses import replace
from typing import Literal

from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, Field

from ai_ml.inference import detect
from backend.entra_auth import (
    APPROVER_ROLE,
    AUDITOR_ROLE,
    EntraAuthConfigurationError,
    EntraIdentityProviderUnavailable,
    InvalidEntraAccessToken,
    ReviewerPrincipal,
    validate_entra_access_token,
)
from backend.integration.event_adapter import event_adapter
from backend.services.event_service import event_service
from security.decision import SecurityDecision
from security.execution import (
    execute_registered_demo_handler,
    has_registered_demo_handler,
)
from security.gateway import SecurityGateway
from shared.agent_action import AgentAction

router = APIRouter(prefix="/api/approvals", tags=["Human Approval"])
_APPROVAL_TTL = timedelta(minutes=15)


class ApprovalResolutionRequest(BaseModel):
    reviewer: str | None = Field(
        default=None,
        description="Deprecated and ignored; reviewer identity comes from Entra claims.",
    )


def _require_reviewer(
    authorization: str | None,
    *,
    allowed_roles: frozenset[str],
) -> ReviewerPrincipal:
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A Microsoft Entra bearer access token is required.",
        )
    scheme, separator, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not separator or not token.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A Microsoft Entra bearer access token is required.",
        )
    try:
        principal = validate_entra_access_token(token.strip())
    except EntraAuthConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    except EntraIdentityProviderUnavailable as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    except InvalidEntraAccessToken as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        ) from exc

    if not principal.roles.intersection(allowed_roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The Entra access token lacks a required approval role.",
        )
    return principal


def _claim_pending_approval(approval_id: str) -> dict[str, object]:
    now = datetime.now(timezone.utc)
    claimed = event_service.db.claim_approval(
        approval_id,
        expired_before=(now - _APPROVAL_TTL).isoformat(),
    )
    if claimed is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Approval request is missing, already resolved, or being reviewed.",
        )
    if claimed["status"] == "expired":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Approval request expired; submit the action again for fresh review.",
        )
    return claimed


def _restore_action(record: dict[str, object]) -> AgentAction:
    return AgentAction(
        action_id=str(record["action_id"]),
        agent_id=str(record["agent_id"]),
        action_type=str(record["action_type"]),
        source=str(record["source"]),
        instruction=str(record["instruction"]),
        trusted_source=bool(record["trusted_source"]),
        timestamp=datetime.fromisoformat(str(record["timestamp"])),
        tool=str(record["tool"]) if record.get("tool") is not None else None,
        resource=(
            str(record["resource"]) if record.get("resource") is not None else None
        ),
        parameters=record.get("parameters", {}),
    )


def _resolution_event(
    approval: dict[str, object],
    reviewer: ReviewerPrincipal,
    approved: bool,
) -> dict[str, object]:
    action_record = approval["action"]
    if not isinstance(action_record, dict):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Stored approval action is invalid.",
        )

    action = _restore_action(action_record)
    ml_result = detect(action)
    decision = SecurityGateway().evaluate(action, ml_result=ml_result)
    execution_result: str | None = None

    if not approved:
        execution_status = (
            "not_executed_blocked"
            if decision.decision == "BLOCK"
            else "not_executed_rejected"
        )
        final_state: Literal["approved", "rejected", "blocked"] = (
            "blocked" if decision.decision == "BLOCK" else "rejected"
        )
        if decision.decision != "BLOCK":
            decision = replace(
                decision,
                reasons=(
                    *decision.reasons,
                    f"Approval was rejected by reviewer {reviewer.display_name!r}.",
                ),
            )
    elif decision.decision == "BLOCK":
        execution_status = "not_executed_blocked"
        final_state = "blocked"
    elif not has_registered_demo_handler(action):
        decision = replace(
            decision,
            decision="BLOCK",
            access_decision="BLOCK",
            reasons=(
                *decision.reasons,
                "Approval was recorded, but execution was blocked because no registered safe handler matches this action.",
            ),
        )
        execution_status = "not_executed_blocked"
        final_state = "blocked"
    else:
        if decision.decision == "APPROVAL_REQUIRED":
            decision = replace(
                decision,
                decision="ALLOW",
                reasons=(
                    *decision.reasons,
                    f"Reviewer {reviewer.display_name!r} explicitly approved this pending action.",
                ),
            )
        execution_result = execute_registered_demo_handler(action)
        execution_status = "executed_after_approval"
        final_state = "approved"

    audit_action = replace(
        action,
        parameters={
            **dict(action.parameters),
            "approval_id": approval["approval_id"],
            "approval_reviewer": reviewer.audit_identity,
            "approval_reviewer_oid": reviewer.object_id,
            "approval_outcome": "approved" if approved else "rejected",
        },
    )
    event = event_adapter.ingest(
        audit_action,
        ml_result,
        decision,
        execution_status=execution_status,
    )
    resolved = event_service.db.resolve_approval(
        approval_id=str(approval["approval_id"]),
        status=final_state,
        reviewer=reviewer.audit_identity,
        resolution_event_id=event.event_id,
    )
    if not resolved:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Approval request could not be finalized.",
        )
    response: dict[str, object] = {
        "approval_id": approval["approval_id"],
        "status": final_state,
        "reviewer": reviewer.display_name,
        "reviewer_oid": reviewer.object_id,
        "event_id": event.event_id,
        "decision": decision.decision,
        "execution_status": execution_status,
        "reasons": list(decision.reasons),
    }
    if execution_result is not None:
        response["execution_result"] = execution_result
    return response


@router.get("")
def list_pending_approvals(
    authorization: str | None = Header(default=None),
) -> dict[str, object]:
    """List pending review items without returning their source instructions."""
    reviewer = _require_reviewer(
        authorization,
        allowed_roles=frozenset({APPROVER_ROLE, AUDITOR_ROLE}),
    )
    approvals = event_service.db.list_approvals(status="pending")
    public_approvals = []
    for approval in approvals:
        action = approval["action"]
        public_approvals.append(
            {
                "approval_id": approval["approval_id"],
                "event_id": approval["event_id"],
                "requested_at": approval["requested_at"],
                "status": approval["status"],
                "action": {
                    key: action.get(key)
                    for key in (
                        "action_id",
                        "agent_id",
                        "action_type",
                        "source",
                        "trusted_source",
                        "tool",
                        "resource",
                    )
                },
            }
        )
    return {
        "approvals": public_approvals,
        "principal": {
            "display_name": reviewer.display_name,
            "roles": sorted(reviewer.roles),
        },
    }


@router.post("/{approval_id}/approve")
def approve_pending_action(
    approval_id: str,
    payload: ApprovalResolutionRequest,
    authorization: str | None = Header(default=None),
) -> dict[str, object]:
    """Re-evaluate an action and resume it only through the registered safe handler."""
    reviewer = _require_reviewer(
        authorization,
        allowed_roles=frozenset({APPROVER_ROLE}),
    )
    approval = _claim_pending_approval(approval_id)
    return _resolution_event(approval, reviewer, approved=True)


@router.post("/{approval_id}/reject")
def reject_pending_action(
    approval_id: str,
    payload: ApprovalResolutionRequest,
    authorization: str | None = Header(default=None),
) -> dict[str, object]:
    """Reject a pending action and persist the non-execution outcome."""
    reviewer = _require_reviewer(
        authorization,
        allowed_roles=frozenset({APPROVER_ROLE}),
    )
    approval = _claim_pending_approval(approval_id)
    return _resolution_event(approval, reviewer, approved=False)
