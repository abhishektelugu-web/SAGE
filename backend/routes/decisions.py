"""Dashboard statistics and decisions REST API routes."""

from fastapi import APIRouter, HTTPException, status
from backend.schemas.api_schemas import StatsResponse
from backend.schemas.decision_response import SecurityDecisionResponse
from backend.services.dashboard_service import dashboard_service
from backend.services.event_service import event_service

router = APIRouter(tags=["Decisions & Dashboard Stats"])


@router.get("/api/dashboard/stats", response_model=StatsResponse)
@router.get("/api/stats", response_model=StatsResponse)
def get_dashboard_stats():
    """Retrieve aggregate security statistics from the database."""
    stats = dashboard_service.get_dashboard_stats()
    return StatsResponse(
        total_events=stats.get("total_events", 0),
        allowed=stats.get("allowed", 0),
        blocked=stats.get("blocked", 0),
        approval_required=stats.get("approval_required", 0),
        threats_detected=stats.get("threats_detected", 0),
        threat_breakdown=stats.get("threat_breakdown", {}),
        decision_breakdown=stats.get("decision_breakdown", {}),
    )


@router.get("/api/decisions/{action_id}", response_model=SecurityDecisionResponse)
def get_decision_by_action_id(action_id: str):
    """Retrieve the SecurityDecision evaluated for a given Action ID."""
    event = event_service.get_event_by_action(action_id)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No security decision found for action ID '{action_id}'.",
        )
    return SecurityDecisionResponse(
        action_id=event.action_id,
        decision=event.decision,
        risk_score=event.risk_score,
        threat_type=event.threat_type,
        reason=event.decision_reason,
    )
