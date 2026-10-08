"""Security Events REST API routes."""

from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, status
from shared.event import SecurityEvent
from backend.schemas.api_schemas import SecurityEventCreate
from backend.services.event_service import event_service

router = APIRouter(prefix="/api/events", tags=["Events"])


@router.post("", response_model=SecurityEvent, status_code=status.HTTP_201_CREATED)
def create_event(payload: SecurityEventCreate):
    """Store a unified security event emitted by Member 1 / Member 2."""
    try:
        created = event_service.record_event(payload)
        return created
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Failed to process and store security event: {str(exc)}",
        )


@router.get("", response_model=List[SecurityEvent])
def list_events(
    decision: Optional[str] = Query(None, description="Filter by decision: ALLOW, BLOCK, APPROVAL_REQUIRED"),
    threat_type: Optional[str] = Query(None, description="Filter by threat type, e.g. prompt_injection"),
    agent_id: Optional[str] = Query(None, description="Filter by agent ID"),
    limit: int = Query(100, ge=1, le=500, description="Max events to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
):
    """Retrieve stored security events with optional filtering."""
    return event_service.list_events(
        decision=decision,
        threat_type=threat_type,
        agent_id=agent_id,
        limit=limit,
        offset=offset,
    )


@router.get("/{event_id}", response_model=SecurityEvent)
def get_event(event_id: str):
    """Retrieve full audit record for a single security event."""
    event = event_service.get_event(event_id)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security event with ID '{event_id}' not found.",
        )
    return event
