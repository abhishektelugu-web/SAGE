"""Pydantic API Schemas for SAGE AI REST endpoints."""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from shared.event import SecurityEvent


class HealthResponse(BaseModel):
    """Health status response."""
    status: str = Field(default="ok")
    service: str = Field(default="SAGE AI Security Engine")
    version: str = Field(default="1.0.0")


class SecurityEventCreate(BaseModel):
    """Input payload to record a unified security event."""
    event_id: Optional[str] = Field(default=None, description="Optional custom event ID")
    action_id: str = Field(..., description="Action ID triggering the event")
    agent_id: str = Field(default="agent_01", description="Agent ID")
    action_type: str = Field(..., description="Action type or tool name")
    resource: str = Field(default="*", description="Target resource")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Action parameters")
    timestamp: Optional[str] = Field(default=None, description="ISO timestamp")

    is_malicious: bool = Field(default=False, description="Whether malicious indicators were found")
    threat_type: str = Field(default="none", description="Classification of threat")
    ml_confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Detection confidence")
    ml_reason: str = Field(default="", description="ML explanation")

    risk_score: float = Field(default=0.0, ge=0.0, le=100.0, description="Evaluated risk score")
    decision: str = Field(default="ALLOW", pattern=r"^(ALLOW|BLOCK|APPROVAL_REQUIRED)$", description="ALLOW, BLOCK, or APPROVAL_REQUIRED")
    decision_reason: str = Field(default="", description="Decision justification")


class EventListResponse(BaseModel):
    """Paginated list of security events."""
    total: int
    count: int
    events: List[SecurityEvent]


class StatsResponse(BaseModel):
    """Aggregated statistics for security dashboard."""
    total_events: int = Field(default=0)
    allowed: int = Field(default=0)
    blocked: int = Field(default=0)
    approval_required: int = Field(default=0)
    threats_detected: int = Field(default=0)
    threat_breakdown: Dict[str, int] = Field(default_factory=dict)
    decision_breakdown: Dict[str, int] = Field(default_factory=dict)
