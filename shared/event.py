"""Shared schema for Unified Security Events across SAGE AI."""

import datetime
import uuid
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field


class SecurityEvent(BaseModel):
    """Unified security event capturing action telemetry, ML inspection, and decision."""
    event_id: str = Field(default_factory=lambda: f"EVT-{uuid.uuid4().hex[:10].upper()}")
    action_id: str = Field(..., description="Correlated Action ID")
    agent_id: str = Field(default="agent_01", description="Identifier of the executing agent")
    action_type: str = Field(..., description="Action requested by agent, e.g. read_file, execute_command")
    resource: str = Field(default="*", description="Target resource or destination")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Parameters passed with the action")
    timestamp: str = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat(),
        description="ISO 8601 timestamp of the event",
    )

    # ML Detection metrics (Member 2)
    is_malicious: bool = Field(default=False, description="Flag indicating malicious activity detected")
    threat_type: str = Field(default="none", description="Categorized threat type")
    ml_confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="ML inference confidence (0.0 to 1.0)")
    ml_reason: str = Field(default="No malicious indicators detected", description="ML model explanation")

    # Risk & Decision metrics (Member 1)
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0, description="Risk assessment score (0 to 100)")
    decision: str = Field(default="ALLOW", description="ALLOW, BLOCK, or APPROVAL_REQUIRED")
    decision_reason: str = Field(default="Action authorized", description="Policy or risk decision reason")


# Alias for backward compatibility if needed
AuditEvent = SecurityEvent
