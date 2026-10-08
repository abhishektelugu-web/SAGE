"""Backend API representation of a stored security decision."""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class DecisionType(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"


class SecurityDecisionResponse(BaseModel):
    decision: DecisionType
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    threat_type: str = "none"
    reason: str
    action_id: Optional[str] = None
