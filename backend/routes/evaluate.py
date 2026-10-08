"""Run the real AI/ML + security pipeline and persist the resulting audit event."""

from datetime import datetime, timezone

from fastapi import APIRouter, status
from pydantic import BaseModel, Field

from ai_ml.inference import detect
from backend.integration.event_adapter import event_adapter
from security.gateway import SecurityGateway
from shared.agent_action import AgentAction

router = APIRouter(prefix="/api/evaluate", tags=["Runtime Security Evaluation"])


class EvaluateRequest(BaseModel):
    action_id: str = Field(..., min_length=1)
    agent_id: str = Field(..., min_length=1)
    action_type: str = Field(..., min_length=1)
    source: str = Field(default="user", min_length=1)
    instruction: str = Field(..., min_length=1)
    trusted_source: bool = True
    tool: str | None = None
    resource: str | None = None
    parameters: dict[str, object] = Field(default_factory=dict)


@router.post("", status_code=status.HTTP_200_OK)
def evaluate_action(payload: EvaluateRequest):
    action = AgentAction(
        action_id=payload.action_id,
        agent_id=payload.agent_id,
        action_type=payload.action_type,
        source=payload.source,
        instruction=payload.instruction,
        trusted_source=payload.trusted_source,
        timestamp=datetime.now(timezone.utc),
        tool=payload.tool,
        resource=payload.resource,
        parameters=payload.parameters,
    )
    ml_result = detect(action)
    decision = SecurityGateway().evaluate(action, ml_result=ml_result)
    event = event_adapter.ingest(action, ml_result, decision)
    return {
        "action_id": action.action_id,
        "decision": decision.decision,
        "risk_score": decision.risk_score,
        "threat_types": decision.threat_types,
        "reasons": decision.reasons,
        "ml": {
            "is_malicious": ml_result.is_malicious,
            "confidence": ml_result.confidence,
            "threat_type": ml_result.threat_type,
            "reason": ml_result.reason,
            "model_name": ml_result.model_name,
        },
        "event_id": event.event_id,
    }
