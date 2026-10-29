"""Adapt canonical security/ML outputs into backend SecurityEvent records."""

from __future__ import annotations

import datetime
import uuid
from typing import Any

from backend.schemas.api_schemas import SecurityEventCreate
from backend.services.event_service import EventService, event_service as default_event_service
from shared.agent_action import AgentAction
from shared.event import SecurityEvent
from shared.ml_result import MLDetectionResult
from security.decision import SecurityDecision


def create_security_event(
    agent_action: AgentAction | dict[str, Any],
    ml_result: MLDetectionResult | dict[str, Any] | None = None,
    security_decision: SecurityDecision | dict[str, Any] | None = None,
    event_id: str | None = None,
    timestamp: str | None = None,
    execution_status: str = "not_requested",
) -> SecurityEvent:
    if isinstance(agent_action, dict):
        action_id = agent_action.get("action_id") or f"ACT-{uuid.uuid4().hex[:8].upper()}"
        agent_id = agent_action.get("agent_id", "agent_01")
        action_type = agent_action.get("action_type", "unknown_action")
        tool = agent_action.get("tool")
        source = agent_action.get("source", "unknown")
        trusted_source = bool(agent_action.get("trusted_source", True))
        resource = agent_action.get("resource", "*")
        parameters = agent_action.get("parameters", {})
        action_time = agent_action.get("timestamp")
    else:
        action_id = agent_action.action_id
        agent_id = agent_action.agent_id
        action_type = agent_action.action_type
        tool = agent_action.tool
        source = agent_action.source
        trusted_source = agent_action.trusted_source
        resource = agent_action.resource or "*"
        parameters = dict(agent_action.parameters)
        action_time = agent_action.timestamp

    if ml_result is None:
        is_malicious = False
        threat_type = "none"
        ml_confidence = 0.0
        ml_reason = "No ML detection performed"
    elif isinstance(ml_result, dict):
        is_malicious = bool(ml_result.get("is_malicious", False))
        threat_type = str(ml_result.get("threat_type") or "none").lower()
        ml_confidence = float(ml_result.get("confidence", 0.0))
        ml_reason = str(ml_result.get("reason") or ml_result.get("ml_reason") or "")
    else:
        is_malicious = ml_result.is_malicious
        threat_type = (ml_result.threat_type or "none").lower()
        ml_confidence = ml_result.confidence
        ml_reason = "; ".join(ml_result.reasons) if ml_result.reasons else ml_result.reason

    if security_decision is None:
        decision = "ALLOW" if not is_malicious else "APPROVAL_REQUIRED"
        risk_score = 0.0
        decision_reason = "No SecurityDecision supplied"
        access_decision = "ALLOW"
        data_leakage_detected = False
    elif isinstance(security_decision, dict):
        decision = str(security_decision.get("decision", "ALLOW")).upper()
        risk_score = float(security_decision.get("risk_score", 0.0))
        decision_reason = str(security_decision.get("decision_reason") or security_decision.get("reason") or "")
        access_decision = str(security_decision.get("access_decision", "ALLOW"))
        data_leakage_detected = bool(
            security_decision.get("data_leakage_detected", False)
        )
        threat_types = [
            str(category) for category in security_decision.get("threat_types", [])
        ]
        if threat_type == "none":
            if threat_types:
                threat_type = threat_types[0].lower()
    else:
        decision = str(security_decision.decision).upper()
        risk_score = float(security_decision.risk_score)
        decision_reason = "; ".join(security_decision.reasons)
        access_decision = security_decision.access_decision
        data_leakage_detected = security_decision.data_leakage_detected
        threat_types = [str(category) for category in security_decision.threat_types]
        if threat_type == "none" and threat_types:
            threat_type = threat_types[0].lower()

    chosen_event_id = event_id or f"EVT-{uuid.uuid4().hex[:10].upper()}"
    chosen_timestamp: str
    if timestamp:
        chosen_timestamp = timestamp
    elif isinstance(action_time, datetime.datetime):
        chosen_timestamp = action_time.isoformat()
    elif action_time:
        chosen_timestamp = str(action_time)
    else:
        chosen_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    return SecurityEvent(
        event_id=chosen_event_id,
        action_id=action_id,
        agent_id=agent_id,
        action_type=action_type,
        tool=tool,
        source=source,
        trusted_source=trusted_source,
        resource=resource,
        parameters=parameters,
        timestamp=chosen_timestamp,
        is_malicious=is_malicious,
        threat_type=threat_type,
        ml_confidence=ml_confidence,
        ml_reason=ml_reason,
        risk_score=risk_score,
        decision=decision,
        decision_reason=decision_reason,
        threat_types=threat_types if security_decision is not None else [],
        execution_status=execution_status,
        access_decision=access_decision,
        data_leakage_detected=data_leakage_detected,
    )


class EventAdapter:
    def __init__(self, event_srv: EventService | None = None):
        self.event_service = event_srv or default_event_service

    def to_security_event(
        self,
        agent_action,
        ml_result=None,
        security_decision=None,
        event_id=None,
        execution_status="not_requested",
    ):
        return create_security_event(
            agent_action,
            ml_result,
            security_decision,
            event_id,
            execution_status=execution_status,
        )

    def ingest(
        self,
        agent_action,
        ml_result=None,
        security_decision=None,
        execution_status="not_requested",
    ):
        event = self.to_security_event(
            agent_action,
            ml_result,
            security_decision,
            execution_status=execution_status,
        )
        payload = SecurityEventCreate(
            event_id=event.event_id,
            action_id=event.action_id,
            agent_id=event.agent_id,
            action_type=event.action_type,
            tool=event.tool,
            source=event.source,
            trusted_source=event.trusted_source,
            resource=event.resource,
            parameters=event.parameters,
            timestamp=event.timestamp,
            is_malicious=event.is_malicious,
            threat_type=event.threat_type,
            ml_confidence=event.ml_confidence,
            ml_reason=event.ml_reason,
            risk_score=event.risk_score,
            decision=event.decision,
            decision_reason=event.decision_reason,
            threat_types=event.threat_types,
            execution_status=event.execution_status,
            access_decision=event.access_decision,
            data_leakage_detected=event.data_leakage_detected,
        )
        return self.event_service.record_event(payload)


event_adapter = EventAdapter()
