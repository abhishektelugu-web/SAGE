"""Immutable final security result assembled from evaluated inputs."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from security.policy import PolicyOutcome
from security.risk import RiskAssessment
from shared.agent_action import AgentAction
from shared.threats import ThreatCategory

DecisionValue = Literal["ALLOW", "APPROVAL_REQUIRED", "BLOCK"]


@dataclass(frozen=True, slots=True)
class SecurityDecision:
    action_id: str
    agent_id: str
    decision: DecisionValue
    risk_score: int
    threat_types: tuple[ThreatCategory, ...]
    reasons: tuple[str, ...]
    timestamp: datetime


def build_security_decision(
    action: AgentAction,
    risk_assessment: RiskAssessment,
    policy_outcome: PolicyOutcome,
) -> SecurityDecision:
    if policy_outcome.risk_score != risk_assessment.risk_score:
        raise ValueError("policy outcome and risk assessment scores must match")
    for field_name in ("action_id", "agent_id"):
        value = getattr(action, field_name)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field_name} must be a non-empty string")

    threat_types: list[ThreatCategory] = []
    seen_categories: set[ThreatCategory] = set()
    for finding in risk_assessment.findings:
        if finding.matched and finding.category not in seen_categories:
            seen_categories.add(finding.category)
            threat_types.append(finding.category)

    return SecurityDecision(
        action_id=action.action_id,
        agent_id=action.agent_id,
        decision=policy_outcome.decision,
        risk_score=policy_outcome.risk_score,
        threat_types=tuple(threat_types),
        reasons=tuple(policy_outcome.reasons),
        timestamp=action.timestamp,
    )
