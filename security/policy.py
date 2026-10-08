"""Deterministic policy outcomes derived from risk assessments."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from security.risk import RiskAssessment
from shared.threats import ThreatCategory

PolicyDecision = Literal["ALLOW", "APPROVAL_REQUIRED", "BLOCK"]
_ALLOW_MAX_SCORE = 30
_APPROVAL_MAX_SCORE = 70
_HARD_BLOCK_CATEGORIES: tuple[tuple[ThreatCategory, ThreatCategory, str], ...] = (
    (
        "SENSITIVE_RESOURCE",
        "EXTERNAL_EXFILTRATION",
        "Policy override: sensitive resource access combined with external data transmission.",
    ),
    (
        "PRIVILEGE_ESCALATION",
        "DANGEROUS_ACTION",
        "Policy override: privilege escalation combined with a dangerous action.",
    ),
)
_CATEGORY_REASONS: dict[ThreatCategory, str] = {
    "PROMPT_INJECTION": "Prompt injection indicator detected",
    "SENSITIVE_RESOURCE": "Sensitive resource access detected",
    "EXTERNAL_EXFILTRATION": "External data transmission detected",
    "PRIVILEGE_ESCALATION": "Privilege escalation indicator detected",
    "DANGEROUS_ACTION": "Dangerous action indicator detected",
}


@dataclass(frozen=True, slots=True)
class PolicyOutcome:
    decision: PolicyDecision
    risk_score: int
    reasons: tuple[str, ...]


def evaluate_policy(risk_assessment: RiskAssessment) -> PolicyOutcome:
    score = risk_assessment.risk_score
    if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 100:
        raise ValueError("risk_score must be an integer from 0 to 100")

    categories = {
        finding.category for finding in risk_assessment.findings if finding.matched
    }
    reasons = [
        _CATEGORY_REASONS[category]
        for category in _CATEGORY_REASONS
        if category in categories
    ]
    reasons.extend(risk_assessment.reasons)

    for first_category, second_category, override_reason in _HARD_BLOCK_CATEGORIES:
        if first_category in categories and second_category in categories:
            reasons.append(override_reason)
            return PolicyOutcome(
                decision="BLOCK", risk_score=score, reasons=tuple(reasons)
            )

    if score <= _ALLOW_MAX_SCORE:
        decision: PolicyDecision = "ALLOW"
        threshold_reason = (
            f"Policy threshold: risk score {score} is within the ALLOW range "
            f"(0-{_ALLOW_MAX_SCORE})."
        )
    elif score <= _APPROVAL_MAX_SCORE:
        decision = "APPROVAL_REQUIRED"
        threshold_reason = (
            f"Policy threshold: risk score {score} is within the "
            f"APPROVAL_REQUIRED range {_ALLOW_MAX_SCORE + 1}-{_APPROVAL_MAX_SCORE}; "
            "a higher-level component must obtain approval before execution."
        )
    else:
        decision = "BLOCK"
        threshold_reason = (
            f"Policy threshold: risk score {score} is within the BLOCK range "
            f"{_APPROVAL_MAX_SCORE + 1}-100."
        )
    reasons.append(threshold_reason)
    return PolicyOutcome(decision=decision, risk_score=score, reasons=tuple(reasons))
