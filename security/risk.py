"""Deterministic risk scoring for findings produced by security rules."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from security.rules import RuleFinding, Severity
from shared.threats import ThreatCategory

_SEVERITY_CONTRIBUTIONS: dict[Severity, int] = {
    "low": 10,
    "medium": 25,
    "high": 40,
}
_SEVERITY_ORDER: tuple[Severity, ...] = ("low", "medium", "high")
_CATEGORY_ORDER: tuple[ThreatCategory, ...] = (
    "PROMPT_INJECTION",
    "SENSITIVE_RESOURCE",
    "EXTERNAL_EXFILTRATION",
    "PRIVILEGE_ESCALATION",
    "DANGEROUS_ACTION",
)
_MAX_RISK_SCORE = 100


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    risk_score: int
    finding_count: int
    severity_counts: tuple[tuple[Severity, int], ...]
    category_counts: tuple[tuple[ThreatCategory, int], ...]
    reasons: tuple[str, ...]
    findings: tuple[RuleFinding, ...]


def calculate_risk(findings: Iterable[RuleFinding]) -> RiskAssessment:
    distinct_findings: dict[str, RuleFinding] = {}
    for finding in findings:
        if not finding.matched or finding.rule_id in distinct_findings:
            continue
        if finding.severity not in _SEVERITY_CONTRIBUTIONS:
            raise ValueError(f"Unsupported finding severity: {finding.severity!r}")
        distinct_findings[finding.rule_id] = finding

    scored_findings = tuple(distinct_findings.values())
    severity_totals = {severity: 0 for severity in _SEVERITY_ORDER}
    category_totals = {category: 0 for category in _CATEGORY_ORDER}
    raw_score = 0
    reasons: list[str] = []

    for finding in scored_findings:
        contribution = _SEVERITY_CONTRIBUTIONS[finding.severity]
        raw_score += contribution
        severity_totals[finding.severity] += 1
        category_totals[finding.category] += 1
        reasons.append(
            f"{finding.severity.capitalize()}-severity "
            f"{finding.category.replace('_', ' ').lower()} indicator "
            f"({finding.rule_id}) matched {finding.matched_text!r} in "
            f"{finding.source_field}; contributes {contribution} points. "
            f"{finding.reason}"
        )

    risk_score = min(raw_score, _MAX_RISK_SCORE)
    if raw_score > _MAX_RISK_SCORE:
        reasons.append(
            f"The uncapped total of {raw_score} points was capped at {_MAX_RISK_SCORE}."
        )

    return RiskAssessment(
        risk_score=risk_score,
        finding_count=len(scored_findings),
        severity_counts=tuple(
            (severity, severity_totals[severity])
            for severity in _SEVERITY_ORDER
            if severity_totals[severity] > 0
        ),
        category_counts=tuple(
            (category, category_totals[category])
            for category in _CATEGORY_ORDER
            if category_totals[category] > 0
        ),
        reasons=tuple(reasons),
        findings=scored_findings,
    )
