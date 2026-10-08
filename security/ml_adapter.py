"""Translate ML detector output into advisory security findings."""

from __future__ import annotations

from shared.ml_result import MLDetectionResult
from security.rules import RuleFinding


def _severity_for_confidence(confidence: float) -> str:
    if confidence >= 0.85:
        return "high"
    if confidence >= 0.60:
        return "medium"
    return "low"


def ml_result_to_finding(result: MLDetectionResult | None) -> RuleFinding | None:
    """Convert a malicious ML result into one advisory risk finding."""
    if result is None or not result.is_malicious:
        return None
    if result.threat_type is None:
        # Generic suspicious behavior contributes risk without inventing a threat category.
        category = "DANGEROUS_ACTION"
        reason = "ML detector flagged suspicious behavior without a specific threat category."
    else:
        category = result.threat_type
        reason = (
            f"ML detector {result.model_name!r} flagged the action with "
            f"{result.confidence:.0%} confidence."
        )
    text = result.reason or "ML detector reported suspicious activity."
    return RuleFinding(
        rule_id=f"ML_{result.model_name.upper()}_{category}",
        category=category,
        matched=True,
        matched_text=text,
        source_field="ml_detector",
        severity=_severity_for_confidence(result.confidence),
        reason=f"{reason} {text}",
    )
