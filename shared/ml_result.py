"""Immutable ML detector output contract with legacy SAGE compatibility."""

from __future__ import annotations

from dataclasses import dataclass
from numbers import Real
from typing import get_args

from shared.threats import ThreatCategory


class ThreatType:
    """Legacy SAGE constants retained as a compatibility surface."""

    SAFE = "SAFE"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    SENSITIVE_RESOURCE = "SENSITIVE_RESOURCE"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    SUSPICIOUS_BEHAVIOR = "SUSPICIOUS_BEHAVIOR"
    ALL: tuple[str, ...] = (
        SAFE,
        PROMPT_INJECTION,
        SENSITIVE_RESOURCE,
        DATA_EXFILTRATION,
        SUSPICIOUS_BEHAVIOR,
    )

_VALID_CATEGORIES = frozenset(get_args(ThreatCategory))
_LEGACY_CATEGORY_MAP: dict[str, ThreatCategory | None] = {
    "SAFE": None,
    "NONE": None,
    "PROMPT_INJECTION": "PROMPT_INJECTION",
    "SENSITIVE_RESOURCE": "SENSITIVE_RESOURCE",
    "DATA_EXFILTRATION": "EXTERNAL_EXFILTRATION",
    "EXTERNAL_EXFILTRATION": "EXTERNAL_EXFILTRATION",
    "PRIVILEGE_ESCALATION": "PRIVILEGE_ESCALATION",
    "DANGEROUS_ACTION": "DANGEROUS_ACTION",
    # Generic suspicious behavior is carried by reasons/confidence only.
    "SUSPICIOUS_BEHAVIOR": None,
}


@dataclass(frozen=True, slots=True, init=False)
class MLDetectionResult:
    """Explainable detector output for the security engine."""

    is_malicious: bool
    confidence: float
    threat_type: ThreatCategory | None
    reasons: tuple[str, ...]
    model_name: str

    def __init__(
        self,
        *,
        is_malicious: bool,
        confidence: float,
        threat_type: str | ThreatCategory | None,
        reasons: tuple[str, ...] = (),
        model_name: str = "unknown",
        reason: str | None = None,
    ) -> None:
        if not isinstance(is_malicious, bool):
            raise TypeError("is_malicious must be a bool")
        if isinstance(confidence, bool) or not isinstance(confidence, Real):
            raise TypeError("confidence must be a numeric value")
        if not 0.0 <= float(confidence) <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")

        normalized: ThreatCategory | None
        if threat_type is None:
            normalized = None
        else:
            key = str(threat_type).strip().upper()
            if key not in _LEGACY_CATEGORY_MAP:
                raise ValueError("threat_type must be None or a valid ThreatCategory")
            normalized = _LEGACY_CATEGORY_MAP[key]

        if not isinstance(reasons, tuple) or not all(
            isinstance(item, str) for item in reasons
        ):
            raise TypeError("reasons must be a tuple of strings")

        if reason is not None:
            if not isinstance(reason, str) or not reason.strip():
                raise ValueError("reason must be a non-empty string")
            if not reasons:
                reasons = (reason,)

        if not isinstance(model_name, str) or not model_name.strip():
            raise ValueError("model_name must be a non-empty string")

        object.__setattr__(self, "is_malicious", is_malicious)
        object.__setattr__(self, "confidence", float(confidence))
        object.__setattr__(self, "threat_type", normalized)
        object.__setattr__(self, "reasons", reasons)
        object.__setattr__(self, "model_name", model_name)

    @property
    def reason(self) -> str:
        """Legacy single-reason accessor used by the SAGE implementation."""
        return self.reasons[0] if self.reasons else ""

    def is_safe(self) -> bool:
        return not self.is_malicious and self.threat_type is None
