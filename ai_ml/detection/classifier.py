"""
ai_ml/detection/classifier.py
================================
SAGE Threat Classifier

Purpose
-------
Given information from all detectors (prompt injection, anomaly, resource
sensitivity), classify the action into the project's threat taxonomy and
produce a final DetectionSignal that represents the strongest threat found.

This module deliberately does NOT make ALLOW/BLOCK decisions.
It maps evidence → ThreatType + score.

Design
------
Rule-based classification with a clear priority order:
  1. PROMPT_INJECTION  (highest priority — direct attack on agent control)
  2. DATA_EXFILTRATION (high priority — data leaving the boundary)
  3. SENSITIVE_RESOURCE (medium — accessing restricted resources)
  4. SUSPICIOUS_BEHAVIOR (low — anomalous but not clearly malicious)
  5. SAFE             (no threat detected)

Why priority order?
  In a combined attack (e.g. prompt injection + sensitive resource + exfil),
  the Security Gateway needs to know the *dominant* threat type for policy
  routing. The classifier surfaces the highest-priority triggered threat.
  Member 1 can still read all signals from the PipelineContext if needed.
"""

from __future__ import annotations

import re
from typing import Optional

from ai_ml.schemas import DetectionSignal, PipelineContext
from shared.ml_result import ThreatType


# ---------------------------------------------------------------------------
# Sensitive resource patterns
# ---------------------------------------------------------------------------
# Resources that suggest access to credentials, keys, or restricted data.

_SENSITIVE_RESOURCE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\bpassword(s)?\b",
        r"\bcredential(s)?\b",
        r"\bsecret(s)?\b",
        r"\bapi[_\-\s]?key(s)?\b",
        r"\bprivate[_\-\s]?key(s)?\b",
        # .env file — use word boundary only on right side; dot is non-word char
        r"(?<![\w])(\.env)(?![\w])",
        r"\bauth(entication)?[_\-\s]?token(s)?\b",
        r"\bssh[_\-\s]?key(s)?\b",
        # .pem / .p12 certificate/key files
        r"\.(pem|p12|pfx|crt|cer|der)(?:[^\w]|$)",
        r"\bssl[_\-\s]?(cert|certificate|key)(s)?\b",
        r"\baccess[_\-\s]?token(s)?\b",
        r"\bsecret[_\-\s]?key(s)?\b",
        r"\bprivate[_\-\s]?data\b",
        r"\bconfidential\b",
        r"\brestricted\b",
        # /etc/passwd, /etc/shadow, /etc/sudoers — path separator is non-word
        r"/etc/(passwd|shadow|sudoers)(?:[^\w]|$)",
        r"\b(admin|root|system)\s+(config|configuration|settings?)\b",
        r"\bdatabase\s+(credentials?|config|password)\b",
    ]
]

# ---------------------------------------------------------------------------
# External transfer / exfiltration patterns (resource or destination-level)
# ---------------------------------------------------------------------------

_EXFIL_RESOURCE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"^https?://",           # URL as destination
        r"^ftp://",
        r"@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",  # email address
        r"\bexternal\b",
        r"\bremote\s+server\b",
        r"\bpastebin\b",
        r"\bngrok\b",
        r"\bwebhook\b",
    ]
]

_EXFIL_ACTION_TYPES: set[str] = {
    "send_email",
    "http_request",
    "http_post",
    "upload",
    "post",
    "transfer",
    "exfiltrate",
    "ftp_upload",
    "webhook",
    "send_data",
    "send_message",
}

# ---------------------------------------------------------------------------
# Suspicious action type combinations
# These action types are inherently higher risk even without other signals.
# ---------------------------------------------------------------------------

_HIGH_RISK_ACTION_TYPES: set[str] = {
    "execute_code",
    "run_script",
    "shell_command",
    "system_call",
    "install_package",
    "modify_system",
    "delete_file",
    "overwrite_file",
}


# ---------------------------------------------------------------------------
# Classifier functions
# ---------------------------------------------------------------------------

def classify_sensitive_resource(resource: str, all_text: str) -> DetectionSignal:
    """
    Detect if the action targets a sensitive or restricted resource.

    Checks both the resource name and any textual references in parameters.
    """
    combined = f"{resource} {all_text}"
    matched_patterns: list[str] = []

    for pattern in _SENSITIVE_RESOURCE_PATTERNS:
        if pattern.search(combined):
            matched_patterns.append(pattern.pattern)

    if matched_patterns:
        # Score proportional to how many indicators matched (capped at 1.0)
        score = min(0.50 + 0.15 * len(matched_patterns), 0.95)
        return DetectionSignal(
            triggered=True,
            threat_type=ThreatType.SENSITIVE_RESOURCE,
            score=round(score, 4),
            evidence=f"Sensitive resource indicators: {matched_patterns[:3]}",
            detector="classifier_sensitive_resource",
        )

    return DetectionSignal(
        triggered=False,
        threat_type=ThreatType.SENSITIVE_RESOURCE,
        score=0.0,
        evidence="no sensitive resource indicators",
        detector="classifier_sensitive_resource",
    )


def classify_data_exfiltration(
    action_type: str,
    resource: str,
    destination: str,
    all_text: str,
) -> DetectionSignal:
    """
    Detect if the action is designed to move data to an external destination.

    Combines action type analysis and resource/destination pattern matching.
    """
    score = 0.0
    evidence_parts: list[str] = []

    # Check action type
    if action_type.lower() in _EXFIL_ACTION_TYPES:
        score += 0.45
        evidence_parts.append(f"high-risk action type '{action_type}'")

    # Check resource for external indicators
    for pattern in _EXFIL_RESOURCE_PATTERNS:
        if pattern.search(resource) or pattern.search(destination):
            score += 0.30
            evidence_parts.append(f"external destination pattern: {pattern.pattern}")
            break

    # Check if sensitive data + external transfer mentioned together
    has_sensitive_mention = any(
        p.search(all_text) for p in _SENSITIVE_RESOURCE_PATTERNS
    )
    has_external_mention = any(
        p.search(all_text) for p in _EXFIL_RESOURCE_PATTERNS
    )
    if has_sensitive_mention and has_external_mention:
        score += 0.30
        evidence_parts.append("sensitive data combined with external transfer reference")

    score = min(score, 1.0)
    # Lower threshold: sensitive data + any external reference is a strong signal
    triggered = score >= 0.30

    return DetectionSignal(
        triggered=triggered,
        threat_type=ThreatType.DATA_EXFILTRATION,
        score=round(score, 4),
        evidence="; ".join(evidence_parts) if evidence_parts else "no exfiltration indicators",
        detector="classifier_exfiltration",
    )


def classify_from_context(context: PipelineContext) -> DetectionSignal:
    """
    Master classification function.

    Given the full PipelineContext (which holds all prior detector signals),
    determines the highest-priority threat type and returns a single
    authoritative DetectionSignal for the inference pipeline.

    Priority order (highest first):
      PROMPT_INJECTION → DATA_EXFILTRATION → SENSITIVE_RESOURCE →
      SUSPICIOUS_BEHAVIOR → SAFE
    """
    triggered = context.triggered_signals()

    if not triggered:
        return DetectionSignal(
            triggered=False,
            threat_type=ThreatType.SAFE,
            score=0.0,
            evidence="no threats detected by any detector",
            detector="classifier",
        )

    # Priority 1: Prompt Injection
    injection_signals = [
        s for s in triggered if s.threat_type == ThreatType.PROMPT_INJECTION
    ]
    if injection_signals:
        best = max(injection_signals, key=lambda s: s.score)
        return DetectionSignal(
            triggered=True,
            threat_type=ThreatType.PROMPT_INJECTION,
            score=best.score,
            evidence=best.evidence,
            detector="classifier",
        )

    # Priority 2: Data Exfiltration
    exfil_signals = [
        s for s in triggered if s.threat_type == ThreatType.DATA_EXFILTRATION
    ]
    if exfil_signals:
        best = max(exfil_signals, key=lambda s: s.score)
        return DetectionSignal(
            triggered=True,
            threat_type=ThreatType.DATA_EXFILTRATION,
            score=best.score,
            evidence=best.evidence,
            detector="classifier",
        )

    # Priority 3: Sensitive Resource
    sensitive_signals = [
        s for s in triggered if s.threat_type == ThreatType.SENSITIVE_RESOURCE
    ]
    if sensitive_signals:
        best = max(sensitive_signals, key=lambda s: s.score)
        return DetectionSignal(
            triggered=True,
            threat_type=ThreatType.SENSITIVE_RESOURCE,
            score=best.score,
            evidence=best.evidence,
            detector="classifier",
        )

    # Priority 4: Suspicious Behavior (catch-all)
    suspicious_signals = [
        s for s in triggered if s.threat_type == ThreatType.SUSPICIOUS_BEHAVIOR
    ]
    if suspicious_signals:
        best = max(suspicious_signals, key=lambda s: s.score)
        return DetectionSignal(
            triggered=True,
            threat_type=ThreatType.SUSPICIOUS_BEHAVIOR,
            score=best.score,
            evidence=best.evidence,
            detector="classifier",
        )

    # Fallback — something triggered but doesn't fit known types
    best_overall = context.highest_triggered_signal()
    if best_overall:
        return DetectionSignal(
            triggered=True,
            threat_type=ThreatType.SUSPICIOUS_BEHAVIOR,
            score=best_overall.score,
            evidence=f"unknown threat type from detector '{best_overall.detector}'",
            detector="classifier",
        )

    return DetectionSignal(
        triggered=False,
        threat_type=ThreatType.SAFE,
        score=0.0,
        evidence="classifier found no actionable threat",
        detector="classifier",
    )
