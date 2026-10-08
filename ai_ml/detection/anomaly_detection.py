"""
ai_ml/detection/anomaly_detection.py
=======================================
SAGE Anomaly / Suspicious Behaviour Detector

Purpose
-------
Identify suspicious behaviour that may NOT be a direct prompt injection
but still warrants attention:
  - Unusual sensitive-resource access
  - Unexpected external communication
  - High-risk action types used in unusual ways
  - Suspicious combinations of action + resource + parameters
  - Parameter structure anomalies

Design philosophy
-----------------
Rule-based heuristic scoring — practical for a hackathon MVP.
No statistical models (no training data required), but the architecture
is ready for a future ML layer (e.g. replacing heuristics with a
trained anomaly scorer).

This returns a DetectionSignal. The inference pipeline combines it
with other signals to produce the final MLDetectionResult.

Scoring methodology
-------------------
Each heuristic that fires adds a weighted score.
Final score = min(sum of weights, 1.0).
A score ≥ ANOMALY_THRESHOLD triggers the signal.
"""

from __future__ import annotations

import re
from typing import Any

from ai_ml.schemas import DetectionSignal
from shared.ml_result import ThreatType


# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------

ANOMALY_THRESHOLD = 0.35  # Score at which we consider behaviour suspicious


# ---------------------------------------------------------------------------
# High-risk action types
# ---------------------------------------------------------------------------

_HIGH_RISK_ACTIONS: dict[str, float] = {
    # action_type -> anomaly weight contribution
    "execute_code": 0.50,
    "run_script": 0.50,
    "shell_command": 0.55,
    "system_call": 0.55,
    "install_package": 0.45,
    "delete_file": 0.40,
    "overwrite_file": 0.40,
    "modify_system": 0.50,
    "send_email": 0.25,
    "http_request": 0.20,
    "http_post": 0.25,
    "upload": 0.30,
    "ftp_upload": 0.40,
    "transfer": 0.30,
}

# ---------------------------------------------------------------------------
# External communication indicators
# ---------------------------------------------------------------------------

_EXTERNAL_INDICATORS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"^https?://(?!localhost|127\.0\.0\.1|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)",
        r"^ftp://",
        r"@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",  # email address as destination
        r"\bexternal\s+(server|api|endpoint|service)\b",
        r"\bremote\s+(host|server|endpoint)\b",
        r"\bpastebin\.com\b",
        r"\bngrok\.io\b",
        r"\bwebhook\b",
    ]
]

# ---------------------------------------------------------------------------
# Suspicious parameter structure indicators
# ---------------------------------------------------------------------------

_LARGE_DATA_THRESHOLD_CHARS = 2000  # If instruction/content is very long, flag it
_SUSPICIOUS_PARAM_KEYS: set[str] = {
    "raw_command",
    "shell",
    "exec",
    "cmd",
    "script",
    "eval",
    "payload",
    "exploit",
}

# ---------------------------------------------------------------------------
# Suspicious action + resource combinations
# ---------------------------------------------------------------------------
# Tuples of (action_type_pattern, resource_pattern, weight)

_SUSPICIOUS_COMBOS: list[tuple[re.Pattern[str], re.Pattern[str], float]] = [
    (
        re.compile(r"read_file", re.IGNORECASE),
        # Match password, credential, secret, .env, db_credentials, etc.
        re.compile(
            r"(password|credential|secret|\.env|shadow|sudoers|api[_\-]?key|private[_\-]?key)",
            re.IGNORECASE,
        ),
        0.60,
    ),
    (
        re.compile(r"(http_request|http_post|upload|send)", re.IGNORECASE),
        re.compile(r"^https?://", re.IGNORECASE),
        0.35,
    ),
    (
        re.compile(r"(execute|run|shell|system)", re.IGNORECASE),
        re.compile(r"(\.sh|\.bat|\.ps1|\.py|\.exe)", re.IGNORECASE),
        0.50,
    ),
    (
        re.compile(r"(delete|remove|rm)", re.IGNORECASE),
        # /etc/ and similar system paths — use simple substring match, not \b
        re.compile(r"(/etc/|/var/|system32|windows)", re.IGNORECASE),
        0.65,
    ),
]


# ---------------------------------------------------------------------------
# Anomaly detector
# ---------------------------------------------------------------------------

def detect_anomaly(
    action_type: str,
    resource: str,
    parameters: dict[str, Any],
    destination: str = "",
) -> DetectionSignal:
    """
    Detect suspicious or anomalous behaviour that may not be a direct
    prompt injection but is still concerning.

    Parameters
    ----------
    action_type  : The type of action requested.
    resource     : The target resource.
    parameters   : The action parameters dictionary.
    destination  : Extracted destination/URL (from parameters).

    Returns
    -------
    DetectionSignal with threat_type = SUSPICIOUS_BEHAVIOR.

    Score contributions
    -------------------
    1. High-risk action type                          +weight per table
    2. External communication indicator in resource    +0.30
    3. Suspicious action + resource combination        +weight per table
    4. Suspicious parameter key present                +0.35 per key (max 1)
    5. Unusually large instruction payload             +0.20
    6. Multiple parameters exceeding normal size       +0.15
    """
    score: float = 0.0
    evidence_parts: list[str] = []

    # ── 1. High-risk action type ──────────────────────────────────────────
    action_lower = action_type.lower().replace("-", "_").replace(" ", "_")
    if action_lower in _HIGH_RISK_ACTIONS:
        w = _HIGH_RISK_ACTIONS[action_lower]
        score += w
        evidence_parts.append(f"high-risk action type '{action_type}' (weight={w})")

    # ── 2. External communication indicator ───────────────────────────────
    combined_dest = f"{resource} {destination}"
    for pattern in _EXTERNAL_INDICATORS:
        if pattern.search(combined_dest):
            score += 0.30
            evidence_parts.append(f"external communication indicator in resource/destination")
            break

    # ── 3. Suspicious action + resource combination ───────────────────────
    for action_pattern, resource_pattern, combo_weight in _SUSPICIOUS_COMBOS:
        if action_pattern.search(action_type) and resource_pattern.search(resource):
            score += combo_weight
            evidence_parts.append(
                f"suspicious combination: action='{action_type}' + resource matches '{resource_pattern.pattern}'"
            )
            break  # count only the strongest combo

    # ── 4. Suspicious parameter keys ──────────────────────────────────────
    param_keys_lower = {k.lower() for k in parameters.keys()}
    suspicious_keys_found = param_keys_lower & _SUSPICIOUS_PARAM_KEYS
    if suspicious_keys_found:
        score += min(0.35 * len(suspicious_keys_found), 0.50)
        evidence_parts.append(f"suspicious parameter keys: {suspicious_keys_found}")

    # ── 5. Unusually large instruction/content payload ────────────────────
    for key, value in parameters.items():
        if isinstance(value, str) and len(value) > _LARGE_DATA_THRESHOLD_CHARS:
            score += 0.20
            evidence_parts.append(
                f"large parameter '{key}': {len(value)} chars (threshold={_LARGE_DATA_THRESHOLD_CHARS})"
            )
            break  # flag once

    score = min(score, 1.0)
    triggered = score >= ANOMALY_THRESHOLD

    return DetectionSignal(
        triggered=triggered,
        threat_type=ThreatType.SUSPICIOUS_BEHAVIOR,
        score=round(score, 4),
        evidence="; ".join(evidence_parts) if evidence_parts else "no anomalous indicators detected",
        detector="anomaly_detection",
    )
