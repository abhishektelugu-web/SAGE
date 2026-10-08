"""
ai_ml/inference.py
===================
SAGE AI — Main Inference Pipeline

This is the single public entry point for the SAGE AI detection engine.

Usage (from Member 1's Security Gateway)
-----------------------------------------
    from ai_ml.inference import detect
    from shared.agent_action import AgentAction

    action = AgentAction(
        agent_id="agent-001",
        action_type="read_file",
        resource="passwords.txt",
        parameters={"instruction": "Read and summarize."},
    )

    result = detect(action)
    # result: MLDetectionResult(is_malicious=True, threat_type="SENSITIVE_RESOURCE", ...)

Security contract
-----------------
SAGE NEVER:
  - Executes the requested tool/action.
  - Makes the final ALLOW/BLOCK/APPROVAL_REQUIRED decision.
  - Reads or writes arbitrary files.
  - Makes network requests.

SAGE ONLY:
  - Analyses the AgentAction data object.
  - Returns an MLDetectionResult for the Security Gateway to act on.

Pipeline stages
---------------
1. Text extraction      – Pull all textual content from the AgentAction.
2. Prompt injection     – Check for instruction hijacking patterns.
3. Sensitive resource   – Check if the resource is sensitive/restricted.
4. Data exfiltration    – Check for external data transfer intent.
5. Anomaly detection    – Check for suspicious action patterns.
6. Classification       – Resolve the strongest threat from all signals.
7. Confidence scoring   – Compute final confidence from all signals.
8. Result assembly      – Build and validate MLDetectionResult.

Confidence scoring methodology
-------------------------------
The confidence score reflects how strongly SAGE believes the dominant
threat signal is real.

Base score: the score from the top-priority triggered signal.
Multi-signal boost: +MULTI_SIGNAL_BOOST per additional triggered signal
  (capped so total stays ≤ 1.0).
For safe actions: confidence reflects certainty-of-safety (0.10–0.25).
All values are clamped to [0.0, 1.0].

This is deterministic and explainable — important for a security demo.
"""

from __future__ import annotations

import logging
from typing import Optional

from ai_ml.detection.anomaly_detection import detect_anomaly
from ai_ml.detection.classifier import (
    classify_data_exfiltration,
    classify_from_context,
    classify_sensitive_resource,
)
from ai_ml.detection.prompt_injection import detect_prompt_injection
from ai_ml.models.model_config import (
    MALICIOUS_THRESHOLD,
    MAX_SAFE_CONFIDENCE,
    MIN_SAFE_CONFIDENCE,
    MULTI_SIGNAL_BOOST,
)
from ai_ml.models.loader import get_model_loader
from ai_ml.schemas import PipelineContext
from shared.agent_action import AgentAction
from shared.ml_result import MLDetectionResult, ThreatType

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect(action: AgentAction) -> MLDetectionResult:
    """
    Analyse an AgentAction and return an MLDetectionResult.

    This is the **only function Member 1 needs to call**.

    Parameters
    ----------
    action : AgentAction
        The action the AI agent wants to perform.

    Returns
    -------
    MLDetectionResult
        is_malicious : bool  — True if SAGE suspects malicious intent.
        threat_type  : str   — One of the ThreatType constants.
        confidence   : float — Detection confidence in [0.0, 1.0].
        reason       : str   — Human-readable explanation.

    Raises
    ------
    Never raises. Malformed/unexpected input is handled safely.
    A failed analysis returns a conservative SUSPICIOUS_BEHAVIOR result
    rather than silently returning SAFE.
    """
    try:
        return _run_pipeline(action)
    except Exception as exc:
        logger.error(
            f"SAGE inference pipeline failed for action_id={action.action_id}: {exc}",
            exc_info=True,
        )
        # Fail SAFE — return suspicious rather than accidentally clearing a threat
        return MLDetectionResult(
            is_malicious=True,
            threat_type=ThreatType.SUSPICIOUS_BEHAVIOR,
            confidence=0.50,
            reason=(
                f"SAGE pipeline encountered an unexpected error: {exc}. "
                "Flagging as suspicious for safety."
            ),
        )


# ---------------------------------------------------------------------------
# Internal pipeline
# ---------------------------------------------------------------------------

def _run_pipeline(action: AgentAction) -> MLDetectionResult:
    """
    Execute all detection stages and assemble the final result.
    """
    logger.debug(
        f"SAGE pipeline starting: action_id={action.action_id}, "
        f"type={action.action_type}, resource={action.resource}"
    )

    # ── Stage 1: Extract text ─────────────────────────────────────────────
    all_text = action.get_all_text()

    # ── Stage 2: Normalize optional resource for detector functions ─────
    resource = action.resource or ""
    context = PipelineContext(
        all_text=all_text,
        action_type=action.action_type,
        resource=resource,
    )

    # ── Stage 3: Prompt injection detection ───────────────────────────────
    injection_signal = detect_prompt_injection(all_text)
    context.add_signal(injection_signal)
    logger.debug(
        f"Injection detector: triggered={injection_signal.triggered}, "
        f"score={injection_signal.score}"
    )

    # ── Stage 4: Sensitive resource classification ─────────────────────────
    sensitive_signal = classify_sensitive_resource(resource, all_text)
    context.add_signal(sensitive_signal)
    logger.debug(
        f"Sensitive resource: triggered={sensitive_signal.triggered}, "
        f"score={sensitive_signal.score}"
    )

    # ── Stage 5: Data exfiltration classification ─────────────────────────
    exfil_signal = classify_data_exfiltration(
        action_type=action.action_type,
        resource=resource,
        destination=action.destination,
        all_text=all_text,
    )
    context.add_signal(exfil_signal)
    logger.debug(
        f"Exfiltration detector: triggered={exfil_signal.triggered}, "
        f"score={exfil_signal.score}"
    )

    # ── Stage 6: Anomaly / suspicious behaviour detection ─────────────────
    anomaly_signal = detect_anomaly(
        action_type=action.action_type,
        resource=resource,
        parameters=action.parameters,
        destination=action.destination,
    )
    context.add_signal(anomaly_signal)
    logger.debug(
        f"Anomaly detector: triggered={anomaly_signal.triggered}, "
        f"score={anomaly_signal.score}"
    )

    # ── Stage 7 (optional): ML model inference ────────────────────────────
    # In rule_based mode this returns 0.0 and has no effect.
    loader = get_model_loader()
    ml_score = loader.predict({
        "text_length": len(all_text),
        "injection_score": injection_signal.score,
        "anomaly_score": anomaly_signal.score,
        "is_sensitive_resource": int(sensitive_signal.triggered),
        "is_external_destination": int(exfil_signal.triggered),
    })
    if ml_score > 0.0:
        logger.debug(f"ML model score: {ml_score}")

    # ── Stage 8: Classify — resolve dominant threat ────────────────────────
    dominant = classify_from_context(context)

    # ── Stage 9: Confidence scoring ───────────────────────────────────────
    confidence = _compute_confidence(context, dominant, ml_score)

    # ── Stage 10: Determine maliciousness ─────────────────────────────────
    is_malicious = dominant.triggered and confidence >= MALICIOUS_THRESHOLD

    # ── Stage 11: Build human-readable reason ─────────────────────────────
    reason = _build_reason(dominant, context, is_malicious)

    result = MLDetectionResult(
        is_malicious=is_malicious,
        threat_type=dominant.threat_type,
        confidence=confidence,
        reason=reason,
        model_name="SAGE",
    )

    logger.info(
        f"SAGE result for action_id={action.action_id}: "
        f"malicious={is_malicious}, type={dominant.threat_type}, "
        f"confidence={confidence:.2f}"
    )

    return result


def _compute_confidence(
    context: PipelineContext,
    dominant: "DetectionSignal",  # type: ignore[name-defined]  # noqa: F821
    ml_score: float,
) -> float:
    """
    Compute the final confidence score [0.0, 1.0].

    Methodology
    -----------
    1. Start with the dominant signal's score as the base.
    2. Apply a multi-signal boost for each *additional* triggered signal.
    3. Optionally blend with ML score if operating in ml_hybrid mode.
    4. For safe actions, cap at MAX_SAFE_CONFIDENCE.
    5. Clamp the final value to [0.0, 1.0].

    This is intentionally deterministic and explainable.
    """
    if not dominant.triggered:
        # Safe action — express confidence in its safety
        # Higher overall cleanliness → higher safe confidence
        all_scores = [s.score for s in context.signals]
        max_score = max(all_scores) if all_scores else 0.0
        # Invert: low threat score → high safe confidence
        safe_confidence = MAX_SAFE_CONFIDENCE * (1.0 - max_score)
        return round(max(MIN_SAFE_CONFIDENCE, safe_confidence), 4)

    # Base: dominant signal score
    base = dominant.score

    # Multi-signal boost
    num_additional_triggered = max(0, len(context.triggered_signals()) - 1)
    boost = min(num_additional_triggered * MULTI_SIGNAL_BOOST, 0.20)

    # Optional ML blend (only if ml_hybrid and model returned a score)
    ml_blend = 0.0
    if ml_score > 0.0:
        # Weighted average: 70% rule-based, 30% ML
        ml_blend = 0.30 * ml_score - 0.30 * base  # delta contribution

    final = base + boost + ml_blend
    return round(max(0.0, min(1.0, final)), 4)


def _build_reason(
    dominant: "DetectionSignal",  # type: ignore[name-defined]  # noqa: F821
    context: PipelineContext,
    is_malicious: bool,
) -> str:
    """
    Build a clear, human-readable reason string for the detection result.
    """
    if not dominant.triggered:
        return (
            f"No threat indicators detected. "
            f"Action type '{context.action_type}' on resource '{context.resource}' "
            f"appears safe."
        )

    threat_descriptions: dict[str, str] = {
        ThreatType.PROMPT_INJECTION: (
            "Prompt injection detected: the action contains instructions that "
            "attempt to override, hijack, or redirect agent behaviour."
        ),
        ThreatType.SENSITIVE_RESOURCE: (
            "Sensitive resource access detected: the action targets a resource "
            "that appears to contain credentials, secrets, or restricted data."
        ),
        ThreatType.DATA_EXFILTRATION: (
            "Data exfiltration indicators detected: the action appears designed "
            "to transfer data to an external destination."
        ),
        ThreatType.SUSPICIOUS_BEHAVIOR: (
            "Suspicious behaviour detected: the action exhibits unusual patterns "
            "that deviate from expected safe agent behaviour."
        ),
    }

    description = threat_descriptions.get(
        dominant.threat_type,
        f"Threat type '{dominant.threat_type}' detected."
    )

    # Append evidence from the dominant signal
    evidence_suffix = f" Evidence: {dominant.evidence}."

    # List any co-triggered threats for full transparency
    other_triggered = [
        s.threat_type
        for s in context.triggered_signals()
        if s.threat_type != dominant.threat_type
    ]
    co_threats = ""
    if other_triggered:
        unique_others = sorted(set(other_triggered))
        co_threats = f" Additional signals: {', '.join(unique_others)}."

    return description + evidence_suffix + co_threats
