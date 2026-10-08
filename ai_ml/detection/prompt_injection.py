"""
ai_ml/detection/prompt_injection.py
=====================================
SAGE Prompt Injection Detector

Purpose
-------
Detect attempts by external content or malicious instructions to override,
hijack, or redirect the behaviour of an AI agent.

Design
------
Hybrid approach:
  1. Pattern-based detection – a maintainable catalogue of regex patterns
     grouped by attack category. Each category contributes a weighted score.
  2. Heuristic scoring – the final score is a weighted combination of how
     many categories fired and how strong the individual signals were.

Why not a pure ML model?
  For a hackathon MVP the pattern approach is:
  - Fully explainable (crucial for security)
  - Offline / no external dependencies
  - Deterministic for demos
  - Easy to extend without retraining

Architecture note
-----------------
This module returns a DetectionSignal, NOT a final MLDetectionResult.
The inference pipeline in inference.py assembles the final result.

NEVER call this directly to make a block/allow decision.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import NamedTuple

from ai_ml.schemas import DetectionSignal
from shared.ml_result import ThreatType


# ---------------------------------------------------------------------------
# Pattern catalogue
# ---------------------------------------------------------------------------
# Each entry defines:
#   name     – human-readable category name (appears in evidence)
#   weight   – contribution to the overall injection score (0.0 – 1.0)
#   patterns – list of regex strings; ANY match fires this category
#
# Design rules for patterns:
#   - IGNORECASE is always applied.
#   - Prefer \b word boundaries to avoid false positives on substrings.
#   - Keep patterns readable – no minified one-liners.
#   - Patterns aim for intent, not exact phrasing.
# ---------------------------------------------------------------------------

class _PatternCategory(NamedTuple):
    name: str
    weight: float
    patterns: list[str]


_INJECTION_CATEGORIES: list[_PatternCategory] = [
    # ── Override / ignore system instructions ─────────────────────────────
    _PatternCategory(
        name="instruction_override",
        weight=0.90,
        patterns=[
            r"\bignore\b.{0,40}\b(previous|prior|above|earlier|system|all)\b.{0,30}\binstructions?\b",
            r"\bdisregard\b.{0,40}\b(instructions?|rules?|guidelines?|policies?|directives?)\b",
            r"\bforget\b.{0,40}\b(instructions?|rules?|guidelines?|what you were told)\b",
            r"\bdo\s+not\s+follow\b.{0,40}\b(previous|prior|system)\b",
            r"\boverride\b.{0,40}\b(instructions?|rules?|guidelines?|policy|security)\b",
            r"\byou\s+(are\s+no\s+longer|must\s+not)\b.{0,40}\b(follow|obey|respect)\b",
            r"\bnew\s+instructions?\s*:?\s*(are|follow|you\s+must|your\s+task)",
            r"\bstop\s+(following|obeying)\b.{0,30}\b(instructions?|rules?|guidelines?)\b",
        ],
    ),

    # ── Reveal / leak confidential information ─────────────────────────────
    _PatternCategory(
        name="reveal_secrets",
        weight=0.85,
        patterns=[
            r"\breveal\b.{0,40}\b(password|secret|key|token|credential|api\s*key|auth)\b",
            r"\bprint\b.{0,40}\b(password|secret|key|token|credential)\b",
            r"\bshow\b.{0,40}\b(password|secret|key|token|credential|system\s*prompt)\b",
            r"\bexpose\b.{0,40}\b(password|secret|key|token|credential|api)\b",
            r"\btell\s+me\b.{0,40}\b(password|secret|credential|system\s+prompt|configuration)\b",
            r"\bwhat\s+(is|are)\b.{0,20}\b(your\s+)?(password|secret|system\s+prompt|instructions?)\b",
            r"\brepeat\s+(back|verbatim|exactly)\b.{0,40}\b(instructions?|prompt|system)\b",
            r"\bsystem\s+prompt\b.{0,20}\b(contents?|text|above|below|leak|show|reveal|print)\b",
        ],
    ),

    # ── Malicious instruction injection via external content ────────────────
    _PatternCategory(
        name="embedded_injection",
        weight=0.80,
        patterns=[
            r"\[injection\b",
            r"\bassistant\s*:\s*(ignore|disregard|forget|override)",
            r"<\s*(system|user|assistant)\s*>\s*(ignore|disregard|forget)",
            r"\bwhen\s+you\s+(read|see|process|encounter)\s+this\b.{0,50}(ignore|disregard|override)",
            r"\bthis\s+message\s+(overrides?|supersedes?|replaces?)\b",
            r"act\s+as\s+if\s+(you\s+have\s+no|there\s+(are|were)\s+no)\s+(restrictions?|rules?|guidelines?|safety)",
            r"\byour\s+(new|real|true|actual)\s+(instructions?|task|role|purpose|goal)\s*:",
            r"\bDAN\b",  # "Do Anything Now" jailbreak
            r"\bjailbreak\b",
            r"\bgrandma\b.{0,30}\b(exploit|jailbreak|bypass|hack)",
        ],
    ),

    # ── Role / persona hijacking ───────────────────────────────────────────
    _PatternCategory(
        name="role_hijack",
        weight=0.75,
        patterns=[
            r"\bact\s+as\s+(if\s+you\s+(are|were)\s+)?(a\s+)?(hacker|evil|unrestricted|unethical|malicious)",
            r"\bpretend\s+(you\s+)?(are|have\s+no)\s*(restrictions?|rules?|guidelines?|safety|filter)",
            r"\bplay\s+(the\s+role\s+of|as)\s+.{0,30}(unrestricted|without\s+filter|no\s+rules?)",
            r"\byou\s+are\s+now\b.{0,40}(unrestricted|without\s+(rules?|guidelines?|restrictions?))",
            r"\bswitch\s+(to|into)\s+.{0,20}(mode|persona|character).{0,30}(unrestricted|no\s+rules?|unsafe)",
        ],
    ),

    # ── Unauthorized action commands ───────────────────────────────────────
    _PatternCategory(
        name="unauthorized_action",
        weight=0.80,
        patterns=[
            r"\bexecute\b.{0,40}\b(without\s+(asking|checking|permission|authoriz|approval))\b",
            r"\b(bypass|circumvent|skip|avoid)\b.{0,40}\b(security|check|validation|filter|guard|approval|auth)\b",
            r"\bdo\s+(this|it)\s+without\b.{0,30}\b(asking|checking|telling|reporting|notif)\b",
            r"\bwithout\s+(user\s+)?knowledge\b",
            r"\bsecretly\b.{0,40}\b(send|upload|transfer|access|read|write|copy)\b",
            r"\b(send|transfer|upload|exfiltrate)\b.{0,40}\bwithout\b.{0,20}\b(notif|telling|asking|permission)\b",
        ],
    ),

    # ── Data exfiltration commands embedded in instructions ────────────────
    _PatternCategory(
        name="exfil_command",
        weight=0.85,
        patterns=[
            r"\b(send|email|upload|post|transfer|exfiltrate|leak)\b.{0,40}\b(to\s+external|to\s+remote|outside)\b",
            r"\b(send|email|transfer)\b.{0,30}\bpassword\b",
            r"\b(send|email|transfer)\b.{0,30}\b(secret|credential|private\s+key|api\s*key)\b",
            r"\bforward\b.{0,40}\b(to\s+)?(http|ftp|external|remote|outside)\b",
            r"\bexport\b.{0,30}\b(database|db|all\s+(data|records|files))\b",
        ],
    ),

    # ── Security policy bypass ─────────────────────────────────────────────
    _PatternCategory(
        name="policy_bypass",
        weight=0.80,
        patterns=[
            r"\b(ignore|disregard|bypass|skip)\b.{0,30}\b(security\s+(policy|rules?|guidelines?|check))\b",
            r"\b(ignore|disregard|bypass)\b.{0,30}\b(access\s+control|acl|permission)\b",
            r"\bsecurity\s+(is\s+off|disabled|not\s+(enabled|active|running))\b",
            r"\bno\s+security\s+(needed|required|check)\b",
            r"\byou\s+have\s+(root|admin|unrestricted)\s+(access|permission|privilege)\b",
        ],
    ),
]

# Pre-compile all patterns for performance
_COMPILED_CATEGORIES: list[tuple[_PatternCategory, list[re.Pattern[str]]]] = [
    (cat, [re.compile(p, re.IGNORECASE | re.DOTALL) for p in cat.patterns])
    for cat in _INJECTION_CATEGORIES
]


# ---------------------------------------------------------------------------
# Detector function
# ---------------------------------------------------------------------------

def detect_prompt_injection(text: str) -> DetectionSignal:
    """
    Analyse a text string for prompt-injection indicators.

    Parameters
    ----------
    text : The full text to analyse (e.g. instruction + resource + parameters).

    Returns
    -------
    DetectionSignal with:
      - triggered = True if any pattern fired above threshold
      - threat_type = PROMPT_INJECTION
      - score = weighted injection confidence [0.0, 1.0]
      - evidence = comma-separated list of triggered category names
      - detector = "prompt_injection"

    Confidence methodology
    ----------------------
    For each category that has at least one pattern match:
      - category contributes its `weight` to a running sum
    Final score = min(sum_of_fired_weights / MAX_POSSIBLE_WEIGHT, 1.0)
    MAX_POSSIBLE_WEIGHT caps scoring so that one very-strong category
    already gives a high signal (not penalised for not hitting others).

    Threshold
    ---------
    TRIGGER_THRESHOLD = 0.30 — a score above this sets triggered=True.
    Single strong category (weight ≥ 0.85) will already exceed threshold.
    """
    if not text or not text.strip():
        return DetectionSignal(
            triggered=False,
            threat_type=ThreatType.PROMPT_INJECTION,
            score=0.0,
            evidence="no text provided",
            detector="prompt_injection",
        )

    fired_categories: list[str] = []
    total_weight: float = 0.0

    for cat, compiled_patterns in _COMPILED_CATEGORIES:
        for pattern in compiled_patterns:
            if pattern.search(text):
                fired_categories.append(cat.name)
                total_weight += cat.weight
                break  # one match per category is enough

    # Normalise — MAX_POSSIBLE_WEIGHT is the highest single category weight
    # so that one strong hit already produces a high score.
    # Multiple hits push the score higher (capped at 1.0).
    MAX_POSSIBLE_WEIGHT = max(cat.weight for cat in _INJECTION_CATEGORIES)
    score = min(total_weight / MAX_POSSIBLE_WEIGHT, 1.0)

    TRIGGER_THRESHOLD = 0.30
    triggered = score >= TRIGGER_THRESHOLD

    evidence = ", ".join(fired_categories) if fired_categories else "no injection patterns matched"

    return DetectionSignal(
        triggered=triggered,
        threat_type=ThreatType.PROMPT_INJECTION,
        score=round(score, 4),
        evidence=evidence,
        detector="prompt_injection",
    )
