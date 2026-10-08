"""
ai_ml/schemas.py
=================
AI/ML-specific internal schemas used within the SAGE detection pipeline.

These are NOT the public shared contracts (those live in shared/).
These are intermediate data structures used *between* the internal detectors
so that the inference pipeline can carry rich information without polluting
the public MLDetectionResult contract.

Public contract: shared/ml_result.py  →  MLDetectionResult
Internal schemas: this file          →  DetectionSignal, DetectorOutput
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DetectionSignal:
    """
    A single detection signal produced by one detector (e.g. prompt injection).

    Fields
    ------
    triggered    : Whether this signal was triggered (True = suspicious).
    threat_type  : The threat category this signal relates to.
    score        : Raw detector score in [0.0, 1.0].
                   Higher = more suspicious.
    evidence     : Short text snippet or pattern name that triggered this.
    detector     : Name of the detector that produced this signal.
    """

    triggered: bool
    threat_type: str
    score: float
    evidence: str
    detector: str

    def __post_init__(self) -> None:
        if not (0.0 <= self.score <= 1.0):
            raise ValueError(f"score must be in [0.0, 1.0], got {self.score}")


@dataclass
class PipelineContext:
    """
    Carries all intermediate signals as the action flows through the
    SAGE detection pipeline.

    The inference.py assembler reads this to compute the final
    MLDetectionResult.

    Fields
    ------
    signals           : All signals produced by all detectors, in order.
    all_text          : Full concatenated text of the AgentAction (for logging).
    action_type       : The action_type of the AgentAction being analysed.
    resource          : The resource of the AgentAction being analysed.
    """

    signals: list[DetectionSignal] = field(default_factory=list)
    all_text: str = ""
    action_type: str = ""
    resource: str = ""

    def add_signal(self, signal: DetectionSignal) -> None:
        """Append a detection signal to the context."""
        self.signals.append(signal)

    def triggered_signals(self) -> list[DetectionSignal]:
        """Return only signals that actually fired."""
        return [s for s in self.signals if s.triggered]

    def highest_score_signal(self) -> Optional[DetectionSignal]:
        """Return the signal with the highest score, or None if no signals."""
        if not self.signals:
            return None
        return max(self.signals, key=lambda s: s.score)

    def highest_triggered_signal(self) -> Optional[DetectionSignal]:
        """Return the triggered signal with the highest score, or None."""
        triggered = self.triggered_signals()
        if not triggered:
            return None
        return max(triggered, key=lambda s: s.score)
