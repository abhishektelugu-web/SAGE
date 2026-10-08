"""
ai_ml/models/loader.py
=======================
Model loading and inference wrapper.

For the MVP this is a stub that supports the rule_based mode.
When a real model is needed, implement the ml_hybrid path here
without changing any other part of the codebase.

This isolation means:
  - inference.py never imports model-loading machinery directly.
  - Swapping rule_based → ml_hybrid requires changes ONLY in this file.
  - Tests can run without any model artifacts.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from ai_ml.models.model_config import MODE, MODEL_PATH

logger = logging.getLogger(__name__)


class ModelLoader:
    """
    Manages loading and accessing the optional ML model.

    In rule_based mode this is a no-op. In ml_hybrid mode it loads
    the model from MODEL_PATH and exposes a predict() method.
    """

    def __init__(self) -> None:
        self._model: Optional[Any] = None
        self._loaded: bool = False
        self.mode: str = MODE

    def load(self) -> None:
        """
        Load the model artifact if operating in ml_hybrid mode.
        Logs a warning and continues if the model file is missing.
        """
        if self.mode == "rule_based":
            logger.debug("SAGE running in rule_based mode — no model to load.")
            self._loaded = True
            return

        if self.mode == "ml_hybrid":
            try:
                import pickle  # noqa: S403 — safe for controlled model files
                with open(MODEL_PATH, "rb") as f:
                    self._model = pickle.load(f)  # noqa: S301
                self._loaded = True
                logger.info(f"SAGE ML model loaded from {MODEL_PATH}")
            except FileNotFoundError:
                logger.warning(
                    f"ML model not found at {MODEL_PATH}. "
                    "Falling back to rule_based mode."
                )
                self.mode = "rule_based"
                self._loaded = True
            except Exception as exc:
                logger.error(f"Failed to load ML model: {exc}. Using rule_based mode.")
                self.mode = "rule_based"
                self._loaded = True

    def is_ready(self) -> bool:
        """True if load() has been called successfully."""
        return self._loaded

    def predict(self, features: dict[str, Any]) -> float:
        """
        Run ML inference and return a maliciousness score [0.0, 1.0].

        Only meaningful in ml_hybrid mode. Returns 0.0 in rule_based mode
        (the rule engine handles scoring instead).

        Parameters
        ----------
        features : Dictionary of extracted features from an AgentAction.

        Returns
        -------
        float — ML-estimated maliciousness probability.
        """
        if self.mode != "ml_hybrid" or self._model is None:
            return 0.0

        try:
            # Assumes the model has a predict_proba method (sklearn-style).
            # Adapt this for other model types.
            feature_vector = _build_feature_vector(features)
            proba = self._model.predict_proba([feature_vector])[0][1]
            return float(max(0.0, min(1.0, proba)))
        except Exception as exc:
            logger.error(f"ML inference failed: {exc}. Returning 0.0.")
            return 0.0


def _build_feature_vector(features: dict[str, Any]) -> list[float]:
    """
    Convert a features dict into a numeric vector for model input.

    Placeholder — replace with real feature engineering when a model
    is integrated.
    """
    return [
        float(features.get("text_length", 0)) / 5000.0,
        float(features.get("injection_score", 0.0)),
        float(features.get("anomaly_score", 0.0)),
        float(features.get("is_sensitive_resource", 0)),
        float(features.get("is_external_destination", 0)),
    ]


# Module-level singleton — created once, shared across calls.
_loader: Optional[ModelLoader] = None


def get_model_loader() -> ModelLoader:
    """
    Return the module-level ModelLoader singleton, loading on first call.
    Thread-safe for single-threaded hackathon demo use.
    """
    global _loader
    if _loader is None:
        _loader = ModelLoader()
        _loader.load()
    return _loader
