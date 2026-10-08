"""
ai_ml/models/model_config.py
==============================
Configuration for SAGE AI model integration.

For the hackathon MVP the system operates in RULE_BASED mode,
which requires no external model files and works fully offline.

When a real ML model is integrated later, set MODE = "ml_hybrid"
and point MODEL_PATH to the model artifact.

This file centralises all model-related configuration so that
model paths are never hard-coded throughout the codebase.
"""

from __future__ import annotations

import os
from pathlib import Path

# ---------------------------------------------------------------------------
# Detection mode
# ---------------------------------------------------------------------------
# "rule_based"  – Pure pattern/heuristic detection (default for MVP).
#                 No external model files required.
# "ml_hybrid"   – Pattern + ML model inference combined.
#                 Requires a trained model at MODEL_PATH.
# ---------------------------------------------------------------------------

MODE: str = os.getenv("SAGE_MODE", "rule_based")

# ---------------------------------------------------------------------------
# Model path — only used when MODE == "ml_hybrid"
# ---------------------------------------------------------------------------
# Default: looks for model.pkl in the same directory as this file.
# Override with environment variable SAGE_MODEL_PATH.
# ---------------------------------------------------------------------------

_DEFAULT_MODEL_PATH = Path(__file__).parent / "model.pkl"
MODEL_PATH: Path = Path(os.getenv("SAGE_MODEL_PATH", str(_DEFAULT_MODEL_PATH)))

# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------

# Score above which an action is considered malicious overall
MALICIOUS_THRESHOLD: float = float(os.getenv("SAGE_MALICIOUS_THRESHOLD", "0.40"))

# Minimum confidence we report even for a clearly safe action
MIN_SAFE_CONFIDENCE: float = 0.10

# Maximum safe confidence — avoids returning 1.0 confidence for safe actions
# which would look suspiciously over-confident to reviewers
MAX_SAFE_CONFIDENCE: float = 0.25

# Boost applied to confidence when multiple threat signals are triggered together
MULTI_SIGNAL_BOOST: float = 0.08
