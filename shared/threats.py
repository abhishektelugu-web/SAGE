"""Canonical threat taxonomy shared across security, AI/ML, and backend layers."""

from typing import Literal

ThreatCategory = Literal[
    "PROMPT_INJECTION",
    "SENSITIVE_RESOURCE",
    "EXTERNAL_EXFILTRATION",
    "PRIVILEGE_ESCALATION",
    "DANGEROUS_ACTION",
]
