"""Deterministic, explainable threat indicators for AgentAction inputs."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

from shared.agent_action import AgentAction
from shared.threats import ThreatCategory

Severity = Literal["low", "medium", "high"]


@dataclass(frozen=True, slots=True)
class RuleFinding:
    """Evidence that one deterministic rule matched an action field."""

    rule_id: str
    category: ThreatCategory
    matched: bool
    matched_text: str
    source_field: str
    severity: Severity
    reason: str


@dataclass(frozen=True, slots=True)
class _Rule:
    rule_id: str
    category: ThreatCategory
    severity: Severity
    reason: str
    patterns: tuple[re.Pattern[str], ...]


def _patterns(*expressions: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(expression, re.IGNORECASE) for expression in expressions)


_RULES = (
    _Rule(
        rule_id="PROMPT_INJECTION_OVERRIDE",
        category="PROMPT_INJECTION",
        severity="high",
        reason="The text asks to ignore, disregard, forget, or override existing instructions.",
        patterns=_patterns(
            r"\b(?:ignore|disregard)\s+(?:(?:all|any)\s+)?"
            r"(?:(?:the)\s+)?(?:previous|prior|preceding|above)\s+"
            r"(?:agent\s+)?instructions?\b",
            r"\bforget\s+(?:(?:all|your|the)\s+)?"
            r"(?:previous\s+)?instructions?\b",
            r"\boverride\s+(?:(?:all|your|the|existing)\s+){0,2}"
            r"instructions?\b",
        ),
    ),
    _Rule(
        rule_id="SENSITIVE_RESOURCE_REFERENCE",
        category="SENSITIVE_RESOURCE",
        severity="medium",
        reason="The text references a credential, secret, key, token, password, or environment file.",
        patterns=_patterns(
            r"\bsensitive\s+(?:data|information)\b",
            r"\bpasswords?\b",
            r"\bpasswd\b",
            r"\bcredentials?\b",
            r"\bsecrets?\b",
            r"\bprivate[\s_-]+keys?\b",
            r"\bapi[\s_-]+keys?\b",
            r"\btokens?\b",
            r"(?<![\w])\.env(?:[.\w-]*)?(?!\w)",
        ),
    ),
    _Rule(
        rule_id="EXTERNAL_DATA_TRANSMISSION",
        category="EXTERNAL_EXFILTRATION",
        severity="high",
        reason="The text describes transmitting data or sensitive information to an external destination.",
        patterns=_patterns(
            r"\b(?:send|upload|post|transmit)\b.{0,80}"
            r"\b(?:sensitive\s+)?(?:data|information|credentials?|secrets?|"
            r"passwords?|private[\s_-]+keys?|api[\s_-]+keys?|tokens?|"
            r"file\s+contents?)\b.{0,80}\b(?:to|into)\b.{0,30}"
            r"\b(?:an?\s+)?(?:external|remote|third[- ]party)\b",
            r"\b(?:upload|post|transmit)\b.{0,50}"
            r"\b(?:sensitive\s+)?(?:data|information|credentials?|secrets?|"
            r"passwords?|private[\s_-]+keys?|api[\s_-]+keys?|tokens?|"
            r"file\s+contents?)\b",
            r"\b(?:send|upload|post|transmit)\b.{0,80}"
            r"\b(?:data|information|credentials?|secrets?|passwords?|"
            r"private[\s_-]+keys?|api[\s_-]+keys?|tokens?|file\s+contents?)"
            r"\b.{0,40}\b(?:externally|outside\s+(?:the\s+)?organization)\b",
        ),
    ),
    _Rule(
        rule_id="PRIVILEGE_ESCALATION_REQUEST",
        category="PRIVILEGE_ESCALATION",
        severity="high",
        reason="The text requests elevated privileges or explicitly names an administrative privilege mechanism.",
        patterns=_patterns(
            r"\bsudo\b",
            r"\b(?:administrator|admin)\s+privileges?\b",
            r"\broot\s+access\b",
            r"\bprivilege\s+escalation\b",
            r"\belevate\s+(?:my\s+)?privileges?\b",
        ),
    ),
    _Rule(
        rule_id="DANGEROUS_ACTION_REQUEST",
        category="DANGEROUS_ACTION",
        severity="high",
        reason="The text requests shell command execution, file deletion, security-setting changes, or disabling security controls.",
        patterns=_patterns(
            r"\b(?:execute|run)\b.{0,30}\b(?:shell|terminal|system)\s+commands?\b",
            r"\b(?:shell|terminal|system)\s+commands?\b.{0,30}"
            r"\b(?:execute|run)\b",
            r"\b(?:delete|remove)\b.{0,30}\b(?:files?|directories|folders)\b",
            r"\b(?:modify|change|alter)\b.{0,30}\bsecurity\s+settings\b",
            r"\bdisable\b.{0,30}\bsecurity\s+(?:controls?|protections?|checks?)\b",
        ),
    ),
)

_ACTION_TEXT_FIELDS = (
    "action_type",
    "source",
    "instruction",
    "tool",
    "resource",
)


def _iter_action_text(action: AgentAction) -> tuple[tuple[str, str], ...]:
    texts: list[tuple[str, str]] = []
    for name in _ACTION_TEXT_FIELDS:
        value = getattr(action, name)
        if isinstance(value, str):
            texts.append((name, value))

    pending: list[tuple[object, str]] = [(action.parameters, "parameters")]
    visited: set[int] = set()
    while pending:
        value, field_name = pending.pop()
        if isinstance(value, str):
            texts.append((field_name, value))
        elif isinstance(value, Mapping):
            identity = id(value)
            if identity in visited:
                continue
            visited.add(identity)
            for key, nested_value in value.items():
                key_label = key if isinstance(key, str) else "key"
                pending.append((nested_value, f"{field_name}.{key_label}"))
        elif isinstance(value, (list, tuple)):
            identity = id(value)
            if identity in visited:
                continue
            visited.add(identity)
            pending.extend(
                (nested_value, f"{field_name}[{index}]")
                for index, nested_value in enumerate(value)
            )

    return tuple(texts)


def evaluate_rules(action: AgentAction) -> tuple[RuleFinding, ...]:
    findings: list[RuleFinding] = []
    action_text = _iter_action_text(action)
    for rule in _RULES:
        for source_field, text in action_text:
            match = None
            for pattern in rule.patterns:
                match = pattern.search(text)
                if match is not None:
                    break
            if match is not None:
                findings.append(
                    RuleFinding(
                        rule_id=rule.rule_id,
                        category=rule.category,
                        matched=True,
                        matched_text=match.group(0),
                        source_field=source_field,
                        severity=rule.severity,
                        reason=rule.reason,
                    )
                )
                break
    return tuple(findings)
