"""Pre-execution checks for requested tools and data resources."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from security.rules import RuleFinding
from shared.agent_action import AgentAction

AccessDecision = Literal["ALLOW", "APPROVAL_REQUIRED", "BLOCK"]

_BLOCKED_TOOLS = frozenset(
    {
        "system_shell",
        "shell",
        "terminal",
        "command_executor",
        "shell_executor",
        "powershell",
        "cmd",
        "python_executor",
        "code_executor",
    }
)
_SENSITIVE_RESOURCE = re.compile(
    r"\b(?:passwords?|credentials?|secrets?|tokens?|private[\s_-]+keys?|"
    r"api[\s_-]+keys?|customer[\s_-]+records?|personal\s+data)\b|"
    r"(?<![\w])\.env(?:[.\w-]*)?(?!\w)",
    re.IGNORECASE,
)
_AGENT_TOOL_RESOURCES: dict[str, dict[str, frozenset[str]]] = {
    "ps27-demo-agent": {
        "file_reader": frozenset({"README.md", "source:file:prompt_injection"}),
        "database_reader": frozenset(
            {
                "public_faq",
                "customer_records",
                "source:database:prompt_injection",
            }
        ),
        "api_content_reader": frozenset({"source:api:request"}),
        "email_reader": frozenset({"source:email:sample_message"}),
        "web_reader": frozenset(
            {"public_article", "source:web:sample_page"}
        ),
    },
    "access-test-agent": {
        "database_reader": frozenset({"customer_records"}),
    },
}
_KNOWN_RESOURCES = frozenset(
    resource
    for tools in _AGENT_TOOL_RESOURCES.values()
    for resources in tools.values()
    for resource in resources
) | frozenset({"operating_system", "system_settings"})


@dataclass(frozen=True, slots=True)
class AccessControlOutcome:
    decision: AccessDecision
    reasons: tuple[str, ...]
    finding: RuleFinding | None = None


def evaluate_access(action: AgentAction) -> AccessControlOutcome:
    """Authorize a requested tool/resource without invoking it."""
    normalized_tool = (action.tool or "").strip().lower().replace("-", "_")
    if normalized_tool in _BLOCKED_TOOLS:
        reason = (
            f"Access control blocked unauthorized dangerous tool "
            f"{action.tool!r}; the request was not executed."
        )
        return AccessControlOutcome(
            decision="BLOCK",
            reasons=(reason,),
            finding=RuleFinding(
                rule_id="ACCESS_CONTROL_BLOCKED_TOOL",
                category="DANGEROUS_ACTION",
                matched=True,
                matched_text=action.tool or "",
                source_field="tool",
                severity="high",
                reason=reason,
            ),
        )

    resource = action.resource or ""
    if action.tool:
        authorized_resources = _AGENT_TOOL_RESOURCES.get(
            action.agent_id, {}
        ).get(normalized_tool)
        if authorized_resources is None:
            reason = (
                f"Access control blocked tool {action.tool!r} for agent "
                f"{action.agent_id!r}; the tool is not registered for this identity."
            )
            return AccessControlOutcome(decision="BLOCK", reasons=(reason,))
        if resource not in authorized_resources:
            reason = (
                f"Access control blocked resource {resource!r} for tool "
                f"{action.tool!r} and agent {action.agent_id!r}; the requested "
                "tool/resource combination is not authorized."
            )
            return AccessControlOutcome(decision="BLOCK", reasons=(reason,))
    elif resource and resource not in _KNOWN_RESOURCES:
        reason = (
            f"Access control blocked unknown resource {resource!r}; "
            "the request was not executed."
        )
        return AccessControlOutcome(decision="BLOCK", reasons=(reason,))

    match = _SENSITIVE_RESOURCE.search(resource)
    if match is not None:
        return AccessControlOutcome(
            decision="APPROVAL_REQUIRED",
            reasons=(
                f"Access control requires approval to access sensitive resource "
                f"{resource!r}.",
            ),
        )

    return AccessControlOutcome(
        decision="ALLOW",
        reasons=("Access control allows this tool and non-sensitive resource.",),
    )
