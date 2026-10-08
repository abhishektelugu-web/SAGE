"""Input contract for actions submitted to the security gateway."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime


@dataclass(slots=True)
class AgentAction:
    """Describe an AI agent action request for evaluation by the gateway."""

    action_id: str
    agent_id: str
    action_type: str
    source: str
    instruction: str
    trusted_source: bool
    timestamp: datetime
    tool: str | None = None
    resource: str | None = None
    parameters: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in (
            "action_id",
            "agent_id",
            "action_type",
            "source",
            "instruction",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")

        for name in ("tool", "resource"):
            value = getattr(self, name)
            if value is not None and (
                not isinstance(value, str) or not value.strip()
            ):
                raise ValueError(f"{name} must be None or a non-empty string")

        if not isinstance(self.trusted_source, bool):
            raise TypeError("trusted_source must be a bool")
        if not isinstance(self.timestamp, datetime):
            raise TypeError("timestamp must be a datetime")
        if not isinstance(self.parameters, Mapping):
            raise TypeError("parameters must be a mapping")

    @property
    def destination(self) -> str:
        """Return a destination-like parameter for ML detectors."""
        for key in ("destination", "url", "endpoint"):
            value = self.parameters.get(key)
            if isinstance(value, str):
                return value
        return ""

    def get_all_text(self) -> str:
        """Return textual action content for the AI/ML detector."""
        parts: list[str] = [
            self.action_type,
            self.source,
            self.instruction,
            self.tool or "",
            self.resource or "",
            self.destination,
        ]
        parts.extend(
            value for value in self.parameters.values() if isinstance(value, str)
        )
        return " ".join(part for part in parts if part)
