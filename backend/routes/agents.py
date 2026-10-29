"""AI proposal endpoints that always evaluate through the runtime security path."""

from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field, field_validator

from ai_ml.agent_providers import (
    ProviderConfigurationError,
    ProviderRequestError,
    get_agent_provider,
)
from backend.routes.evaluate import _evaluate_action
from shared.agent_action import AgentAction

router = APIRouter(prefix="/api/agents", tags=["AI Agent Integration"])


class AgentProposalRequest(BaseModel):
    action_id: str = Field(..., min_length=1)
    agent_id: str = Field(..., min_length=1)
    instruction: str = Field(..., min_length=1, max_length=4000)
    provider: Literal["mock", "openai-compatible"] = "mock"
    source: str = Field(default="api", min_length=1)
    execute: bool = False

    @field_validator("action_id", "agent_id", "instruction", "source")
    @classmethod
    def reject_blank_values(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("value must be a non-empty string")
        return value


@router.post("/propose", status_code=status.HTTP_200_OK)
def propose_agent_action(payload: AgentProposalRequest) -> dict[str, object]:
    """Ask a provider for a proposal, then evaluate it through the existing gateway."""
    try:
        provider = get_agent_provider(payload.provider)
        proposal = provider.propose_tool_call(payload.instruction)
    except ProviderConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    except ProviderRequestError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(exc),
        ) from exc

    action = AgentAction(
        action_id=payload.action_id,
        agent_id=payload.agent_id,
        action_type=proposal.action_type,
        source=payload.source,
        instruction=payload.instruction,
        trusted_source=False,
        timestamp=datetime.now(timezone.utc),
        tool=proposal.tool,
        resource=proposal.resource,
        parameters=proposal.parameters,
    )
    result = _evaluate_action(action, execute=payload.execute)
    result["provider"] = payload.provider
    result["proposal"] = {
        "action_type": proposal.action_type,
        "tool": proposal.tool,
        "resource": proposal.resource,
        "parameters": dict(proposal.parameters),
    }
    return result
