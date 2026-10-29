"""Registry of safe, deterministic handlers for the execution-gateway demo."""

from __future__ import annotations

from collections.abc import Callable

from shared.agent_action import AgentAction

DemoHandler = Callable[[AgentAction], str]


def _read_public_readme(_action: AgentAction) -> str:
    return "Safe demonstration README content."


def _read_public_faq(_action: AgentAction) -> str:
    return "Demo FAQ: contact support for help with your account."


def _read_synthetic_customer_record(_action: AgentAction) -> str:
    return (
        'Synthetic demonstration data only: '
        '{"record_id":"DEMO-001","status":"active","balance":0.00}; '
        "no live database was queried."
    )


DEMO_HANDLERS: dict[tuple[str, str], DemoHandler] = {
    ("file_reader", "README.md"): _read_public_readme,
    ("database_reader", "public_faq"): _read_public_faq,
    ("database_reader", "customer_records"): _read_synthetic_customer_record,
}


def has_registered_demo_handler(action: AgentAction) -> bool:
    return (action.tool or "", action.resource or "") in DEMO_HANDLERS


def execute_registered_demo_handler(action: AgentAction) -> str:
    """Run only an explicitly registered tool/resource handler."""
    handler = DEMO_HANDLERS.get((action.tool or "", action.resource or ""))
    if handler is None:
        raise LookupError(
            f"No safe demonstration handler is registered for "
            f"{action.tool!r} and {action.resource!r}."
        )
    return handler(action)
