from datetime import datetime, timezone
import pytest
from shared.agent_action import AgentAction


def make_action(**overrides: object) -> AgentAction:
    values: dict[str, object] = {
        "action_id": "action-123",
        "agent_id": "agent-456",
        "action_type": "read",
        "source": "user",
        "instruction": "Read the project README",
        "trusted_source": True,
        "timestamp": datetime(2026, 10, 8, 12, 0, tzinfo=timezone.utc),
    }
    values.update(overrides)
    return AgentAction(**values)  # type: ignore[arg-type]


def test_creates_valid_agent_action() -> None:
    action = make_action()
    assert action.action_id == "action-123"
    assert action.agent_id == "agent-456"
    assert action.instruction == "Read the project README"


def test_required_fields_cannot_be_omitted() -> None:
    with pytest.raises(TypeError):
        AgentAction()  # type: ignore[call-arg]

@pytest.mark.parametrize("field_name", ("action_id", "agent_id", "action_type", "source", "instruction"))
def test_required_text_fields_cannot_be_empty(field_name: str) -> None:
    with pytest.raises(ValueError, match=field_name):
        make_action(**{field_name: "  "})


def test_optional_fields_and_parameters_are_independent() -> None:
    action = make_action(parameters={"path": "README.md"})
    another = make_action()
    assert action.tool is None and action.resource is None
    assert action.parameters is not another.parameters


def test_timestamp_is_preserved() -> None:
    timestamp = datetime(2026, 10, 8, 12, 0, tzinfo=timezone.utc)
    assert make_action(timestamp=timestamp).timestamp is timestamp


@pytest.mark.parametrize(
    ("field_name", "value", "error"),
    (("trusted_source", "yes", TypeError), ("timestamp", "now", TypeError), ("parameters", [], TypeError)),
)
def test_invalid_field_values_are_rejected(field_name: str, value: object, error: type[Exception]) -> None:
    with pytest.raises(error):
        make_action(**{field_name: value})
