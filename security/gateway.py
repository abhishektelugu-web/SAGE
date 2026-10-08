"""Security evaluation boundary for AgentAction requests."""

from __future__ import annotations

from collections.abc import Callable

from security.decision import SecurityDecision, build_security_decision
from security.ml_adapter import ml_result_to_finding
from security.policy import evaluate_policy
from security.risk import calculate_risk
from security.rules import RuleFinding, evaluate_rules
from shared.agent_action import AgentAction
from shared.ml_result import MLDetectionResult


class SecurityGateway:
    """Orchestrate deterministic security evaluation plus optional ML signals."""

    def __init__(
        self,
        detector: Callable[[AgentAction], MLDetectionResult] | None = None,
    ) -> None:
        self._detector = detector

    def evaluate(
        self,
        action: AgentAction,
        *,
        ml_result: MLDetectionResult | None = None,
    ) -> SecurityDecision:
        """Evaluate an action through rules, optional ML, risk, policy, and decision."""
        findings = list(evaluate_rules(action))
        if ml_result is None and self._detector is not None:
            ml_result = self._detector(action)
        ml_finding = ml_result_to_finding(ml_result)
        if ml_finding is not None:
            findings.append(ml_finding)

        risk_assessment = calculate_risk(tuple(findings))
        policy_outcome = evaluate_policy(risk_assessment)
        return build_security_decision(action, risk_assessment, policy_outcome)
