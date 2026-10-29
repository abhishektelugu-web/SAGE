"""Run the real AI/ML + security pipeline and persist the resulting audit event."""

from datetime import datetime, timezone
from dataclasses import replace
import hashlib
import hmac
from http import HTTPStatus
import json
import logging
import os
import uuid

from fastapi import APIRouter, Header, HTTPException, Path, status
from pydantic import BaseModel, Field

from ai_ml.agent_providers import MockAgentProvider
from ai_ml.inference import detect
from backend.integration.event_adapter import event_adapter
from backend.services.event_service import event_service
from security.gateway import SecurityGateway
from security.execution import (
    execute_registered_demo_handler,
    has_registered_demo_handler,
)
from security.scenarios import EVALUATION_SCENARIOS
from security.rules import evaluate_rules
from backend.source_adapters import (
    AdaptedContent,
    EmailSourceNotConfigured,
    EmailSourceUnavailable,
    MAX_CONTENT_LENGTH,
    UNTRUSTED_FIXTURE_TEXT,
    source_adapters,
)
from shared.agent_action import AgentAction, SUPPORTED_SOURCE_CATEGORIES

router = APIRouter(prefix="/api/evaluate", tags=["Runtime Security Evaluation"])
logger = logging.getLogger(__name__)
_SUPPORTED_SOURCES_DESCRIPTION = (
    "Source category. Supported: "
    f"{', '.join(sorted(SUPPORTED_SOURCE_CATEGORIES))}. "
    "Existing non-empty source labels remain accepted."
)


class EvaluateRequest(BaseModel):
    action_id: str = Field(..., min_length=1)
    agent_id: str = Field(..., min_length=1)
    action_type: str = Field(..., min_length=1)
    source: str = Field(default="user", min_length=1, description=_SUPPORTED_SOURCES_DESCRIPTION)
    instruction: str = Field(..., min_length=1)
    trusted_source: bool = True
    tool: str | None = None
    resource: str | None = None
    parameters: dict[str, object] = Field(default_factory=dict)


class SourceEvaluationRequest(BaseModel):
    content: str | None = Field(
        default=None,
        max_length=MAX_CONTENT_LENGTH,
        description="Untrusted content supplied to the API source adapter.",
    )
    action_id: str | None = Field(default=None, min_length=1)


class WorkbenchRequest(BaseModel):
    task: str = Field(..., min_length=1, description="Agent task description")
    source_type: str = Field(default="user", min_length=1, description="Source category")
    source_content: str | None = Field(default=None, description="Untrusted content received from source")
    source_trust: bool = Field(default=False, description="Whether the source is verified trusted")
    requested_action: str = Field(default="auto", description="Operation or 'auto'")
    tool: str | None = Field(default=None, description="Requested tool name")
    resource: str | None = Field(default=None, description="Target resource")
    destination: str | None = Field(default=None, description="Destination URL/server")
    execute: bool = Field(default=False, description="Request execution if allowed")
    agent_id: str = Field(default="ps27-demo-agent", description="Agent identity")
    action_id: str | None = Field(default=None, description="Custom action ID")


@router.post("", status_code=status.HTTP_200_OK)
def evaluate_action(payload: EvaluateRequest):
    action = AgentAction(
        action_id=payload.action_id,
        agent_id=payload.agent_id,
        action_type=payload.action_type,
        source=payload.source,
        instruction=payload.instruction,
        trusted_source=payload.trusted_source,
        timestamp=datetime.now(timezone.utc),
        tool=payload.tool,
        resource=payload.resource,
        parameters=payload.parameters,
    )
    return _evaluate_action(action)


@router.post("/execute", status_code=status.HTTP_200_OK)
def evaluate_and_execute_demo_action(payload: EvaluateRequest):
    """Evaluate first, then run only a registered safe handler for ALLOW."""
    action = AgentAction(
        action_id=payload.action_id,
        agent_id=payload.agent_id,
        action_type=payload.action_type,
        source=payload.source,
        instruction=payload.instruction,
        trusted_source=payload.trusted_source,
        timestamp=datetime.now(timezone.utc),
        tool=payload.tool,
        resource=payload.resource,
        parameters=payload.parameters,
    )
    return _evaluate_action(action, execute=True)


@router.post("/sources", status_code=status.HTTP_200_OK)
def evaluate_all_source_adapters():
    """Evaluate untrusted fixture content from each of the five adapters."""
    results = [
        _evaluate_source(source, api_content=UNTRUSTED_FIXTURE_TEXT)
        for source in sorted(SUPPORTED_SOURCE_CATEGORIES)
    ]
    return {"results": results}


@router.post("/sources/{source}", status_code=status.HTTP_200_OK)
def evaluate_source_adapter(source: str, payload: SourceEvaluationRequest):
    """Load content through one source adapter and pass it to the evaluator."""
    if source not in SUPPORTED_SOURCE_CATEGORIES:
        raise HTTPException(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail=f"Unsupported source category: {source!r}.",
        )
    if source == "api" and payload.content is None:
        raise HTTPException(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="API source evaluation requires request content.",
        )
    if source != "api" and payload.content is not None:
        raise HTTPException(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="Caller-supplied content is only accepted by the API source adapter.",
        )
    return _evaluate_source(
        source,
        api_content=payload.content,
        action_id=payload.action_id,
    )


@router.post("/email/{uid}", status_code=status.HTTP_200_OK)
def evaluate_imap_email(
    uid: str = Path(..., pattern=r"^[0-9]{1,20}$"),
    email_source_token: str | None = Header(default=None, alias="X-Email-Source-Token"),
):
    """Read one configured IMAP message without changing its mailbox state."""
    expected_token = os.getenv("TRACEGUARD_EMAIL_SOURCE_TOKEN", "")
    if not expected_token:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The read-only email source is not enabled.",
        )
    if not email_source_token or not hmac.compare_digest(
        email_source_token, expected_token
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A valid email source access token is required.",
        )

    try:
        adapted = source_adapters.read_imap_email(uid)
    except EmailSourceNotConfigured as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    except EmailSourceUnavailable as exc:
        logger.warning("IMAP email UID %s could not be evaluated: %s", uid, exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(exc),
        ) from exc
    return _evaluate_adapted_source(adapted, action_id=None)


@router.post("/scenarios", status_code=status.HTTP_200_OK)
def evaluate_scenarios():
    """Evaluate and audit each predefined scenario; never execute requested tools."""
    results = []
    for scenario in EVALUATION_SCENARIOS:
        scenario_input = {
            "action_type": scenario.action_type,
            "source": scenario.source,
            "instruction": scenario.instruction,
            "tool": scenario.tool,
            "resource": scenario.resource,
            "parameters": dict(scenario.parameters),
            "trusted_source": scenario.trusted_source,
            "execute": False,
        }
        if scenario.malformed_proposal:
            from ai_ml.agent_providers import (
                ProviderRequestError,
                parse_openai_compatible_proposal,
            )

            malformed_response = {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "action_type": "",
                                    "tool": "file_reader",
                                    "resource": "README.md",
                                    "parameters": {},
                                }
                            )
                        }
                    }
                ]
            }
            try:
                parse_openai_compatible_proposal(malformed_response)
            except ProviderRequestError:
                actual_result = "REJECTED"
            else:
                actual_result = "ACCEPTED"
            results.append(
                {
                    "scenario_id": scenario.scenario_id,
                    "scenario": scenario.name,
                    "input": {"mock_provider_response": malformed_response},
                    "expected_result": scenario.expected_result,
                    "actual_result": actual_result,
                    "passed": actual_result == scenario.expected_result,
                    "explanation": scenario.explanation,
                    "decision": actual_result,
                    "execution_status": "not_requested",
                    "event_id": None,
                    "audit_status": "not_created_invalid_provider_proposal",
                    "threat_types": [],
                    "reasons": [
                        "The mocked provider response failed proposal validation before security evaluation."
                    ],
                }
            )
            continue

        action_id = f"{scenario.scenario_id}-{uuid.uuid4().hex[:8].upper()}"
        action = scenario.build_action(action_id, datetime.now(timezone.utc))
        result = _evaluate_action(action)
        result["scenario_id"] = scenario.scenario_id
        result["scenario"] = scenario.name
        result["input"] = scenario_input
        result["expected_result"] = scenario.expected_result
        result["actual_result"] = result["decision"]
        result["passed"] = result["actual_result"] == scenario.expected_result
        result["explanation"] = scenario.explanation
        result["audit_status"] = "recorded"
        if scenario.scenario_id == "PS27-CANARY-EXPOSURE":
            from backend.services.event_service import event_service

            canary = "TRACEGUARD-CANARY-R3-7F2A"
            public_result = {
                key: value for key, value in result.items() if key != "input"
            }
            audit_event = event_service.get_event(result["event_id"])
            audit_payload = audit_event.model_dump() if audit_event else {}
            response_exposed = canary in json.dumps(public_result, default=str)
            audit_exposed = canary in json.dumps(audit_payload, default=str)
            result["data_leakage_analysis"] = {
                "canary_exposed_in_result": response_exposed,
                "canary_exposed_in_audit": audit_exposed,
                "passed": not response_exposed and not audit_exposed,
            }
        results.append(result)
    passed_count = sum(result["passed"] for result in results)
    no_execution = all(
        result.get("execution_status") == "not_requested" for result in results
    )
    decision_counts: dict[str, int] = {}
    for result in results:
        decision = str(result.get("actual_result", "UNKNOWN"))
        decision_counts[decision] = decision_counts.get(decision, 0) + 1
    return {
        "results": results,
        "metrics": {
            "scenario_count": len(results),
            "passed_count": passed_count,
            "failed_count": len(results) - passed_count,
            "pass_rate_percent": round(
                passed_count * 100 / len(results), 1
            ) if results else 0.0,
            "actual_result_counts": decision_counts,
            "no_execution_verified": no_execution,
        },
    }


def _evaluate_source(
    source: str,
    *,
    api_content: str | None = None,
    action_id: str | None = None,
) -> dict[str, object]:
    adapted = source_adapters.read(source, api_content=api_content)
    return _evaluate_adapted_source(adapted, action_id=action_id)


def _evaluate_adapted_source(
    adapted: AdaptedContent, *, action_id: str | None
) -> dict[str, object]:
    action = AgentAction(
        action_id=action_id or f"SOURCE-{adapted.source.upper()}-{uuid.uuid4().hex[:8].upper()}",
        agent_id="ps27-demo-agent",
        action_type=f"read_{adapted.source}_content",
        source=adapted.source,
        instruction=adapted.content,
        trusted_source=False,
        timestamp=datetime.now(timezone.utc),
        tool=adapted.tool,
        resource=adapted.resource,
    )
    result = _evaluate_action(action)
    result["source_adapter"] = True
    return result


def _evaluate_action(
    action: AgentAction,
    *,
    execute: bool = False,
) -> dict[str, object]:
    rule_findings = evaluate_rules(action)
    ml_result = detect(action)
    decision = SecurityGateway().evaluate(action, ml_result=ml_result)
    execution_status = "not_requested"
    execution_result: str | None = None
    if execute:
        if decision.decision == "ALLOW":
            if has_registered_demo_handler(action):
                execution_result = execute_registered_demo_handler(action)
                execution_status = "executed"
            else:
                decision = replace(
                    decision,
                    decision="BLOCK",
                    access_decision="BLOCK",
                    reasons=(
                        *decision.reasons,
                        "Execution blocked because no registered safe demonstration handler matches this tool and resource.",
                    ),
                )
                execution_status = "not_executed_blocked"
        elif decision.decision == "APPROVAL_REQUIRED":
            execution_status = "not_executed_approval_required"
        else:
            execution_status = "not_executed_blocked"
    event = event_adapter.ingest(
        action,
        ml_result,
        decision,
        execution_status=execution_status,
    )
    response: dict[str, object] = {
        "action_id": action.action_id,
        "agent_id": action.agent_id,
        "action_type": action.action_type,
        "source": action.source,
        "trusted_source": action.trusted_source,
        "tool": action.tool,
        "resource": action.resource,
        "decision": decision.decision,
        "access_decision": decision.access_decision,
        "risk_score": decision.risk_score,
        "data_leakage_detected": decision.data_leakage_detected,
        "threat_types": decision.threat_types,
        "reasons": decision.reasons,
        "detections": [
            {
                "rule_id": finding.rule_id,
                "category": finding.category,
                "severity": finding.severity,
                "explanation": finding.reason,
                "evidence": {
                    "field": (
                        finding.source_field.split(".", 1)[0].split("[", 1)[0]
                    ),
                    "rule_id": finding.rule_id,
                },
            }
            for finding in rule_findings
        ],
        "execution_status": execution_status,
        "ml": {
            "is_malicious": ml_result.is_malicious,
            "confidence": ml_result.confidence,
            "threat_type": ml_result.threat_type,
            "reason": ml_result.reason,
            "model_name": ml_result.model_name,
        },
        "event_id": event.event_id,
    }
    if execute and decision.decision == "APPROVAL_REQUIRED":
        approval_id = uuid.uuid4().hex
        action_record = {
            "action_id": action.action_id,
            "agent_id": action.agent_id,
            "action_type": action.action_type,
            "source": action.source,
            "instruction": action.instruction,
            "trusted_source": action.trusted_source,
            "timestamp": action.timestamp.isoformat(),
            "tool": action.tool,
            "resource": action.resource,
            "parameters": dict(action.parameters),
        }
        event_service.db.create_approval(
            approval_id=approval_id,
            event_id=event.event_id,
            action_json=json.dumps(action_record),
            requested_at=datetime.now(timezone.utc).isoformat(),
        )
        response["approval_id"] = approval_id
    if execution_result is not None:
        response["execution_result"] = execution_result
    return response


@router.post("/workbench", status_code=status.HTTP_200_OK)
def evaluate_workbench(payload: WorkbenchRequest) -> dict[str, object]:
    """Evaluate an agent task and source content from the Agent Security Workbench."""
    norm_source = payload.source_type.strip().lower()
    if norm_source in ("website", "url", "web page"):
        norm_source = "web"
    elif norm_source in ("api response", "api_response"):
        norm_source = "api"
    elif norm_source in ("user input", "user_input"):
        norm_source = "user"
    elif norm_source not in SUPPORTED_SOURCE_CATEGORIES and norm_source != "user":
        norm_source = "user"

    task_clean = payload.task.strip()
    source_content_clean = (payload.source_content or "").strip()

    req_act = (payload.requested_action or "auto").strip().lower()
    tool = payload.tool.strip() if payload.tool else None
    resource = payload.resource.strip() if payload.resource else None
    destination = payload.destination.strip() if payload.destination else None
    action_type = "read"

    if req_act in ("read_file", "read a public document", "read public document"):
        tool = tool or "file_reader"
        resource = resource or "README.md"
        action_type = "read_file"
    elif req_act in ("read_records", "read sensitive customer records", "read customer records"):
        tool = tool or "database_reader"
        resource = resource or "customer_records"
        action_type = "read_records"
    elif req_act in ("send_data", "send data to an external destination", "send external"):
        tool = tool or "api_client"
        resource = resource or "customer_records"
        action_type = "send_data"
        if not destination:
            destination = "https://external.example"
    elif req_act in ("execute", "execute a shell command", "shell command", "system_shell"):
        tool = tool or "system_shell"
        resource = resource or "operating_system"
        action_type = "execute"
    elif req_act in ("write", "write or modify a resource", "modify resource"):
        tool = tool or "file_writer"
        resource = resource or "system_settings"
        action_type = "write"
    else:
        combined_prompt = f"{task_clean} {source_content_clean}"
        proposal = MockAgentProvider().propose_tool_call(combined_prompt)
        tool = tool or proposal.tool
        resource = resource or proposal.resource
        action_type = proposal.action_type
        if not destination and "destination" in proposal.parameters:
            destination = str(proposal.parameters["destination"])

    if source_content_clean:
        instruction = f"Task: {task_clean}\nSource Content: {source_content_clean}"
        content_hash = hashlib.sha256(source_content_clean.encode("utf-8")).hexdigest()[:16]
        content_preview = (source_content_clean[:140] + "...") if len(source_content_clean) > 140 else source_content_clean
    else:
        instruction = task_clean
        content_hash = hashlib.sha256(task_clean.encode("utf-8")).hexdigest()[:16]
        content_preview = (task_clean[:140] + "...") if len(task_clean) > 140 else task_clean

    parameters: dict[str, object] = {
        "task": task_clean,
        "source_type": norm_source,
        "source_trust": payload.source_trust,
        "source_content_hash": content_hash,
        "source_content_preview": content_preview,
    }
    if destination:
        parameters["destination"] = destination

    action_id = payload.action_id or f"WB-{uuid.uuid4().hex[:8].upper()}"
    agent_id = payload.agent_id.strip() if payload.agent_id else "ps27-demo-agent"

    action = AgentAction(
        action_id=action_id,
        agent_id=agent_id,
        action_type=action_type,
        source=norm_source,
        instruction=instruction,
        trusted_source=payload.source_trust,
        timestamp=datetime.now(timezone.utc),
        tool=tool,
        resource=resource,
        parameters=parameters,
    )

    result = _evaluate_action(action, execute=payload.execute)
    attack_path = _build_attack_path(
        action,
        result,
        payload.source_trust,
        content_hash,
        content_preview,
        destination,
    )
    recommended_response = _get_recommended_response(
        str(result["decision"]),
        str(result["execution_status"]),
    )

    result["task"] = task_clean
    result["source_type"] = norm_source
    result["source_content_preview"] = content_preview
    result["source_content_hash"] = content_hash
    result["destination"] = destination or ""
    result["attack_path"] = attack_path
    result["recommended_response"] = recommended_response
    result["policy_explanation"] = "; ".join(result.get("reasons", []))
    return result


def _build_attack_path(
    action: AgentAction,
    result: dict[str, object],
    source_trust: bool,
    content_hash: str,
    content_preview: str,
    destination: str | None,
) -> list[dict[str, object]]:
    threat_types = [str(t) for t in result.get("threat_types", [])]
    decision = str(result.get("decision", "ALLOW"))
    access_decision = str(result.get("access_decision", "ALLOW"))
    execution_status = str(result.get("execution_status", "not_requested"))
    risk_score = result.get("risk_score", 0)
    ml_data = result.get("ml", {}) if isinstance(result.get("ml"), dict) else {}

    # Step 1: Source Ingestion & Provenance
    step1_title = f"{action.source.upper()} SOURCE INGESTION"
    step1_desc = (
        f"Content ingested from {action.source} origin. "
        f"Provenance Trust: {'TRUSTED' if source_trust else 'UNTRUSTED'}. "
        f"Integrity Hash: SHA-256 [{content_hash}]."
    )
    step1 = {
        "step": 1,
        "stage": "Source Ingestion",
        "title": step1_title,
        "nature": "Observed event",
        "status": "trusted" if source_trust else "untrusted",
        "summary": step1_desc,
        "details": {
            "source": action.source,
            "trusted_source": source_trust,
            "content_hash": content_hash,
            "preview": content_preview,
        },
    }

    # Step 2: Content Threat & Injection Analysis
    has_injection = "PROMPT_INJECTION" in threat_types
    if has_injection:
        step2_title = "UNTRUSTED INSTRUCTION / PROMPT INJECTION IDENTIFIED"
        step2_status = "threat_detected"
        step2_desc = (
            f"SAGE ML & deterministic rule inspection detected prompt injection attempt "
            f"(Confidence: {float(ml_data.get('confidence', 0.0)):.2f}). Instruction override patterns flagged."
        )
    elif threat_types:
        step2_title = f"SECURITY THREAT PATTERNS DETECTED ({', '.join(threat_types)})"
        step2_status = "threat_detected"
        step2_desc = f"Identified threat categories: {', '.join(threat_types)}."
    else:
        step2_title = "BENIGN INSTRUCTION VERIFIED"
        step2_status = "clean"
        step2_desc = "No prompt injection, exfiltration, or escalation patterns detected in instruction or content."

    step2 = {
        "step": 2,
        "stage": "Threat Analysis",
        "title": step2_title,
        "nature": "Detected threat" if threat_types else "Observed event",
        "status": step2_status,
        "summary": step2_desc,
        "details": {
            "threat_types": threat_types,
            "ml_model": ml_data.get("model_name"),
            "ml_confidence": ml_data.get("confidence", 0.0),
            "reasons": result.get("reasons", []),
        },
    }

    # Step 3: Proposed Agent Action & Access Control
    step3_title = f"ACTION PROPOSAL: {action.action_type.upper()} ({action.tool or 'no-tool'} -> {action.resource or 'no-resource'})"
    if access_decision == "BLOCK":
        step3_status = "blocked"
        step3_desc = f"Access control BLOCKED tool {action.tool!r} / resource {action.resource!r}. Unauthorized operation."
    elif access_decision == "APPROVAL_REQUIRED":
        step3_status = "approval_required"
        step3_desc = f"Access control flagged sensitive resource {action.resource!r}. Least-privilege policy requires human supervisor authorization."
    else:
        step3_status = "authorized"
        step3_desc = f"Access control verified: agent identity {action.agent_id!r} is authorized for tool {action.tool!r}."

    step3 = {
        "step": 3,
        "stage": "Action Authorization",
        "title": step3_title,
        "nature": "Observed event",
        "status": step3_status,
        "summary": step3_desc,
        "details": {
            "action_type": action.action_type,
            "tool": action.tool,
            "resource": action.resource,
            "destination": destination,
            "access_decision": access_decision,
        },
    }

    # Step 4: Policy Decision & Risk Scoring
    step4_title = f"POLICY VERDICT: {decision}"
    step4_desc = (
        f"Evaluated risk score: {risk_score}/100. "
        f"Gateway synthesized access control + ML + deterministic threat rules -> Final verdict {decision}."
    )
    step4 = {
        "step": 4,
        "stage": "Policy Enforcement",
        "title": step4_title,
        "nature": "Final policy decision",
        "status": decision.lower(),
        "summary": step4_desc,
        "details": {
            "decision": decision,
            "risk_score": risk_score,
            "data_leakage_detected": result.get("data_leakage_detected", False),
            "reasons": result.get("reasons", []),
        },
    }

    # Step 5: Runtime Execution Boundary
    if execution_status == "executed":
        step5_title = "RUNTIME GATEWAY: EXECUTED (SAFE DEMO HANDLER)"
        step5_status = "executed"
        step5_desc = "Safe demo handler invoked within strict runtime sandbox. Output returned safely."
    elif execution_status == "not_executed_blocked":
        step5_title = "RUNTIME GATEWAY: EXECUTION PREVENTED (BLOCKED)"
        step5_status = "blocked"
        step5_desc = "Runtime containment enforced: action terminated at security boundary. No system access or command run."
    elif execution_status == "not_executed_approval_required":
        step5_title = "RUNTIME GATEWAY: EXECUTION PREVENTED (APPROVAL PENDING)"
        step5_status = "approval_required"
        step5_desc = "Execution held pending human authorization. No unapproved access permitted."
    else:
        step5_title = "RUNTIME GATEWAY: DRY-RUN AUDITED (NOT REQUESTED)"
        step5_status = "not_requested"
        step5_desc = "Execution was not requested; evaluated in dry-run inspection mode and recorded in audit ledger."

    step5 = {
        "step": 5,
        "stage": "Execution Boundary",
        "title": step5_title,
        "nature": "Observed event",
        "status": step5_status,
        "summary": step5_desc,
        "details": {
            "execution_status": execution_status,
            "execution_result": result.get("execution_result"),
            "event_id": result.get("event_id"),
        },
    }

    return [step1, step2, step3, step4, step5]


def _get_recommended_response(decision: str, execution_status: str) -> str:
    if decision == "ALLOW":
        if execution_status == "executed":
            return "Action passed all security policies and executed through approved safe demo handler. No remedial action needed."
        return "The action is fully compliant with runtime security policies. Execution can safely proceed if requested."
    elif decision == "APPROVAL_REQUIRED":
        return "Action requires supervisor approval. Human security reviewer must evaluate the justification before unlocking access to sensitive customer records or resources."
    else:
        return "Mandatory block enforced. Malicious proposal discarded; tool execution halted at gateway boundary. Incident logged to persistent audit store for forensic review."
