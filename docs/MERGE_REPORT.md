# Merge Report

## Canonical ownership

- `security/` is the authoritative Security & Runtime Protection implementation developed in the current workstream.
- `ai_ml/` is the Member 2 SAGE detection implementation from the uploaded archive.
- `backend/` and `dashboard/` are the Member 3 backend/dashboard implementation from the uploaded archive.
- `shared/agent_action.py`, `shared/threats.py`, and `shared/ml_result.py` are the common runtime contracts.

## Integration choices

The uploaded teammate archives contained overlapping implementations of `AgentAction`, `MLDetectionResult`, `ThreatCategory`, and `SecurityGateway`. Those duplicate implementations were not merged blindly.

The canonical security contracts were retained, while Member 2's SAGE detector was adapted to consume the canonical `AgentAction` and return the canonical `MLDetectionResult` with a small compatibility surface for legacy SAGE fields (`reason` and `ThreatType`).

Member 3's backend adapter was updated to consume the canonical security result. The backend API still has its own Pydantic response schema under `backend/schemas/` and does not own security decisions.

## Runtime flow

`AgentAction -> SAGE detect() -> deterministic SecurityGateway -> Risk/Policy -> SecurityDecision -> EventAdapter -> SQLite -> FastAPI -> Streamlit`

ML detection is advisory. The deterministic security policy remains the final decision authority.

## Validation

The merged project passes the focused security, backend, and integration test suite with **73 passing tests** in the current environment.

A real `/api/evaluate` test was also exercised for a benign request and a full prompt-injection + sensitive-resource + external-exfiltration attack. The benign request returned `ALLOW` / `0`, and the attack returned `BLOCK` / `100`.

The current environment used for validation does not have Streamlit installed, so the dashboard process itself was not launched here. The project declares Streamlit in `requirements.txt`.
