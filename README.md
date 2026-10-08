# TECH HORIZON 2.0 - Integrated Runtime Security Platform

This repository merges the three team workstreams for Problem Statement 27, Runtime Security for AI Agents.

## Architecture

AgentAction → SAGE AI/ML Detection → Deterministic Security Gateway → SecurityDecision → Audit Event → FastAPI → Streamlit Dashboard

### Ownership
- Security & Runtime Protection: `security/`
- AI/ML Detection: `ai_ml/`
- Backend + Dashboard: `backend/`, `dashboard/`
- Common contracts: `shared/`

## Key runtime flow

1. A request is represented as `shared.agent_action.AgentAction`.
2. `ai_ml.inference.detect()` produces advisory `MLDetectionResult`.
3. `security.gateway.SecurityGateway` evaluates deterministic rules plus the ML signal.
4. Risk scoring and policy produce `ALLOW`, `APPROVAL_REQUIRED`, or `BLOCK`.
5. `backend.integration.event_adapter` persists a sanitized audit event.
6. FastAPI and Streamlit expose the runtime history and dashboard.

## Run

Create a Python 3.13 environment, install `requirements.txt`, then:

```bash
python -m pytest -q
python server.py
```

In another terminal:

```bash
streamlit run dashboard/app.py
```

The main runtime evaluation endpoint is `POST /api/evaluate`.

## Security boundary

The gateway evaluates actions but never executes the requested tool, command, or network operation. ML is advisory; deterministic policy remains authoritative.
