# TRACEGUARD — AI AGENT RUNTIME SECURITY PLATFORM
**Tagline:** *"Inspect every instruction. Control every action. Prove every decision."*

**Project:** Problem Statement 27 (PS-27) — Runtime Security for AI Agents
**Category:** College Hackathon Jury Edition • Defense-in-Depth AI Operations

---

## 1. Overview & Architecture

TRACEGUARD provides a deterministic, rule-based security runtime boundary with advisory detector signals for AI-agent actions. It evaluates source provenance, requested tools and resources, threat patterns, and risk policy before any allow-listed demo execution, and records outcomes in a persistent SQLite audit log.

```
+---------------------------------------------------------------------------------------+
|                                    TRACEGUARD RUNTIME                                 |
+---------------------------------------------------------------------------------------+
|  User Task & Untrusted Source Content (Email, Web, File, API, Database, User Input)   |
|                                         |                                             |
|                                         v                                             |
|                             Input Validation & Provenance                             |
|                                         |                                             |
|                                         v                                             |
|                         Agent Tool Call Proposal (Mock / AI)                          |
|                                         |                                             |
|                                         v                                             |
|                       SAGE ML Detection & Deterministic Rules                         |
|                                         |                                             |
|                                         v                                             |
|                          Access Control & Least-Privilege                             |
|                                         |                                             |
|                                         v                                             |
|                               Composite Risk Scoring                                  |
|                                         |                                             |
|                                         v                                             |
|                 Policy Engine (ALLOW | APPROVAL_REQUIRED | BLOCK)                      |
|                                         |                                             |
|                                         v                                             |
|               Runtime Execution Boundary (Allow-listed Safe Handlers)                 |
|                                         |                                             |
|                                         v                                             |
|                     Persistent SQLite Audit Ledger (sage.db)                          |
+---------------------------------------------------------------------------------------+
```

### Module Architecture
- **Security Gateway & Enforcement:** [`security/`](file:///c:/users/umez/OneDrive/文档/New%20folder%20(2)/TECH_HORIZON_2.0_MERGED/TECH_HORIZON_2.0_MERGED/security) — Deterministic rules, access control, risk scoring, policies, and safe execution registry.
- **AI/ML Threat Intelligence:** [`ai_ml/`](file:///c:/users/umez/OneDrive/文档/New%20folder%20(2)/TECH_HORIZON_2.0_MERGED/TECH_HORIZON_2.0_MERGED/ai_ml) — SAGE detection engine, prompt injection classifiers, and provider adapters (`MockAgentProvider`, `OpenAICompatibleProvider`).
- **Backend & APIs:** [`backend/`](file:///c:/users/umez/OneDrive/文档/New%20folder%20(2)/TECH_HORIZON_2.0_MERGED/TECH_HORIZON_2.0_MERGED/backend) — FastAPI REST endpoints, SQLite persistence, and event adapters.
- **Operations Workbench & Dashboard:** [`dashboard/`](file:///c:/users/umez/OneDrive/文档/New%20folder%20(2)/TECH_HORIZON_2.0_MERGED/TECH_HORIZON_2.0_MERGED/dashboard) — Streamlit operations center with dark cyber-ops UI, workbench, attack chain explorer, red-team lab, and telemetry.
- **Shared Contracts:** [`shared/`](file:///c:/users/umez/OneDrive/文档/New%20folder%20(2)/TECH_HORIZON_2.0_MERGED/TECH_HORIZON_2.0_MERGED/shared) — Unified dataclasses for `AgentAction`, `SecurityEvent`, and `MLDetectionResult`.

---

## 2. Core Platform Capabilities

### A. Agent Security Workbench
Operate the entire security evaluation live from the UI without manual JSON:
- **Agent Task:** High-level objective assigned to the agent.
- **Source Type:** Provenance origin (Email, Web, File, API response, Database, User input). Built-in examples are fixtures or simulated content, not live service connectors.
- **Source Content:** Raw ingested content with live prompt-injection detection and `.txt`/`.md` document upload support (validated, max 50KB).
- **Requested Action & Target Resource:** Configurable tools and resources (`README.md`, `customer_records`, `operating_system`, etc.).
- **Execution Mode:** Dry-run analysis by default; safe execution strictly gated to allow-listed demo handlers.

### B. Attack Path & Provenance Explorer
Visual connected flow generated from actual evaluation evidence:
1. **Source Ingestion:** Records origin, trust status, and SHA-256 integrity hash.
2. **Threat Analysis:** Highlights prompt injection, exfiltration, or escalation signals with ML confidence.
3. **Proposed Action:** Evaluates agent tool call against registered identity permissions.
4. **Policy Enforcement:** Displays calculated risk score (0–100) and threshold reasoning.
5. **Runtime Boundary:** Verifies whether execution was safely run, blocked, or held for human review.

### C. Red-Team Security Lab
The repeatable API evaluation contains ten cases. Each is evaluated with
`execute=false`; only the malformed provider-response case has no audit event
because it is rejected before gateway evaluation.
1. **Safe public read:** Registered README read -> `ALLOW`.
2. **Prompt injection:** Untrusted instruction override -> `BLOCK`.
3. **Sensitive data:** `customer_records` -> `APPROVAL_REQUIRED`.
4. **Data exfiltration:** Sensitive records sent externally -> `BLOCK`.
5. **Privilege escalation:** Administrative privilege request -> `BLOCK`.
6. **Dangerous tool:** `system_shell` request -> `BLOCK`.
7. **Unauthorized resource:** Unlisted file resource -> `BLOCK`.
8. **Synthetic canary exposure:** Customer-record read -> `APPROVAL_REQUIRED`; canary leakage is checked.
9. **Policy bypass:** Untrusted instruction attempts authorization bypass -> `BLOCK`.
10. **Malformed provider proposal:** Synthetic invalid response -> `REJECTED`.

The workbench's preloaded scenarios also include a provenance-gating example.
Their execution flag defaults to false. Do not enable execution during a
demonstration.

---

## 3. Quickstart & Running Locally

### Prerequisites
- Python 3.10+ (Tested on Python 3.13)
- Virtual environment with dependencies installed:
  ```bash
  pip install -r requirements.txt
  ```

### Run Tests
```bash
python -m pytest
```
The Round 3 completion run and measured test count are recorded in
[`docs/TECHNICAL_REPORT.md`](./docs/TECHNICAL_REPORT.md); rerun the command above
to reproduce the current result.

### Start Backend Server
Configure Microsoft Entra API and dashboard app registrations to enable approval review:
```powershell
$env:TRACEGUARD_ENTRA_TENANT_ID = "<tenant-guid>"
$env:TRACEGUARD_ENTRA_AUDIENCE = "<traceguard-api-app-client-guid>"
$env:TRACEGUARD_ENTRA_CLIENT_ID = "<dashboard-public-client-app-id>"
$env:TRACEGUARD_ENTRA_API_SCOPE = "api://<traceguard-api-app-client-guid>/access_as_user"
```

```bash
python server.py
```
- API Base: `http://127.0.0.1:8000`
- Swagger Interactive Docs: `http://127.0.0.1:8000/docs`
- Health Check: `http://127.0.0.1:8000/health`

### Start Streamlit Operations Dashboard
In a second terminal:
```bash
streamlit run dashboard/app.py
```
- Local URL: `http://localhost:8501`
- Browser visits to `http://127.0.0.1:8000/` redirect to the dashboard
  (`TRACEGUARD_DASHBOARD_URL` can override the default dashboard URL).
- API clients that request JSON from `/` continue to receive service metadata.

---

## 4. API Endpoints Reference

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/evaluate/workbench` | Full workbench evaluation returning verdict, risk score, attack chain, and telemetry |
| `POST` | `/api/evaluate` | Standard action evaluation against gateway |
| `POST` | `/api/evaluate/execute` | Evaluation followed by safe execution of allow-listed demo handlers only |
| `POST` | `/api/evaluate/scenarios` | Evaluates the predefined PS-27 benchmark scenarios |
| `POST` | `/api/evaluate/sources` | Evaluates all five untrusted source adapters |
| `POST` | `/api/evaluate/email/{uid}` | Fetches one read-only IMAP message by UID, then evaluates and audits it |
| `POST` | `/api/agents/propose` | AI agent proposal endpoint (`mock` or `openai-compatible`) |
| `GET` | `/api/events` | List audited events with filtering by decision, threat type, source, execution status |
| `GET` | `/api/events/{event_id}` | Retrieve single comprehensive audit record |
| `GET` | `/api/dashboard/stats` | Aggregate metrics (total events, blocked, allowed, approval required, threat breakdown) |
| `GET` | `/api/approvals` | List pending approval requests (Entra Auditor or Approver app role required) |
| `POST` | `/api/approvals/{approval_id}/approve` | Re-evaluate and approve, then resume only through a registered safe handler |
| `POST` | `/api/approvals/{approval_id}/reject` | Reject a pending request and audit its non-execution |

### Human approval workflow

Execution requests evaluated as `APPROVAL_REQUIRED` remain unexecuted and are
stored as pending review items. The **Human Approvals** dashboard and API use
Microsoft Entra v2 access tokens. The dashboard signs in using device code
flow; the API validates the RSA signature against the tenant's published
signing keys and checks issuer, tenant, audience, authorized client, expiry,
and assigned app roles. `TraceGuard.Auditor` can view the queue;
`TraceGuard.Approver` can view, approve, and reject. Reviewer identity is taken
from the signed `oid` and name claims; client-supplied reviewer names are
ignored. Requests expire after 15 minutes and can be resolved only once.
Approval triggers a fresh security evaluation; `BLOCK` cannot be overridden,
and a request without an exact registered safe handler is blocked even when approved. The
`database_reader` + `customer_records` handler returns fixed, synthetic
demonstration text and never reads a live database. The original decision and
the separate reviewer resolution are both recorded in SQLite.
The pending action payload is retained only until resolution or expiry, then
discarded; avoid submitting highly sensitive source content to a demo instance.

### Microsoft Entra app registration

Register an API application and expose a delegated scope named
`access_as_user`. Register a separate dashboard public-client application,
enable device code flow for it, and grant it that API scope. Set the API app's
access-token version to v2. Add app roles with exact values
`TraceGuard.Auditor` and `TraceGuard.Approver`, then assign users or groups
through Entra enterprise-app role assignments. Configure:

- Backend: `TRACEGUARD_ENTRA_TENANT_ID` (tenant GUID),
  `TRACEGUARD_ENTRA_AUDIENCE` (the API app's client GUID, which is the `aud`
  value in v2 access tokens), and `TRACEGUARD_ENTRA_CLIENT_ID` (dashboard
  public-client GUID, required to match the token's `azp` claim).
- Dashboard: `TRACEGUARD_ENTRA_TENANT_ID`, `TRACEGUARD_ENTRA_CLIENT_ID`
  (dashboard client GUID), and `TRACEGUARD_ENTRA_API_SCOPE` (full delegated
  scope such as `api://<api-app-id>/access_as_user`).

Do not configure `APPROVAL_REVIEW_TOKEN`; it is no longer used. Keep the
dashboard and API on private HTTPS in deployment and use tenant Conditional
Access/MFA policies appropriate to the environment. Automated tests use
locally generated signing keys and mocked role claims; no live Entra tenant or
sign-in was available during verification.

### OpenAI-compatible provider

The only live-model adapter currently implemented is `openai-compatible` for
Chat Completions APIs. The backend loads the project-root `.env` at startup
without overriding variables already set in the process environment. Enter
your API key locally in the ignored `.env` file; never paste it into chat or
commit it. `OPENAI_BASE_URL` defaults to `https://api.openai.com/v1`, and the
adapter's existing `OPENAI_MODEL` default is `gpt-4o-mini`. Change the model
locally if your API account does not have access to that model. Restart the
backend after changing `.env`. A missing or blank `OPENAI_API_KEY` leaves the
provider unavailable; the mock provider remains available without credentials.
The dashboard's **Agent task evaluation** panel accepts arbitrary task text,
uses the selected provider to create a structured proposal, and sends that
proposal through the gateway. It always sets `execute=false` and displays the
backend decision and the corresponding fetched audit event. The mock adapter
uses deterministic local heuristics and is not an autonomous AI model; only
the OpenAI-compatible adapter asks a live model to produce the proposal.
To make a live, non-executing proposal request, set `execute` to `false`:

```powershell
$request = @{
    action_id = "provider-smoke-test"
    agent_id = "ps27-demo-agent"
    instruction = "Summarize the public README."
    provider = "openai-compatible"
    execute = $false
} | ConvertTo-Json

Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8000/api/agents/propose" `
  -ContentType "application/json" -Body $request
```

The resulting proposal still goes through the runtime gateway and is audited;
this request does not invoke a handler. The Round 3 validation uses the mock
provider and does not send a live OpenAI-compatible request.

There is no
live web, external API, or customer database connector in this build; those
examples remain fixtures or simulated source content. An optional read-only
IMAP connector is available for one explicitly selected message UID:

```powershell
$env:TRACEGUARD_IMAP_HOST = "imap.example.com"
$env:TRACEGUARD_IMAP_USERNAME = "traceguard-readonly@example.com"
$env:TRACEGUARD_IMAP_PASSWORD = "set-a-mailbox-specific-app-password"
$env:TRACEGUARD_IMAP_MAILBOX = "INBOX" # Optional; defaults to INBOX
$env:TRACEGUARD_EMAIL_SOURCE_TOKEN = "set-a-separate-random-access-token"
```

Call `POST /api/evaluate/email/{uid}` with the `X-Email-Source-Token` header.
The adapter uses certificate-verified IMAP over TLS on port 993, selects the
configured mailbox read-only, and fetches only the requested numeric UID with
`BODY.PEEK` (so it does not mark the message as read). It rejects messages over
256 KB, extracts a plain-text body only, and passes that body through the
existing untrusted-source evaluator and audit path. It does not list mailboxes,
search messages, fetch attachments, send mail, or execute actions. Use a
dedicated least-privilege mailbox account and keep the API bound to localhost
or protect it with private HTTPS; the connector token is a separate shared-token
control, not user identity. Tests mock IMAP and never contact a mailbox.

The detector is rule-based/advisory, not a broadly trained model. The audit
log is persistent SQLite, not a tamper-evident ledger.

---

## 5. Round 3 Dry-Run Demonstration

Run the backend and dashboard using the commands above, then execute:

```powershell
.venv\Scripts\python scripts\round3_demo.py
```

The script uses only the local mock provider and local TRACEGUARD API. Every
proposal sets `execute` to `false`; the scenario endpoint evaluates without
calling a handler. It demonstrates a benign proposal, an untrusted
prompt-injection attempt, an unauthorized resource request, reasons and audit
records, then prints measured scenario results and confirms `not_requested`
execution status. Do not enable the workbench execution checkbox during this
dry-run demonstration.

Open `http://localhost:8501` to demonstrate the same workflow in the existing
dashboard. The Red-Team Security Lab reports expected and actual results,
pass/fail metrics, leakage analysis for the synthetic canary, and execution
status. Review actual audit records in the Audit Trail & Telemetry tab.
