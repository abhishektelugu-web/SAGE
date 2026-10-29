# Technical Report: PS-27 — Runtime Security for AI Agents
**Project Title:** TRACEGUARD — AI Agent Runtime Security Platform  
**Tagline:** *"Inspect every instruction. Control every action. Prove every decision."*  
**Problem Statement ID:** TH2-PS-SS-027 (PS-27)  
**Evaluation Target:** College Hackathon Jury Demonstration  

---

## 1. Executive Summary & Challenge Overview

Autonomous AI agents capable of consuming data from files, databases, APIs, emails, and web pages are vulnerable to indirect prompt injection, instruction hijacking, privilege escalation, and accidental or deliberate data exfiltration. Static system prompts and post-generation text filtering fail because the agent's reasoning process itself becomes tainted once malicious instructions enter its context.

**TRACEGUARD** addresses Problem Statement 27 by deploying an external, deterministic runtime security gateway between the AI agent's proposals and the underlying system resources. Every proposed tool invocation is intercepted, analyzed against ML threat models and deterministic rules, verified against least-privilege identity access policies, scored for risk, gated by mandatory security policies, and logged to a persistent SQLite audit ledger.

---

## 2. Requirement-to-Outcome Mapping

| Problem Statement 27 Requirement | Expected Outcome | TRACEGUARD Implementation | Status |
|---|---|---|:---:|
| **1. Working runtime security platform** | **End-to-end action evaluation** | Existing Streamlit workbench, FastAPI evaluation/proposal routes, deterministic checks, policy gateway, and SQLite audit events; the Round 3 demo uses dry-run requests. | **See verification below** |
| **2. Untrusted-instruction detection** | **Structured local detection** | Findings include category, severity, explanation, and non-content evidence; policy, not text detection alone, decides authorization. | **See verification below** |
| **3. Tool and data access control** | **Least-privilege gateway** | Identity-specific tool/resource allow-lists, deny-by-default unknown combinations, sensitive-resource approval, hard-block rules, and separation of evaluation from optional execution. | **See verification below** |
| **4. Runtime monitoring and audit dashboard** | **Persistent telemetry** | Streamlit displays backend event metrics, filters, details, and scenario results sourced from the API/SQLite store. SQLite is not tamper-evident. | **See verification below** |
| **5. Attack evaluation and leakage analysis** | **Repeatable synthetic suite** | Ten deterministic scenarios report input, expected and actual result, pass/fail, explanation, audit linkage where applicable, measured metrics, and a synthetic-canary output/audit check. | **See verification below** |
| **6. Technical report and demonstration** | **Reproducible dry-run** | This report and `scripts/round3_demo.py` demonstrate mock-provider and policy decisions with `execute=false`; the script confirms no execution. | **See verification below** |

---

## 3. Architecture & Data Flow

```
                                      +---------------------------------------------+
                                      |            EXTERNAL SOURCES                 |
                                      |  (Email, Web, File, API, Database, User)    |
                                      +---------------------------------------------+
                                                             |
                                                             v
+-----------------------------------------------------------------------------------------------------------------------+
|                                             TRACEGUARD RUNTIME GATEWAY                                                |
+-----------------------------------------------------------------------------------------------------------------------+
|  1. INPUT VALIDATION & PROVENANCE RECORDING                                                                           |
|     - Computes SHA-256 integrity hash of raw source content                                                           |
|     - Tags source trust status (trusted vs untrusted external)                                                        |
|                                                                                                                       |
|  2. AGENT TOOL-CALL PROPOSAL (UNTRUSTED INTENT)                                                                       |
|     - Deterministic intent mapping via MockAgentProvider or OpenAI-compatible provider adapter                        |
|                                                                                                                       |
|  3. PARALLEL THREAT ANALYSIS                                                                                          |
|     - SAGE AI/ML Inference: Prompt injection classifier, anomaly detector, confidence scoring (0.0 - 1.0)            |
|     - Deterministic Security Rules: Regex indicators for overrides, secrets, exfiltration, privilege escalation       |
|                                                                                                                       |
|  4. IDENTITY & ACCESS CONTROL ENFORCEMENT                                                                             |
|     - Blocks unauthorized or dangerous execution tools (system_shell, cmd, powershell)                                |
|     - Gates sensitive resources (customer_records, credentials, .env) -> APPROVAL_REQUIRED                            |
|     - Enforces agent-specific allow-listed tool/resource capabilities                                                 |
|                                                                                                                       |
|  5. COMPOSITE RISK SCORING & POLICY ARBITRATION                                                                       |
|     - Severity points: Low (+10), Medium (+25), High (+40) capped at 100                                              |
|     - Mandatory Hard-Block Policies: Sensitive Data + External Exfiltration -> BLOCK                                   |
|     - Decision Thresholds: 0-30: ALLOW | 31-70: APPROVAL_REQUIRED | 71-100: BLOCK                                      |
|                                                                                                                       |
|  6. RUNTIME EXECUTION SANDBOX BOUNDARY                                                                                |
|     - Executed ONLY if decision == ALLOW and requested tool/resource matches an allow-listed demo handler            |
|     - Blocks all arbitrary commands, network calls, or unauthorized file writes                                       |
|                                                                                                                       |
|  7. PERSISTENT AUDIT LOGGING                                                                                           |
|     - SQLite database (sage.db) persists event ID, action ID, timestamp, verdict, threat list, and decision reasons  |
+-----------------------------------------------------------------------------------------------------------------------+
```

---

## 4. Detailed Component Implementation

### 4.1 Untrusted-Instruction Detection Module
* **SAGE ML Pipeline (`ai_ml/`):** Evaluates `AgentAction` inputs without executing them. Uses text extraction, prompt injection classifiers, sensitive resource classifiers, anomaly detectors, and multi-signal confidence boosters.
* **Deterministic Rules (`security/rules.py`):**
  * `PROMPT_INJECTION_OVERRIDE` (High severity): Matches instructions attempting to disregard, forget, or override prior instructions.
  * `SENSITIVE_RESOURCE_REFERENCE` (Medium severity): Matches credentials, tokens, passwords, customer records, and `.env` references.
  * `EXTERNAL_DATA_TRANSMISSION` (High severity): Matches data upload, transfer, or external sink transmission patterns.
  * `PRIVILEGE_ESCALATION_REQUEST` (High severity): Matches `sudo`, admin privileges, and root access requests.
  * `DANGEROUS_ACTION_REQUEST` (High severity): Matches shell execution, directory deletion, or security-disabling commands.

### 4.2 Tool and Data Access Control Layer (`security/access_control.py`)
* **Dangerous Tool Deny-List:** `system_shell`, `shell`, `terminal`, `command_executor`, `powershell`, `cmd`, `python_executor`.
* **Agent Capability Registry:** Explicit mapping of agent identities to allowed tools and resources.
* **Sensitive Resource Gating:** Resources matching sensitive regexes (e.g. `customer_records`, `passwords`) mandate `APPROVAL_REQUIRED`, preventing automated execution until authorized.

### 4.3 Data-Leakage Protection & Policy Engine (`security/policy.py`)
* **Hard-Block Policy Combinations:**
  * `SENSITIVE_RESOURCE` + `EXTERNAL_EXFILTRATION` $\rightarrow$ Immediate mandatory `BLOCK` and `data_leakage_detected = True`.
  * `PRIVILEGE_ESCALATION` + `DANGEROUS_ACTION` $\rightarrow$ Immediate mandatory `BLOCK`.
* A low numerical risk score cannot bypass mandatory access control blocks or hard-block policy rules.

### 4.4 Agent Security Workbench (`dashboard/components/workbench.py`)
* Allows jury members and operators to test any arbitrary task and source content without editing code or opening API tools.
* Supports live uploading of `.txt` and `.md` files (validated, size-limited to 50KB).
* Integrates editable pre-loaded demo scenarios for instant evaluation.

### 4.5 Attack Path & Provenance Explorer (`dashboard/components/attack_chain.py`)
* Generates a visual 5-step timeline based on empirical evaluation data:
  1. *Source Ingestion:* Origin, trust metadata, SHA-256 hash.
  2. *Threat Analysis:* Flagged prompt injection or clean verification.
  3. *Action Authorization:* Tool and resource access verification.
  4. *Policy Enforcement:* Calculated composite score and policy reasons.
  5. *Execution Boundary:* Enforcement confirmation (executed vs blocked vs approval-held).

---

## 5. Benchmark Scenarios & Evaluation Results

`POST /api/evaluate/scenarios` evaluates the original six PS-27 scenarios and
four additional cases for unauthorized resource access, synthetic confidential
data, policy bypass, and malformed proposal validation. It performs local
deterministic checks only, never requests execution, and does not call an
external provider or a tool handler. Each valid action result links to its
audit event. The malformed provider proposal is a synthetic in-process response
fixture; adapter validation rejects it before gateway evaluation, so that case
intentionally has no event or network request.

The endpoint calculates scenario count, pass/fail totals, pass-rate percentage,
actual-result counts, and whether all results remained non-executing from the
returned results; it does not hardcode a detection rate.

| Scenario ID | Scenario | Expected | Actual | Pass | Execution |
|---|---|---|---|---|---|
| `PS27-SAFE` | Authorized public README read | `ALLOW` | `ALLOW` | Pass | `not_requested` |
| `PS27-INJECTION` | Untrusted prompt injection | `BLOCK` | `BLOCK` | Pass | `not_requested` |
| `PS27-SENSITIVE` | Customer-record access | `APPROVAL_REQUIRED` | `APPROVAL_REQUIRED` | Pass | `not_requested` |
| `PS27-EXFIL` | Customer-data exfiltration | `BLOCK` | `BLOCK` | Pass | `not_requested` |
| `PS27-PRIVILEGE` | Privilege escalation | `BLOCK` | `BLOCK` | Pass | `not_requested` |
| `PS27-DANGEROUS-TOOL` | System-shell tool request | `BLOCK` | `BLOCK` | Pass | `not_requested` |
| `PS27-UNAUTHORIZED-RESOURCE` | Unlisted file resource | `BLOCK` | `BLOCK` | Pass | `not_requested` |
| `PS27-CANARY-EXPOSURE` | Synthetic canary disclosure attempt | `APPROVAL_REQUIRED` | `APPROVAL_REQUIRED` | Pass | `not_requested` |
| `PS27-POLICY-BYPASS` | Instruction attempts policy bypass | `BLOCK` | `BLOCK` | Pass | `not_requested` |
| `PS27-MALFORMED-PROPOSAL` | Empty proposal instruction | `REJECTED` | `REJECTED` | Pass | `not_requested` |

The focused scenario test verifies every expected/actual comparison and
asserts no demo handler runs. In the canary case, the explicitly recorded
synthetic attack input contains the canary by design; tests verify it is absent
from the remaining result fields, persisted audit payload, and captured logs.
This synthetic check is not a general proof against all possible data leaks.

### Functional Source Adapters Evaluation (`POST /api/evaluate/sources`)
All 5 external source adapters were evaluated through the gateway:
* `api`: Bounded caller-supplied JSON content $\rightarrow$ Evaluated and audited.
* `database`: Local SQLite fixture row $\rightarrow$ Untrusted flag enforced.
* `email`: Plaintext `.eml` parser fixture $\rightarrow$ Untrusted flag enforced.
* `file`: Local document fixture $\rightarrow$ Untrusted flag enforced.
* `web`: HTML text extractor (scripts/styles stripped) $\rightarrow$ Untrusted flag enforced.

---

## 6. Verification & Automated Test Suite

The automated test suite runs via pytest in the project's virtual environment:

```powershell
.venv\Scripts\python -m pytest
```

### Round 3 verification results

Verified against the completed Round 3 code:

* Full suite: `.venv\Scripts\python.exe -m pytest -q` — **153 passed, 0
  failed, 0 skipped**. Pytest reported one existing Starlette/httpx
  deprecation warning.
* Focused affected tests (`test_evaluate_scenarios.py`,
  `test_agent_providers.py`, and `test_dashboard_app.py`) — **36 passed**.
* `git diff --check` — passed.
* Backend health returned HTTP 200, `/docs` loaded and listed
  `POST /api/agents/propose`, and the local mock proposal returned `ALLOW`
  with `not_requested` execution; its audit event was retrievable.
* The scenario API reported **10/10 passed** with actual decisions:
  `ALLOW: 1`, `BLOCK: 6`, `APPROVAL_REQUIRED: 2`, and `REJECTED: 1`.
  No scenario handler ran.
* The dashboard loaded locally, connected to the API, and rendered evaluation
  results and the audit/telemetry view. The Red-Team Lab showed 10 scenarios,
  10 passed, and 0 failed.
* No live OpenAI-compatible request was made. No proposed action was executed
  during the Round 3 demo.

The full-suite count above was measured after the final code changes. The
focused affected tests were also rerun after the last code edits.

---

## 7. Operational Demonstration Guide

### Running the Services Locally:
```powershell
# Terminal 1 — Start TRACEGUARD Backend API:
.venv\Scripts\python server.py
# Running at: http://127.0.0.1:8000 (Swagger: http://127.0.0.1:8000/docs)

# Terminal 2 — Start TRACEGUARD Dashboard:
.venv\Scripts\streamlit run dashboard/app.py
# Running at: http://localhost:8501
```

### Round 3 dry-run demo workflow
1. Start the backend with `.venv\Scripts\python server.py` and the dashboard
   with `.venv\Scripts\streamlit run dashboard/app.py`.
2. Open `http://localhost:8501` and keep the Workbench execution control off.
3. Run `.venv\Scripts\python scripts/round3_demo.py`.
4. Show the mock-provider safe proposal, the untrusted-instruction block, and
   the unauthorized-resource block with their reasons.
5. Open the returned event IDs in the Audit Trail & Telemetry tab.
6. Show the Red-Team Lab's inputs, expected/actual outcomes, pass status,
   explanation, synthetic-canary check, and `not_requested` execution status.
   Do not enable execution during this demonstration.

---

## 8. Limitations & Scope of Protection

To uphold engineering rigor, the following design boundaries are documented:
1. **Advisory ML vs Authoritative Policy:** SAGE AI/ML provides probabilistic guidance; deterministic access control rules and hard-block policy rules remain the final authority.
2. **Execution Boundary Scope:** Demonstration execution is strictly constrained to safe, allow-listed read handlers (`README.md`, `public_faq`). The gateway purposefully refuses to execute arbitrary shell scripts or outward network traffic.
3. **Defense-in-Depth Reality:** Passing the tested synthetic cases demonstrates configured-rule behavior, not immunity to novel attacks or perfect detection. Continuous monitoring and human oversight remain essential.
4. **Provider Availability:** Round 3 validation uses the mock provider. The adapter's mocked request/auth behavior is tested, but no live provider response or decision is claimed.
5. **Audit Integrity:** SQLite provides local persistence but is not immutable or tamper-evident.
6. **Source Scope:** Web, API, file, and database examples are fixture/simulation-based except the separately configured read-only IMAP connector. The demo performs no live data access, outbound transfer, shell, or command execution.
