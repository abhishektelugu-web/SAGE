"""Red-Team Security Lab component for TRACEGUARD."""

import json
import os
import requests
import streamlit as st
from typing import List, Dict, Any

API_BASE_URL = os.getenv("API_BASE_URL", "http://127.0.0.1:8000")


def _evaluation_rows(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        {
            "Scenario": result.get("scenario", result.get("source", "Source adapter")),
            "Input": json.dumps(result.get("input", {}), ensure_ascii=True),
            "Expected": result.get("expected_result", ""),
            "Actual": result.get("actual_result", result.get("decision", "")),
            "Passed": result.get("passed", ""),
            "Explanation": result.get("explanation", ""),
            "Action ID": result.get("action_id", ""),
            "Source": result.get(
                "source", result.get("input", {}).get("source", "")
            ),
            "Agent": result.get("agent_id", ""),
            "Trusted source": result.get("trusted_source", True),
            "Tool": result.get(
                "tool", result.get("input", {}).get("tool")
            ) or "",
            "Resource": result.get(
                "resource", result.get("input", {}).get("resource")
            ) or "",
            "Risk Score": result.get("risk_score", 0),
            "Decision": result.get("decision", ""),
            "Access": result.get("access_decision", ""),
            "Data leakage": result.get("data_leakage_detected", False),
            "Threat Types": ", ".join(result.get("threat_types", [])),
            "Reasons": " ".join(result.get("reasons", [])),
            "Execution": result.get("execution_status", "not_requested"),
            "Event ID": result.get("event_id", ""),
            "Audit status": result.get("audit_status", ""),
        }
        for result in results
    ]


def render_red_team_lab() -> None:
    """Render the Red-Team Security Lab with controlled benchmark scenarios."""
    st.subheader("🧪 RED-TEAM SECURITY LAB")
    st.caption(
        "Empirical adversary testing against the runtime security engine. "
        "Evaluates prompt injection, sensitive data gating, data exfiltration, dangerous tools, and provenance trust."
    )

    # Top Control Buttons (Maintains exact test labels)
    btn_col1, btn_col2, btn_col3 = st.columns(3)

    with btn_col1:
        if st.button("Run PS-27 attack scenarios", width="stretch"):
            try:
                response = requests.post(f"{API_BASE_URL}/api/evaluate/scenarios", timeout=30)
                response.raise_for_status()
                st.session_state["ps27_scenario_results"] = response.json()["results"]
                st.toast("PS-27 scenario test suite executed successfully!")
            except requests.RequestException as exc:
                st.error(f"Could not run security scenarios through evaluator API: {exc}")
                # Fallback to local evaluation
                from backend.routes.evaluate import evaluate_scenarios as local_eval_scenarios
                try:
                    st.session_state["ps27_scenario_results"] = local_eval_scenarios()["results"]
                    st.toast("Evaluated scenarios via local fallback engine.")
                except Exception as local_exc:
                    st.error(f"Local scenario evaluation failed: {local_exc}")

    with btn_col2:
        if st.button("Evaluate all five source adapters", width="stretch"):
            try:
                response = requests.post(f"{API_BASE_URL}/api/evaluate/sources", timeout=30)
                response.raise_for_status()
                st.session_state["ps27_source_results"] = response.json()["results"]
                st.toast("Source adapter evaluation complete!")
            except requests.RequestException as exc:
                st.error(f"Could not evaluate source adapters through API: {exc}")
                from backend.routes.evaluate import evaluate_all_source_adapters as local_eval_sources
                try:
                    st.session_state["ps27_source_results"] = local_eval_sources()["results"]
                    st.toast("Evaluated source adapters via local fallback engine.")
                except Exception as local_exc:
                    st.error(f"Local source adapter evaluation failed: {local_exc}")

    with btn_col3:
        if st.button("⚡ Run Full Red-Team Benchmark Suite", width="stretch", type="primary"):
            with st.spinner("Running comprehensive red-team benchmark suite across all vectors..."):
                try:
                    # Run scenarios
                    scen_resp = requests.post(f"{API_BASE_URL}/api/evaluate/scenarios", timeout=30)
                    if scen_resp.status_code == 200:
                        st.session_state["ps27_scenario_results"] = scen_resp.json()["results"]

                    # Run sources
                    src_resp = requests.post(f"{API_BASE_URL}/api/evaluate/sources", timeout=30)
                    if src_resp.status_code == 200:
                        st.session_state["ps27_source_results"] = src_resp.json()["results"]

                    st.success("Full benchmark suite executed against runtime gateway!")
                except Exception as exc:
                    st.error(f"Benchmark run error: {exc}")

    # Display Results Tables
    results = st.session_state.get("ps27_scenario_results", [])
    if results:
        st.markdown("#### 🎯 Benchmark Scenario Results")
        passed_count = sum(result.get("passed") is True for result in results)
        failed_count = len(results) - passed_count
        metric_columns = st.columns(3)
        metric_columns[0].metric("Scenarios", len(results))
        metric_columns[1].metric("Passed", passed_count)
        metric_columns[2].metric("Failed", failed_count)
        st.caption(
            "Every scenario runs in dry-run mode. No proposed action or safe handler is executed."
        )
        leakage_results = [
            result.get("data_leakage_analysis", {})
            for result in results
            if result.get("data_leakage_analysis")
        ]
        if leakage_results:
            if all(result.get("passed") is True for result in leakage_results):
                st.success(
                    "Synthetic canary was absent from the evaluation result outside its recorded input and from the audit record."
                )
            else:
                st.error("Synthetic canary leakage was detected.")
        st.dataframe(
            _evaluation_rows(results),
            hide_index=True,
            width="stretch",
        )

    source_results = st.session_state.get("ps27_source_results", [])
    if source_results:
        st.markdown("**Live source-adapter results**")
        st.dataframe(
            _evaluation_rows(source_results),
            hide_index=True,
            width="stretch",
        )

    # Explanatory Security Matrix
    with st.expander("📚 Red-Team Attack Matrix & Expected Verdicts", expanded=False):
        st.markdown(
            """
            | # | Scenario Title | Threat Vector | Expected Verdict | Runtime Enforcement Boundary |
            |---|---|---|---|---|
            | **1** | **Benign Public Read** | None (Safe task & resource) | `ALLOW` | Demo handler reads `README.md` safely |
            | **2** | **Indirect Prompt Injection** | Untrusted content overrides instructions | Evaluated by policy | SAGE ML flags injection; gateway evaluates tool/resource |
            | **3** | **Sensitive Data Access** | Accessing `customer_records` | `APPROVAL_REQUIRED` | Conservative least-privilege access policy halts execution |
            | **4** | **Data Exfiltration** | Sensitive records + external destination | `BLOCK` | Mandatory hard-block policy halts execution |
            | **5** | **Dangerous Tool (Shell)** | Tool `system_shell` requested | `BLOCK` | Dangerous execution tools blocked at access control layer |
            | **6** | **Provenance Gating** | Untrusted source instructions | Controlled | Instructions from untrusted sources do not gain trusted status |
            """
        )
