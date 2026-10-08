"""Threat and Decision Visualizations component for SAGE AI Dashboard."""

import streamlit as st
import pandas as pd
from typing import Dict, Any, List


def render_threat_charts(stats: Dict[str, Any], events: List[Dict[str, Any]]) -> None:
    """Render charts visualizing threat distribution and decision breakdown."""
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("🎯 Threat Categories")
        threat_breakdown = stats.get("threat_breakdown", {})

        if threat_breakdown and any(v > 0 for v in threat_breakdown.values()):
            df_threats = pd.DataFrame(
                list(threat_breakdown.items()),
                columns=["Threat Category", "Incidents"],
            ).sort_values(by="Incidents", ascending=False)
            st.bar_chart(df_threats.set_index("Threat Category"), color="#E63946")
        else:
            st.info("No active threats recorded. System posture is clean.")

    with col2:
        st.subheader("⚖️ Decision Distribution")
        decision_breakdown = stats.get("decision_breakdown", {})

        # Fill default zero counts if missing
        chart_data = {
            "ALLOW": decision_breakdown.get("ALLOW", 0),
            "BLOCK": decision_breakdown.get("BLOCK", 0),
            "APPROVAL_REQUIRED": decision_breakdown.get("APPROVAL_REQUIRED", 0),
        }

        if any(v > 0 for v in chart_data.values()):
            df_decisions = pd.DataFrame(
                list(chart_data.items()),
                columns=["Decision", "Count"],
            )
            st.bar_chart(df_decisions.set_index("Decision"), color="#457B9D")
        else:
            st.info("No decision telemetry recorded yet.")
