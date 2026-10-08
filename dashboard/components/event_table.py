"""Security Event Table component for SAGE AI Dashboard."""

import streamlit as st
import pandas as pd
from typing import List, Dict, Any


def render_event_table(events: List[Dict[str, Any]]) -> None:
    """Render the detailed audit event table with filtering and inspector view."""
    st.subheader("📋 Security Audit Event Trail")

    if not events:
        st.info("No security events match the current filter criteria.")
        return

    # Prepare DataFrame columns for display
    display_rows = []
    for ev in events:
        display_rows.append({
            "Event ID": ev.get("event_id", ""),
            "Action ID": ev.get("action_id", ""),
            "Agent ID": ev.get("agent_id", ""),
            "Action": ev.get("action_type", ""),
            "Resource": ev.get("resource", "*"),
            "Threat Type": ev.get("threat_type", "none"),
            "ML Confidence": f"{float(ev.get('ml_confidence', 0.0)):.2f}",
            "Risk Score": f"{float(ev.get('risk_score', 0.0)):.1f}",
            "Decision": ev.get("decision", ""),
            "Reason": ev.get("decision_reason", "") or ev.get("ml_reason", ""),
            "Timestamp": ev.get("timestamp", ""),
        })

    df = pd.DataFrame(display_rows)

    # Render DataFrame
    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Decision": st.column_config.TextColumn(
                "Decision",
                help="Security decision outcome",
            ),
            "Risk Score": st.column_config.NumberColumn(
                "Risk Score",
                help="Composite risk assessment (0-100)",
            ),
            "ML Confidence": st.column_config.NumberColumn(
                "ML Confidence",
                help="SAGE AI detection confidence (0.0-1.0)",
            ),
        },
    )

    # Expandable detail inspector
    with st.expander("🔍 Inspect Full Event Payload"):
        selected_id = st.selectbox(
            "Select Event ID to inspect:",
            options=[ev.get("event_id") for ev in events],
            index=0 if events else None,
        )
        if selected_id:
            chosen = next((e for e in events if e.get("event_id") == selected_id), None)
            if chosen:
                st.json(chosen)
