"""Attack Path and Provenance Explorer component for TRACEGUARD."""

import streamlit as st
from typing import List, Dict, Any


def render_attack_chain(attack_path: List[Dict[str, Any]]) -> None:
    """Render the chronological provenance and attack path timeline."""
    st.subheader("🗺️ ATTACK PATH & PROVENANCE EXPLORER")
    st.caption(
        "Traceable chronological sequence connecting ingested source data, detected threats, "
        "proposed agent operations, policy decisions, and runtime execution boundaries."
    )

    if not attack_path:
        st.info("Submit an action in the Agent Security Workbench to visualize the live attack path.")
        return

    # Visual timeline flow
    for idx, node in enumerate(attack_path):
        step_num = node.get("step", idx + 1)
        stage = node.get("stage", "Processing Step")
        title = node.get("title", f"Step {step_num}")
        nature = node.get("nature", "Observed event")
        status = str(node.get("status", "neutral")).lower()
        summary = node.get("summary", "")
        details = node.get("details", {})

        # Status styling & icon
        if status in ("threat_detected", "block", "blocked"):
            badge_icon = "🛑"
            border_color = "#ef4444"
            status_text = "THREAT DETECTED / BLOCKED"
        elif status in ("sensitive", "approval_required"):
            badge_icon = "⏳"
            border_color = "#f59e0b"
            status_text = "APPROVAL REQUIRED"
        elif status in ("trusted", "clean", "authorized", "allow", "executed"):
            badge_icon = "✅"
            border_color = "#10b981"
            status_text = "VERIFIED SAFE / AUTHORIZED"
        else:
            badge_icon = "ℹ️"
            border_color = "#3b82f6"
            status_text = status.upper()

        with st.container(border=True):
            col_icon, col_content = st.columns([1, 11])
            with col_icon:
                st.markdown(f"### {badge_icon}")
                st.caption(f"**Step {step_num}**")
            with col_content:
                header_cols = st.columns([3, 1])
                with header_cols[0]:
                    st.markdown(f"**{title}**")
                    st.caption(f"Stage: `{stage}` • Nature: `{nature}`")
                with header_cols[1]:
                    st.markdown(f":grey-background[{status_text}]")

                st.write(summary)

                if details:
                    with st.expander(f"View Step {step_num} Telemetry & Evidence"):
                        st.json(details)

        # Connector arrow between steps
        if idx < len(attack_path) - 1:
            st.markdown(
                "<div style='text-align: center; color: #64748b; font-size: 1.2rem; margin: -6px 0 6px 0;'>"
                "↓ <i>provenance flow</i> ↓"
                "</div>",
                unsafe_allow_html=True,
            )
