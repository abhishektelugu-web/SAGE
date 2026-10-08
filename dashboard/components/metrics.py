"""Metrics KPI component for SAGE AI Dashboard."""

import streamlit as st
from typing import Dict, Any


def render_metrics(stats: Dict[str, Any]) -> None:
    """Render top KPI metric cards for the security monitoring dashboard."""
    total = stats.get("total_events", 0)
    blocked = stats.get("blocked", 0)
    allowed = stats.get("allowed", 0)
    approval = stats.get("approval_required", 0)
    threats = stats.get("threats_detected", 0)

    # 5 KPI Columns
    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.metric(
            label="🛡️ Total Security Events",
            value=f"{total:,}",
            help="Total security actions evaluated by SAGE",
        )
    with col2:
        st.metric(
            label="🛑 Blocked Actions",
            value=f"{blocked:,}",
            delta=f"{blocked} critical" if blocked > 0 else None,
            delta_color="inverse",
            help="High-risk or malicious actions blocked",
        )
    with col3:
        st.metric(
            label="✅ Allowed Actions",
            value=f"{allowed:,}",
            help="Actions verified and authorized",
        )
    with col4:
        st.metric(
            label="⏳ Approval Required",
            value=f"{approval:,}",
            help="Actions held pending human supervisor approval",
        )
    with col5:
        st.metric(
            label="⚠️ Threats Detected",
            value=f"{threats:,}",
            delta=f"{threats} detected" if threats > 0 else None,
            delta_color="inverse",
            help="Prompt injections or policy violations identified",
        )
