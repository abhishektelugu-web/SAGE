"""Main Security Dashboard View for SAGE AI."""

import os
import requests
import streamlit as st
from typing import Dict, Any, List, Optional
from dashboard.components.metrics import render_metrics
from dashboard.components.threat_chart import render_threat_charts
from dashboard.components.event_table import render_event_table
from backend.database import db as local_db

API_BASE_URL = os.getenv("API_BASE_URL", "http://127.0.0.1:8000")


def fetch_dashboard_data(
    decision_filter: Optional[str] = None,
    threat_filter: Optional[str] = None,
    agent_filter: Optional[str] = None,
) -> tuple[Dict[str, Any], List[Dict[str, Any]], bool]:
    """Fetch metrics and event logs from SAGE Backend API with direct DB fallback.

    Returns:
        tuple of (stats_dict, events_list, is_live_api)
    """
    stats = {}
    events = []
    is_live_api = False

    # 1. Attempt REST API fetch
    try:
        stats_resp = requests.get(f"{API_BASE_URL}/api/dashboard/stats", timeout=1.5)
        if stats_resp.status_code == 200:
            stats = stats_resp.json()
            is_live_api = True

        params = {}
        if decision_filter and decision_filter != "ALL":
            params["decision"] = decision_filter
        if threat_filter and threat_filter != "ALL":
            params["threat_type"] = threat_filter
        if agent_filter:
            params["agent_id"] = agent_filter

        events_resp = requests.get(f"{API_BASE_URL}/api/events", params=params, timeout=1.5)
        if events_resp.status_code == 200:
            events = events_resp.json()
    except Exception:
        # Fallback to local database layer directly
        is_live_api = False

    # 2. If API is not reachable, load directly from SQLite database
    if not is_live_api:
        stats = local_db.get_stats()
        d_filter = None if decision_filter == "ALL" else decision_filter
        t_filter = None if threat_filter == "ALL" else threat_filter
        a_filter = agent_filter if agent_filter else None
        db_events = local_db.list_events(
            decision=d_filter,
            threat_type=t_filter,
            agent_id=a_filter,
            limit=200,
        )
        events = [e.model_dump() for e in db_events]

    return stats, events, is_live_api


def render_security_dashboard() -> None:
    """Render the primary SAGE AI Security Dashboard."""
    # Top banner & title
    st.title("🛡️ SAGE AI — Security Analysis & Guard Engine")
    st.caption("Live AI Agent Security Gateway, Threat Monitoring & Audit Engine")

    # Sidebar Filter Controls
    st.sidebar.header("🔍 Audit Trail Filters")

    decision_choice = st.sidebar.selectbox(
        "Filter by Decision:",
        options=["ALL", "ALLOW", "BLOCK", "APPROVAL_REQUIRED"],
        index=0,
    )

    threat_choice = st.sidebar.selectbox(
        "Filter by Threat Category:",
        options=["ALL", "prompt_injection", "sensitive_resource", "external_transfer", "credential_access", "none"],
        index=0,
    )

    agent_id_input = st.sidebar.text_input(
        "Filter by Agent ID:",
        value="",
        placeholder="e.g. agent_01",
    )

    # Refresh button
    if st.sidebar.button("🔄 Refresh Telemetry"):
        st.rerun()

    # Quick Demo Data Seed Button
    st.sidebar.markdown("---")
    st.sidebar.subheader("🧪 Hackathon Demo Controls")
    if st.sidebar.button("⚡ Seed Demo Security Events"):
        from scripts.seed_demo_data import seed_demo_events
        seeded_count = seed_demo_events()
        st.sidebar.success(f"Added {seeded_count} realistic demo events!")
        st.rerun()

    # Fetch live data
    stats, events, is_live_api = fetch_dashboard_data(
        decision_filter=decision_choice,
        threat_filter=threat_choice,
        agent_filter=agent_id_input,
    )

    # Status indicator pill
    if is_live_api:
        st.success(f"🟢 Connected to SAGE Backend API at {API_BASE_URL}")
    else:
        st.info("🟡 SAGE Backend API offline. Connected directly to SQLite Database (`sage.db`).")

    # Render top KPI metrics
    render_metrics(stats)

    st.markdown("---")

    # Render Visual Threat Charts
    render_threat_charts(stats, events)

    st.markdown("---")

    # Render Event Log Table
    render_event_table(events)
