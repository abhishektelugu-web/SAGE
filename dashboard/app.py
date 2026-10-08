"""SAGE AI — Streamlit Dashboard Application Entry Point."""

import sys
from pathlib import Path

# Ensure project root is on Python sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import streamlit as st
from dashboard.views.security_dashboard import render_security_dashboard


def main():
    """Streamlit entry point configuring wide view and invoking main dashboard."""
    st.set_page_config(
        page_title="SAGE AI — Security Dashboard",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    render_security_dashboard()


if __name__ == "__main__":
    main()
