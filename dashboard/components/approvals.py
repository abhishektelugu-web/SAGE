"""Human-review queue for pending agent actions."""

import os

import msal
import requests
import streamlit as st

API_BASE_URL = os.getenv("API_BASE_URL", "http://127.0.0.1:8000")
APPROVER_ROLE = "TraceGuard.Approver"


def _entra_public_client() -> tuple[msal.PublicClientApplication, list[str]]:
    tenant_id = os.getenv("TRACEGUARD_ENTRA_TENANT_ID", "").strip()
    client_id = os.getenv("TRACEGUARD_ENTRA_CLIENT_ID", "").strip()
    api_scope = os.getenv("TRACEGUARD_ENTRA_API_SCOPE", "").strip()
    if not tenant_id or not client_id or not api_scope:
        raise ValueError(
            "Configure TRACEGUARD_ENTRA_TENANT_ID, TRACEGUARD_ENTRA_CLIENT_ID, "
            "and TRACEGUARD_ENTRA_API_SCOPE for dashboard sign-in."
        )
    app = msal.PublicClientApplication(
        client_id,
        authority=f"https://login.microsoftonline.com/{tenant_id}",
    )
    return app, [api_scope]


def render_approval_queue() -> None:
    """Render explicit approval/rejection controls backed by the review API."""
    st.subheader("Human approval queue")
    st.caption(
        "Approval never overrides BLOCK or adds tools. Approved requests are re-evaluated "
        "and can resume only through an existing safe handler."
    )

    access_token = st.session_state.get("approval_entra_access_token")
    if not access_token:
        try:
            entra_app, scopes = _entra_public_client()
        except ValueError as exc:
            st.warning(str(exc))
            return

        if st.button("Sign in with Microsoft Entra ID", key="approval_entra_sign_in"):
            try:
                flow = entra_app.initiate_device_flow(scopes=scopes)
            except requests.RequestException as exc:
                st.error(f"Could not contact Microsoft Entra ID: {exc}")
            else:
                if "user_code" not in flow:
                    st.error(
                        flow.get("error_description", "Could not start Entra sign-in.")
                    )
                else:
                    st.session_state["approval_entra_device_flow"] = flow
                    st.rerun()

        flow = st.session_state.get("approval_entra_device_flow")
        if flow:
            st.info(flow["message"])
            if st.button("Complete Entra sign-in", key="approval_entra_complete_sign_in"):
                try:
                    result = entra_app.acquire_token_by_device_flow(flow)
                except requests.RequestException as exc:
                    st.error(f"Could not complete Microsoft Entra sign-in: {exc}")
                else:
                    token = result.get("access_token")
                    if token:
                        st.session_state["approval_entra_access_token"] = token
                        st.session_state.pop("approval_entra_device_flow", None)
                        st.rerun()
                    else:
                        st.error(
                            result.get(
                                "error_description",
                                "Entra sign-in was not completed.",
                            )
                        )
        return

    if st.button("Sign out of reviewer session", key="approval_entra_sign_out"):
        for key in (
            "approval_entra_access_token",
            "approval_entra_device_flow",
            "approval_entra_principal",
            "pending_approvals",
        ):
            st.session_state.pop(key, None)
        st.rerun()
    headers = {"Authorization": f"Bearer {access_token}"}

    if st.button("Load pending approvals", key="load_pending_approvals"):
        try:
            response = requests.get(
                f"{API_BASE_URL}/api/approvals",
                headers=headers,
                timeout=5,
            )
            response.raise_for_status()
            payload = response.json()
            st.session_state["pending_approvals"] = payload["approvals"]
            st.session_state["approval_entra_principal"] = payload["principal"]
        except requests.RequestException as exc:
            st.error(f"Could not load pending approvals: {exc}")

    principal = st.session_state.get("approval_entra_principal")
    if principal:
        roles = set(principal.get("roles", []))
        st.caption(
            f"Signed in as {principal['display_name']} · "
            f"roles: {', '.join(sorted(roles)) or 'none'}"
        )
    else:
        roles = set()

    result = st.session_state.get("approval_resolution_result")
    if result:
        st.info(
            f"Review result: {result['status']} · {result['decision']} · "
            f"{result['execution_status']} · event {result['event_id']}"
        )
        if result.get("reasons"):
            st.caption("Policy outcome: " + "; ".join(result["reasons"]))
        if result.get("execution_result"):
            st.success(f"Safe handler output: {result['execution_result']}")

    approvals = st.session_state.get("pending_approvals", [])
    if not approvals:
        st.info("No pending approval requests loaded.")
        return

    for item in approvals:
        action = item["action"]
        with st.container(border=True):
            st.markdown(
                f"**{action['action_type']}** · `{action.get('tool') or 'no tool'}` "
                f"→ `{action.get('resource') or 'no resource'}`"
            )
            st.caption(
                f"Agent: {action['agent_id']} · Source: {action['source']} · "
                f"Initial event: {item['event_id']} · Requested: {item['requested_at']}"
            )
            col_approve, col_reject = st.columns(2)
            for approved, column, label in (
                (True, col_approve, "Approve and attempt safe resume"),
                (False, col_reject, "Reject"),
            ):
                with column:
                    if st.button(
                        label,
                        key=f"{'approve' if approved else 'reject'}_{item['approval_id']}",
                        disabled=APPROVER_ROLE not in roles,
                    ):
                        try:
                            outcome = "approve" if approved else "reject"
                            response = requests.post(
                                f"{API_BASE_URL}/api/approvals/"
                                f"{item['approval_id']}/{outcome}",
                                json={},
                                headers=headers,
                                timeout=10,
                            )
                            response.raise_for_status()
                            st.session_state["approval_resolution_result"] = (
                                response.json()
                            )
                            st.session_state["pending_approvals"] = [
                                pending
                                for pending in approvals
                                if pending["approval_id"] != item["approval_id"]
                            ]
                            st.rerun()
                        except requests.RequestException as exc:
                            st.error(f"Could not resolve approval: {exc}")
