"""Response recommendation & approval queue (simulated actions only)."""

from __future__ import annotations

import streamlit as st

from threatlens.security.rbac import Permission, has_permission
from threatlens.services.container import Services
from threatlens.ui.components import empty_state, esc, guarded, html_line, status_badge


def render(services: Services, token: str) -> None:
    st.title("Response Approvals")
    st.markdown(
        '<span class="tl-sim">SIMULATION MODE</span> No action in this version changes a '
        "real account, host or network. Approval and execution are separate, confirmed, "
        "audited steps.",
        unsafe_allow_html=True,
    )
    principal = guarded(services.auth.resolve, token)
    if principal is None:
        return
    can_decide = has_permission(principal.role, Permission.DECIDE_RESPONSE)
    status = st.segmented_control(
        "Status", ["pending", "approved", "executed", "rejected"], default="pending"
    )
    proposals = guarded(services.response.list_proposals, token, status=status) or []
    if not proposals:
        empty_state(
            f"No {status} proposals",
            "Propose actions from the investigation workspace or an AI report.",
        )
        return
    for p in proposals:
        with st.container(border=True):
            source = "AI-suggested" if p["source"] == "ai" else "analyst"
            html_line(
                status_badge(p["status"]),
                f"<b>#{p['id']} {esc(p['action_type'])}</b> → <code>{esc(p['target'])}</code>",
                f'<span class="tl-muted">incident #{p["incident_id"]} '
                f"({esc(p['incident_title'])}) · {source} · proposed by "
                f"{esc(p['proposed_by_name'])} at {esc(p['created_at'])}</span>",
            )
            st.text(p["rationale"])
            if p["decided_by_name"]:
                st.caption(
                    f"Decision by {p['decided_by_name']} at {p['decided_at']}: "
                    f"{p['decision_reason']}"
                )
            if p["result"]:
                st.json(p["result"], expanded=False)
            if not can_decide:
                continue
            if p["status"] == "pending":
                with st.form(f"decide-{p['id']}"):
                    reason = st.text_input("Reason (required, audited)", max_chars=1000)
                    confirm = st.checkbox("I confirm this decision")
                    c1, c2 = st.columns(2)
                    approve = c1.form_submit_button("Approve", type="primary")
                    reject = c2.form_submit_button("Reject")
                    if approve or reject:
                        if guarded(
                            services.response.decide,
                            token,
                            p["id"],
                            approve=approve,
                            reason=reason,
                            confirm=confirm,
                        ):
                            st.rerun()
            elif p["status"] == "approved":
                with st.form(f"exec-{p['id']}"):
                    confirm = st.checkbox("Run this SIMULATED action now")
                    if st.form_submit_button("Execute (simulated)"):
                        result = guarded(services.response.execute, token, p["id"], confirm=confirm)
                        if result:
                            st.success(result["outcome"])
