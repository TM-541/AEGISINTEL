"""Administrator user management."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from threatlens.models.domain import Role
from threatlens.security.passwords import MIN_LENGTH
from threatlens.services.container import Services
from threatlens.ui.components import guarded


def render(services: Services, token: str) -> None:
    st.title("User Management")
    users = guarded(services.users.list_users, token)
    if users is None:
        return
    st.dataframe(pd.DataFrame([u.model_dump() for u in users]), hide_index=True, width="stretch")

    c1, c2 = st.columns(2)
    with c1, st.form("create_user", clear_on_submit=True):
        st.subheader("Create user")
        username = st.text_input("Username", max_chars=64)
        display = st.text_input("Display name", max_chars=128)
        role = st.selectbox("Role", [r.value for r in Role], index=1)
        pw = st.text_input(f"Initial password (min {MIN_LENGTH})", type="password")
        if st.form_submit_button("Create", type="primary"):
            new_id = guarded(
                services.users.create_user,
                token,
                username=username,
                password=pw,
                role=Role(role),
                display_name=display,
            )
            if new_id:
                st.session_state["flash"] = f"User '{username}' created."
                st.rerun()
    with c2, st.form("modify_user"):
        st.subheader("Modify user")
        by_name = {u.username: u for u in users}
        name = st.selectbox("User", list(by_name))
        new_role = st.selectbox("New role", [r.value for r in Role])
        action = st.radio(
            "Action", ["Change role", "Disable", "Enable", "Reset password"], horizontal=True
        )
        new_pw = st.text_input("New password (for reset)", type="password")
        if st.form_submit_button("Apply"):
            uid = by_name[name].id
            ok = {
                "Change role": lambda: guarded(
                    services.users.change_role, token, uid, Role(new_role)
                ),
                "Disable": lambda: guarded(services.users.set_active, token, uid, False),
                "Enable": lambda: guarded(services.users.set_active, token, uid, True),
                "Reset password": lambda: guarded(
                    services.users.reset_password, token, uid, new_pw
                ),
            }[action]()
            if ok:
                st.rerun()
    st.caption(
        "Safeguards enforced server-side: no self role change, no self disable, the last "
        "active administrator cannot be removed, and role changes revoke sessions."
    )
