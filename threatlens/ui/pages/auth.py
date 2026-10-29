"""Initial setup, login and account pages."""

from __future__ import annotations

import streamlit as st

from threatlens.branding import LOGO_PATH, PRODUCT_NAME
from threatlens.security.passwords import MIN_LENGTH
from threatlens.services.container import Services
from threatlens.ui.components import guarded


def _header(tagline: str, subtitle: str) -> None:
    logo_col, text_col = st.columns([1, 3], vertical_alignment="center")
    if LOGO_PATH.is_file():
        logo_col.image(str(LOGO_PATH), width=110)
    text_col.markdown(
        f'<div class="tl-brand" style="font-size:2.2rem">{PRODUCT_NAME}</div>'
        f'<div class="tl-tagline" style="font-size:1rem">{tagline}</div>',
        unsafe_allow_html=True,
    )
    st.subheader(subtitle)


def setup_page(services: Services, tagline: str) -> None:
    _, mid, _ = st.columns([1, 2, 1])
    with mid:
        _header(tagline, "Initial administrator setup")
        st.write("No users exist yet. In a terminal in the project folder, run:")
        st.code(r".venv\Scripts\python.exe scripts\init_db.py", language="powershell")
        st.caption(
            "It prints a one-time setup code (valid 30 minutes). Only someone with "
            "access to this machine's terminal can create the first administrator."
        )
        with st.form("setup", clear_on_submit=False):
            code = st.text_input("One-time setup code", type="password")
            username = st.text_input("Administrator username", max_chars=64)
            display = st.text_input("Display name (optional)", max_chars=128)
            pw = st.text_input(
                f"Password (min {MIN_LENGTH} characters)", type="password", max_chars=128
            )
            pw2 = st.text_input("Confirm password", type="password", max_chars=128)
            if st.form_submit_button("Create administrator", type="primary"):
                if pw != pw2:
                    st.error("Passwords do not match.")
                elif guarded(
                    services.auth.create_initial_admin,
                    setup_code=code,
                    username=username,
                    password=pw,
                    display_name=display,
                ):
                    st.success("Administrator created. Please sign in.")
                    st.rerun()


def login_page(services: Services, tagline: str) -> None:
    _, mid, _ = st.columns([1, 1.4, 1])
    with mid:
        _header(tagline, "Sign in")
        with st.form("login"):
            username = st.text_input("Username", max_chars=64)
            password = st.text_input("Password", type="password", max_chars=128)
            if st.form_submit_button("Sign in", type="primary", width="stretch"):
                token = guarded(services.auth.login, username, password)
                if token:
                    st.session_state.clear()
                    st.session_state["token"] = token
                    st.rerun()
        st.caption(
            "Sessions expire after inactivity. Refreshing the browser requires signing "
            "in again (sessions are held server-side only)."
        )


def account_page(services: Services, token: str) -> None:
    st.title("My account")
    principal = guarded(services.auth.resolve, token)
    if principal:
        st.write(f"**Username:** {principal.username}  \n**Role:** {principal.role.value}")
    st.subheader("Change password")
    with st.form("change_pw", clear_on_submit=True):
        current = st.text_input("Current password", type="password")
        new = st.text_input(f"New password (min {MIN_LENGTH})", type="password")
        new2 = st.text_input("Confirm new password", type="password")
        if st.form_submit_button("Change password"):
            if new != new2:
                st.error("New passwords do not match.")
            else:
                if guarded(services.auth.change_own_password, token, current, new):
                    st.session_state.clear()
                    st.session_state["flash"] = "Password changed. Please sign in again."
                    st.rerun()
