"""AEGISINTEL — Streamlit entry point.

Run:  .venv\\Scripts\\python.exe -m streamlit run app.py
(binds to 127.0.0.1 via .streamlit/config.toml)
"""

from __future__ import annotations

import streamlit as st

from threatlens.branding import ICON_PATH, PRODUCT_NAME, TAGLINE, WORDMARK_PATH
from threatlens.security.rbac import Permission, has_permission
from threatlens.services.container import Services, build_services
from threatlens.ui import nav as registry
from threatlens.ui import pages
from threatlens.ui.components import guarded
from threatlens.ui.theme import apply_theme

st.set_page_config(
    page_title=PRODUCT_NAME,
    page_icon=str(ICON_PATH) if ICON_PATH.is_file() else ":material/shield:",
    layout="wide",
    initial_sidebar_state="expanded",
)
apply_theme()


@st.cache_resource(show_spinner=f"Starting {PRODUCT_NAME}…")
def get_services() -> Services:
    return build_services()


def brand() -> None:
    if WORDMARK_PATH.is_file():
        # Full shield + name when the sidebar is open; the shield alone when it is collapsed.
        st.logo(str(WORDMARK_PATH), size="large", icon_image=str(ICON_PATH))
        st.sidebar.markdown(f'<div class="tl-tagline">{TAGLINE}</div>', unsafe_allow_html=True)
    else:
        st.sidebar.markdown(
            f'<div class="tl-brand">{PRODUCT_NAME}</div><div class="tl-tagline">{TAGLINE}</div>',
            unsafe_allow_html=True,
        )


def main() -> None:
    services = get_services()
    if flash := st.session_state.pop("flash", None):
        st.warning(flash)

    if services.auth.setup_required():
        pages.auth.setup_page(services, TAGLINE)
        return
    token = st.session_state.get("token")
    principal = guarded(services.auth.resolve, token) if token else None
    if principal is None:
        pages.auth.login_page(services, TAGLINE)
        return

    brand()
    role = principal.role

    def page(fn, title: str, icon: str, perm: Permission, url: str):
        if not has_permission(role, perm):  # convenience only; services re-authorize
            return None
        return st.Page(lambda: fn(services, token), title=title, icon=icon, url_path=url)

    sections = {
        "Operations": [
            page(
                pages.overview.render,
                "Overview",
                ":material/monitoring:",
                Permission.VIEW_DASHBOARD,
                "overview",
            ),
            page(
                pages.events.render,
                "Alerts & Events",
                ":material/list_alt:",
                Permission.VIEW_EVENTS,
                "events",
            ),
            page(
                pages.incidents.render,
                "Incident Queue",
                ":material/inbox:",
                Permission.VIEW_INCIDENTS,
                "incidents",
            ),
        ],
        "Investigation": [
            page(
                pages.workspace.render,
                "Investigation Workspace",
                ":material/search:",
                Permission.VIEW_INCIDENTS,
                "workspace",
            ),
            page(
                pages.timeline.render,
                "Evidence & Timeline",
                ":material/timeline:",
                Permission.VIEW_INCIDENTS,
                "timeline",
            ),
            page(
                pages.ai_report.render,
                "AI Investigation Report",
                ":material/psychology:",
                Permission.VIEW_REPORTS,
                "ai-report",
            ),
            page(
                pages.rules.render,
                "Detections & ATT&CK",
                ":material/rule:",
                Permission.VIEW_RULES,
                "rules",
            ),
            page(
                pages.responses.render,
                "Response Approvals",
                ":material/gavel:",
                Permission.VIEW_INCIDENTS,
                "responses",
            ),
        ],
        "Administration": [
            page(
                pages.audit.render,
                "Audit Log",
                ":material/history:",
                Permission.VIEW_AUDIT,
                "audit",
            ),
            page(
                pages.users.render,
                "User Management",
                ":material/group:",
                Permission.MANAGE_USERS,
                "users",
            ),
            page(
                pages.health.render,
                "Health & Configuration",
                ":material/health_and_safety:",
                Permission.VIEW_HEALTH,
                "health",
            ),
            page(
                pages.auth.account_page,
                "My Account",
                ":material/person:",
                Permission.VIEW_DASHBOARD,
                "account",
            ),
        ],
    }
    registry.PAGES.clear()
    registry.PAGES.update({p.url_path: p for v in sections.values() for p in v if p})
    nav = st.navigation({k: [p for p in v if p] for k, v in sections.items() if any(v)})
    with st.sidebar:
        st.caption(f"Signed in as **{principal.username}** · {role.value}")
        if st.button("Sign out", width="stretch"):
            guarded(services.auth.logout, token)
            st.session_state.clear()
            st.rerun()
    nav.run()


main()
