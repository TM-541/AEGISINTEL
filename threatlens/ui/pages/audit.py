"""Audit log viewer with hash-chain verification (administrators)."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from threatlens.services.container import Services
from threatlens.ui.components import empty_state, guarded, safe_csv


def render(services: Services, token: str) -> None:
    st.title("Audit Log")
    chain = guarded(services.admin.verify_audit_chain, token)
    if chain is None:
        return
    if chain["ok"]:
        st.success(f"Hash chain verified: {chain['checked']} record(s) intact.")
    else:
        st.error(
            f"Hash chain BROKEN at record #{chain['first_bad_id']}. The audit log may have "
            "been modified outside the application."
        )
    c = st.columns([1, 1, 1])
    action = c[0].text_input("Action (exact, e.g. auth.login)")
    actor = c[1].text_input("Actor username")
    limit = c[2].number_input("Max rows", 50, 5000, 500, step=50)
    rows = (
        guarded(
            services.admin.audit_log,
            token,
            action=action or None,
            actor=actor or None,
            limit=int(limit),
        )
        or []
    )
    if not rows:
        empty_state("No audit events", "Try different filters.")
        return
    df = pd.DataFrame(rows)[
        [
            "id",
            "ts",
            "actor_username",
            "action",
            "outcome",
            "target_type",
            "target_id",
            "details",
            "row_hash",
        ]
    ]
    st.dataframe(df, hide_index=True, width="stretch", height=520)
    st.download_button("Export CSV", safe_csv(df), "threatlens_audit.csv", "text/csv")
