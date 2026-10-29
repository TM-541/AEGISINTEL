"""Incident queue with filtering, sorting and pagination."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from threatlens.models.domain import DetectionStatus, Disposition, IncidentStatus, Severity
from threatlens.services.container import Services
from threatlens.ui import nav
from threatlens.ui.components import empty_state, guarded
from threatlens.ui.theme import DETECTION_LABELS

PAGE_SIZE = 50
COLUMNS = [
    "id",
    "severity",
    "confidence",
    "detection_status",
    "status",
    "disposition",
    "title",
    "assignee",
    "event_count",
    "first_seen",
    "last_seen",
]


def render(services: Services, token: str) -> None:
    st.title("Incident Queue")
    st.caption(
        "Severity = potential impact · Confidence = strength of evidence · Detection = "
        "how it was found · Verdict = analyst disposition."
    )
    with st.container(border=True):
        c = st.columns([2, 1.3, 1.1, 1.4, 1.3])
        text = c[0].text_input("Search title / description")
        statuses = c[1].multiselect(
            "Status",
            [s.value for s in IncidentStatus],
            default=["new", "triage", "investigating", "contained"],
        )
        sevs = c[2].multiselect("Severity", [s.value for s in Severity])
        detection = c[3].multiselect(
            "Detection",
            [d.value for d in DetectionStatus],
            format_func=lambda v: DETECTION_LABELS[v],
        )
        verdicts = c[4].multiselect("Verdict", [d.value for d in Disposition])
        c2 = st.columns([1, 1, 3])
        sort = c2[0].selectbox("Sort", ["severity", "last_seen", "created_at", "status"])
        mine = c2[1].toggle("Assigned to me")
    me = guarded(services.auth.resolve, token)
    filters = {
        "statuses": statuses,
        "severities": sevs,
        "text": text or None,
        "detection_statuses": detection,
        "dispositions": verdicts,
        "assigned_to": me.user_id if (mine and me) else None,
    }
    total = guarded(services.incidents.count, token, **filters) or 0
    if not total:
        empty_state(
            "No incidents",
            "Import events and run detection, or adjust the filters. "
            "No incident does not mean the environment is safe.",
        )
        return
    pages = max(1, -(-total // PAGE_SIZE))
    page = st.number_input(f"Page (1-{pages}) · {total} incident(s)", 1, pages, 1)
    rows = (
        guarded(
            services.incidents.list_incidents,
            token,
            sort=sort,
            limit=PAGE_SIZE,
            offset=(page - 1) * PAGE_SIZE,
            **filters,
        )
        or []
    )
    df = pd.DataFrame(rows)[COLUMNS]
    df["detection_status"] = df["detection_status"].map(DETECTION_LABELS)
    st.caption("Select a row to open it in the investigation workspace.")
    selection = st.dataframe(
        df,
        hide_index=True,
        width="stretch",
        on_select="rerun",
        selection_mode="single-row",
        column_config={
            "id": st.column_config.NumberColumn("ID", format="#%d"),
            "event_count": st.column_config.NumberColumn("Events"),
            "detection_status": "Detection",
            "disposition": "Verdict",
        },
    )
    picked = selection.selection.rows if selection else []
    if picked:
        st.session_state["incident_id"] = int(df.iloc[picked[0]]["id"])
        nav.go("workspace")
