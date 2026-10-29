"""Evidence and timeline viewer for the selected incident."""

from __future__ import annotations

import altair as alt
import pandas as pd
import streamlit as st

from threatlens.services.container import Services
from threatlens.ui.components import guarded, require_incident, safe_csv
from threatlens.ui.theme import SEVERITY_COLORS

SEV_ORDER = ["critical", "high", "medium", "low", "informational"]


def render(services: Services, token: str) -> None:
    st.title("Evidence & Timeline")
    iid = require_incident()
    if iid is None:
        return
    detail = guarded(services.incidents.detail, token, iid)
    if not detail:
        return
    st.subheader(f"#{iid} · {detail['incident']['title']}")
    events = pd.DataFrame(detail["events"])
    if events.empty:
        st.info("This incident has no linked events.")
        return
    finding_events = {e for f in detail["findings"] for e in f["event_ids"]}
    events["role"] = events["id"].map(
        lambda e: "rule evidence" if e in finding_events else "context"
    )
    events["ts"] = pd.to_datetime(events["timestamp"])
    chart = (
        alt.Chart(events)
        .mark_circle(size=140, opacity=0.9)
        .encode(
            x=alt.X("ts:T", title="Time (UTC)"),
            y=alt.Y("event_type:N", title=None),
            color=alt.Color(
                "severity:N",
                scale=alt.Scale(domain=SEV_ORDER, range=[SEVERITY_COLORS[s] for s in SEV_ORDER]),
                legend=alt.Legend(title="Severity"),
            ),
            shape=alt.Shape("role:N", legend=alt.Legend(title="Link")),
            tooltip=["id", "timestamp", "event_type", "username", "host", "process_name", "role"],
        )
        .properties(height=max(220, 34 * events["event_type"].nunique()))
    )
    st.altair_chart(chart, width="stretch")

    cols = [
        "timestamp",
        "id",
        "role",
        "severity",
        "event_type",
        "username",
        "host",
        "src_ip",
        "process_name",
        "command_line",
        "message",
    ]
    st.dataframe(events[cols], hide_index=True, width="stretch", height=360)
    st.download_button(
        "Export evidence (CSV)", safe_csv(events[cols]), f"incident_{iid}_evidence.csv", "text/csv"
    )
    with st.expander("Original record (verbatim, untrusted)"):
        pick = st.selectbox("Event", events["id"].tolist())
        st.code(events.loc[events["id"] == pick, "raw_json"].iloc[0], language="json")
