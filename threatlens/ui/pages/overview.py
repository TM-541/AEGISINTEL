"""Security operations overview. Every number comes from stored data."""

from __future__ import annotations

import altair as alt
import pandas as pd
import streamlit as st

from threatlens.services.container import Services
from threatlens.ui.components import empty_state, guarded, metric_card
from threatlens.ui.theme import SEVERITY_COLORS

SEV_ORDER = ["critical", "high", "medium", "low", "informational"]


def render(services: Services, token: str) -> None:
    st.title("Security Operations Overview")
    stats = guarded(services.incidents.dashboard_stats, token)
    if stats is None:
        return
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        metric_card("Open incidents", stats["incidents_open"])
    with c2:
        metric_card(
            "Critical / high open",
            stats["incidents_by_severity"].get("critical", 0)
            + stats["incidents_by_severity"].get("high", 0),
        )
    with c3:
        metric_card("Pending approvals", stats["pending_approvals"])
    with c4:
        metric_card("Events stored", f"{stats['events']:,}", f"{stats['imports']} import(s)")

    if stats["events"] == 0:
        st.write("")
        empty_state(
            "No telemetry yet",
            "Go to **Alerts & Events** to import the synthetic datasets in "
            "`sample_data/`, then run detection.",
        )
        return

    left, right = st.columns([1, 1.4])
    with left:
        st.subheader("Open incidents by severity")
        sev = pd.DataFrame(
            [
                {"severity": s, "incidents": stats["incidents_by_severity"].get(s, 0)}
                for s in SEV_ORDER
            ]
        )
        chart = (
            alt.Chart(sev)
            .mark_bar()
            .encode(
                x=alt.X("incidents:Q", title="Incidents", axis=alt.Axis(tickMinStep=1)),
                y=alt.Y("severity:N", sort=SEV_ORDER, title=None),
                color=alt.Color(
                    "severity:N",
                    scale=alt.Scale(
                        domain=SEV_ORDER, range=[SEVERITY_COLORS[s] for s in SEV_ORDER]
                    ),
                    legend=None,
                ),
                tooltip=["severity", "incidents"],
            )
        )
        st.altair_chart(chart, width="stretch")
    with right:
        st.subheader("Event volume (UTC, hourly)")
        hourly = pd.DataFrame(stats["events_by_hour"])
        hourly["hour"] = pd.to_datetime(hourly["hour"])
        st.altair_chart(
            alt.Chart(hourly)
            .mark_area(opacity=0.6, line=True)
            .encode(
                x=alt.X("hour:T", title=None),
                y=alt.Y("events:Q", title="Events"),
                tooltip=[alt.Tooltip("hour:T", format="%Y-%m-%d %H:%M"), "events"],
            ),
            width="stretch",
        )

    st.subheader("Open incidents by detection layer")
    layers = stats.get("incidents_by_detection", {})
    lc = st.columns(3)
    for col, (key, label, hint) in zip(
        lc,
        (
            ("known_detection", "Known detections", "a Sigma or correlation rule matched"),
            ("anomalous_behavior", "Behaviour only", "statistical anomaly, no rule matched"),
            ("suspicious_unmatched", "Analyst-flagged", "raised by an analyst, no rule matched"),
        ),
        strict=True,
    ):
        with col:
            metric_card(label, layers.get(key, 0), hint)

    left, right = st.columns(2)
    with left:
        st.subheader("Incidents by status")
        st.dataframe(
            pd.DataFrame(
                list(stats["incidents_by_status"].items()), columns=["status", "incidents"]
            ),
            hide_index=True,
            width="stretch",
        )
    with right:
        st.subheader("Most-mapped ATT&CK techniques")
        if stats["top_techniques"]:
            st.dataframe(pd.DataFrame(stats["top_techniques"]), hide_index=True, width="stretch")
        else:
            st.caption("No mappings yet. Run detection from the Alerts & Events page.")
