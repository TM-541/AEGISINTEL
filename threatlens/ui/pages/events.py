"""Alerts & event explorer, with two-step import (preview → confirm) and detection run."""

from __future__ import annotations

import json

import pandas as pd
import streamlit as st

from threatlens.ingest.normalize import SourceType
from threatlens.models.domain import Severity
from threatlens.repositories.event_repo import EventFilter
from threatlens.security.rbac import Permission, has_permission
from threatlens.services.container import Services
from threatlens.ui.components import empty_state, guarded, safe_csv

TABLE_COLS = [
    "timestamp",
    "severity",
    "event_type",
    "username",
    "host",
    "src_ip",
    "process_name",
    "message",
    "id",
]


def _import_panel(services: Services, token: str) -> None:
    with st.expander("Import security events", expanded=False):
        st.caption(
            "Accepted: .json, .jsonl/.ndjson, .csv · UTF-8 · max "
            f"{services.settings.max_upload_mb} MB · content is treated as untrusted data."
        )
        source = st.selectbox(
            "Source type",
            [s.value for s in SourceType],
            format_func=lambda s: {
                "auth": "Authentication logs",
                "endpoint": "Endpoint events",
                "alert": "Security alerts",
            }[s],
        )
        upload = st.file_uploader("File", type=["json", "jsonl", "ndjson", "csv"])
        if upload is None:
            return
        data = upload.getvalue()
        preview = guarded(services.ingestion.preview, token, upload.name, data, SourceType(source))
        if preview is None:
            return
        c = st.columns(5)
        c[0].metric("Records", preview.total_records)
        c[1].metric("Valid", len(preview.valid_events))
        c[2].metric("New", preview.new_events)
        c[3].metric("Duplicates", preview.duplicates_in_file + preview.already_stored)
        c[4].metric("Rejected", preview.error_count)
        if preview.errors:
            st.warning("Some records failed validation and will be skipped:")
            st.dataframe(
                pd.DataFrame(preview.errors, columns=["row", "problem"]),
                hide_index=True,
                width="stretch",
            )
        if preview.valid_events:
            st.caption("Preview of normalised events (first 20):")
            st.dataframe(
                pd.DataFrame(
                    [
                        e.model_dump(mode="json", exclude={"raw_json", "content_hash"})
                        for e in preview.valid_events[:20]
                    ]
                ),
                hide_index=True,
                width="stretch",
            )
        if preview.file_already_imported:
            st.info("This exact file has already been imported.")
            return
        confirm = st.checkbox(
            f"I have reviewed the preview and want to import "
            f"{preview.new_events} new event(s) from '{preview.file_label}'."
        )
        if st.button("Confirm import", type="primary", disabled=not confirm):
            result = guarded(
                services.ingestion.commit,
                token,
                upload.name,
                data,
                SourceType(source),
                confirmed_sha256=preview.file_sha256,
            )
            if result:
                st.success(
                    f"Imported {result.inserted} event(s); {result.duplicates} duplicate(s)"
                    f" skipped; {result.rejected} rejected ({result.duration_ms} ms)."
                )


PAGE_SIZE = 200


def render(services: Services, token: str) -> None:
    st.title("Alerts & Event Explorer")
    principal = guarded(services.auth.resolve, token)
    if principal is None:
        return
    if has_permission(principal.role, Permission.IMPORT_EVENTS):
        _import_panel(services, token)
    if has_permission(principal.role, Permission.RUN_CORRELATION):
        col, _ = st.columns([1, 3])
        if col.button("Run detection & correlation", type="primary", width="stretch"):
            with st.spinner("Evaluating rules, correlation and behavioural analytics…"):
                summary = guarded(services.detection.run, token)
            if summary:
                st.success(
                    f"Scanned {summary.events_scanned} events in {summary.duration_ms} ms: "
                    f"{summary.findings_new} new rule finding(s), {summary.indicators_new} new "
                    f"behavioural indicator(s), {summary.incidents_new} new incident(s) "
                    f"({summary.anomaly_incidents_new} anomaly-only), {summary.links_new} new "
                    f"incident link(s)."
                )
                if summary.coverage_gaps:
                    st.info(
                        f"{summary.coverage_gaps} entities lacked enough history for "
                        "behavioural baselines. See Detections & ATT&CK → Behavioural "
                        "analytics. No alert is not proof of safety."
                    )

    facets = guarded(services.ingestion.facets, token) or {}
    with st.container(border=True):
        c = st.columns([2, 1, 1, 1, 1])
        text = c[0].text_input("Search message / command line / process / event id", "")
        users = c[1].multiselect("User", facets.get("username", []))
        hosts = c[2].multiselect("Host", facets.get("host", []))
        types = c[3].multiselect("Event type", facets.get("event_type", []))
        sevs = c[4].multiselect("Severity", facets.get("severity", []))
        c2 = st.columns([1, 1, 2])
        sort = c2[0].selectbox(
            "Sort by", ["timestamp", "severity", "event_type", "username", "host"]
        )
        desc = c2[1].toggle("Newest first", value=True)
    base = EventFilter(
        text=text or None,
        usernames=users,
        hosts=hosts,
        event_types=types,
        severities=sevs,
        sort=sort,
        descending=desc,
        limit=PAGE_SIZE,
    )
    total = guarded(services.ingestion.count, token, base) or 0
    if not total:
        empty_state("No events match", "Import data or relax the filters.")
        _retention_panel(services, token, principal)
        return
    pages = max(1, -(-total // PAGE_SIZE))
    page = st.number_input(f"Page (1-{pages}) · {total:,} matching event(s)", 1, pages, 1)
    base.offset = (page - 1) * PAGE_SIZE
    rows = guarded(services.ingestion.search, token, base) or []
    df = pd.DataFrame(rows)
    st.dataframe(df[TABLE_COLS], hide_index=True, width="stretch", height=420)
    st.download_button(
        "Export this page (CSV)", safe_csv(df[TABLE_COLS]), "aegisintel_events.csv", "text/csv"
    )
    with st.expander("Inspect original evidence and provenance"):
        event_id = st.selectbox("Event", df["id"].tolist())
        row = df[df["id"] == event_id].iloc[0]
        notes = json.loads(row.get("normalization_notes") or "[]")
        st.caption(
            f"Import #{row['import_id']} · source {row['source_type']} · ingested "
            f"{row['ingested_at']} · original timestamp: "
            f"{row.get('original_timestamp') or 'not recorded (imported before v2)'}"
        )
        if notes:
            st.caption("Normalisation: " + "; ".join(notes))
        st.code(row["raw_json"], language="json")
    if has_permission(principal.role, Permission.UPDATE_INCIDENT):
        _flag_panel(services, token, df)
    _retention_panel(services, token, principal)


def _flag_panel(services: Services, token: str, df: pd.DataFrame) -> None:
    with st.expander("Flag suspicious events for investigation (no rule matched)"):
        st.caption(
            "No rule match is not proof of safety. Use this when your own judgement "
            "says something is wrong. The incident is labelled 'Suspicious - no rule "
            "match' with low confidence until other evidence is attached."
        )
        with st.form("flag"):
            picked = st.multiselect(
                "Events (from this page)",
                df["id"].tolist(),
                format_func=lambda i: (
                    lambda r: (
                        f"{i} · {r['timestamp']} · {r['event_type']} "
                        f"· {r['username'] or '-'}@{r['host'] or '-'}"
                    )
                )(df[df["id"] == i].iloc[0]),
            )
            title = st.text_input("Incident title", max_chars=200)
            reason = st.text_area("Why is this suspicious?", max_chars=2000)
            severity = st.selectbox(
                "Potential impact (severity)", [s.value for s in Severity], index=2
            )
            if st.form_submit_button("Create incident"):
                iid = guarded(
                    services.incidents.flag_events,
                    token,
                    picked,
                    title=title,
                    reason=reason,
                    severity=Severity(severity),
                )
                if iid:
                    st.session_state["incident_id"] = iid
                    st.success(f"Incident #{iid} created. Open it from the Incident Queue.")


def _retention_panel(services: Services, token: str, principal) -> None:
    if not has_permission(principal.role, Permission.MANAGE_SYSTEM):
        return
    imports = guarded(services.ingestion.list_imports, token) or []
    with st.expander("Data retention: delete an import (administrators)"):
        if not imports:
            st.caption("No imports.")
            return
        st.warning(
            "Deletion is permanent. It removes the import's events and every incident "
            "built on them (findings, reports, notes, proposals). Take a backup first: "
            "scripts\\backup_db.py. The audit log keeps a record of the deletion "
            "(counts only)."
        )
        choice = st.selectbox(
            "Import",
            imports,
            format_func=lambda i: (
                f"#{i['id']} {i['file_label']} · {i['inserted_count']} events · "
                f"{i['created_at']} by {i['imported_by_name']}"
            ),
        )
        impact = guarded(services.ingestion.purge_impact, token, choice["id"])
        if impact:
            st.write(
                f"Will delete **{impact['events']}** event(s) and "
                f"**{len(impact['incident_ids'])}** incident(s): "
                f"{', '.join(f'#{i}' for i in impact['incident_ids']) or 'none'}."
            )
            with st.form("purge"):
                typed = st.text_input(f"Type the file name to confirm: {choice['file_label']}")
                if st.form_submit_button("Delete permanently"):
                    removed = guarded(
                        services.ingestion.purge_import, token, choice["id"], confirm_label=typed
                    )
                    if removed:
                        st.session_state.pop("incident_id", None)
                        st.session_state["flash"] = (
                            f"Deleted {removed['events_deleted']} event(s) and "
                            f"{removed['incidents_deleted']} incident(s). Rebuild the "
                            "similarity index if you use it."
                        )
                        st.rerun()
