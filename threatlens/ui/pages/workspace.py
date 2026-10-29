"""Incident investigation workspace: assessment, verdict, evidence layers, links, notes."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from threatlens.detection.behavior import strength_label
from threatlens.models.domain import Disposition, IncidentStatus
from threatlens.models.report import SimulatedAction
from threatlens.security.rbac import Permission, has_permission
from threatlens.services.container import Services
from threatlens.services.incident_service import ALLOWED_TRANSITIONS
from threatlens.ui import nav
from threatlens.ui.components import (
    assessment_line,
    esc,
    guarded,
    html_line,
    require_incident,
    severity_badge,
)

DISPOSITION_HELP = {
    "undetermined": "No verdict yet.",
    "true_positive": "Malicious or policy-violating activity confirmed.",
    "benign_confirmed": "Activity confirmed legitimate (e.g. authorised admin work).",
    "false_positive": "The detection fired incorrectly.",
    "inconclusive": "Investigated, but the evidence does not settle it.",
    "insufficient_telemetry": "Logs do not contain enough evidence to decide.",
}


def render(services: Services, token: str) -> None:
    st.title("Investigation Workspace")
    iid = require_incident()
    if iid is None:
        return
    detail = guarded(services.incidents.detail, token, iid)
    principal = guarded(services.auth.resolve, token)
    if not detail or not principal:
        return
    inc = detail["incident"]
    can_edit = has_permission(principal.role, Permission.UPDATE_INCIDENT)

    st.subheader(f"#{inc['id']} · {inc['title']}")
    assessment_line(inc)
    st.caption(
        f"Assigned: {inc['assignee'] or 'unassigned'} · {inc['first_seen']} → {inc['last_seen']}"
        f" · source {inc['rule_id']} · Confidence basis: {inc.get('confidence_rationale') or '—'}"
    )
    st.text(inc["description"])
    if inc.get("disposition_note"):
        st.info(f"Analyst verdict note: {inc['disposition_note']}")

    if can_edit:
        _workflow_controls(services, token, iid, inc)

    tabs = st.tabs(
        [
            f"Rule findings ({len(detail['findings'])})",
            f"Behavioural indicators ({len(detail['indicators'])})",
            f"ATT&CK mappings ({len(detail['mappings'])})",
            f"Related incidents ({len(detail['links'])})",
            "Similar incidents",
            f"Notes ({len(detail['notes'])})",
            "Propose response",
        ]
    )
    with tabs[0]:
        _findings(detail)
    with tabs[1]:
        _indicators(detail)
    with tabs[2]:
        _mappings(services, token, detail, can_edit)
    with tabs[3]:
        _links(detail)
    with tabs[4]:
        _similar(services, token, iid, principal)
    with tabs[5]:
        _notes(services, token, iid, detail, can_edit)
    with tabs[6]:
        _propose(services, token, iid, principal)


def _workflow_controls(services: Services, token: str, iid: int, inc: dict) -> None:
    with st.container(border=True):
        st.markdown("**Workflow**")
        c = st.columns([1.2, 2, 1.2, 1])
        options = sorted(s.value for s in ALLOWED_TRANSITIONS[IncidentStatus(inc["status"])])
        new_status = c[0].selectbox("Move to status", options)
        reason = c[1].text_input("Reason (recorded in audit log)")
        if c[2].button("Update status", width="stretch") and guarded(
            services.incidents.change_status, token, iid, IncidentStatus(new_status), reason
        ):
            st.rerun()
        assignable = guarded(services.users.list_assignable, token) or []
        names = {u.username: u.id for u in assignable}
        who = c[3].selectbox("Assign", ["(unassigned)", *names])
        if c[3].button("Assign", width="stretch") and guarded(
            services.incidents.assign, token, iid, names.get(who)
        ):
            st.rerun()
    with st.expander("Record analyst verdict (disposition)"):
        st.caption(
            "Your conclusion is recorded separately from severity and confidence, "
            "and never set automatically."
        )
        with st.form("disposition"):
            values = [d.value for d in Disposition]
            choice = st.selectbox(
                "Verdict",
                values,
                index=values.index(inc.get("disposition", "undetermined")),
                format_func=lambda v: f"{v.replace('_', ' ')} — {DISPOSITION_HELP[v]}",
            )
            note = st.text_area("Justification (required, audited)", max_chars=2000)
            if st.form_submit_button("Save verdict") and guarded(
                services.incidents.set_disposition, token, iid, Disposition(choice), note
            ):
                st.rerun()


def _findings(detail: dict) -> None:
    st.caption(
        "Deterministic rule matches. A rule match is evidence for review, not proof of an attack."
    )
    if not detail["findings"]:
        st.info(
            "No detection rule matched this incident. It was raised by behavioural "
            "analytics or by an analyst. No rule match does not mean the activity is safe."
        )
    for f in detail["findings"]:
        with st.container(border=True):
            html_line(
                severity_badge(f["severity"]),
                f"<b>{esc(f['rule_title'])}</b>",
                f'<span class="tl-muted">{esc(f["engine"])} · {esc(f["rule_id"])} · version '
                f"{esc(f.get('rule_version') or 'n/a')} · matched {esc(f['created_at'])}</span>",
            )
            st.write("**Matched fields**")
            st.json(f["matched_fields"], expanded=False)
            st.caption("Supporting events: " + ", ".join(f["event_ids"]))


def _indicators(detail: dict) -> None:
    st.caption(
        "Statistical signals compared with each entity's own history. The score is "
        "anomaly strength (0-1), **not** a probability of compromise. Baselines come "
        "from imported data and may themselves contain attacker activity."
    )
    if not detail["indicators"]:
        st.caption("No behavioural indicators are attached to this incident.")
    for i in detail["indicators"]:
        with st.container(border=True):
            st.markdown(
                f"**{i['detector_id']}** · {esc(i['entity'])} · anomaly score "
                f"**{i['score']:.2f}** ({strength_label(i['score'])}) · detector "
                f"v{esc(i['detector_version'])}"
            )
            st.text(i["rationale"])
            st.caption(
                "Baseline: "
                + ", ".join(f"{k} = {v}" for k, v in i["baseline"].items())
                + " · Events: "
                + ", ".join(i["event_ids"])
            )


def _mappings(services: Services, token: str, detail: dict, can_edit: bool) -> None:
    if not detail["mappings"]:
        st.caption(
            "No ATT&CK mappings for this incident. Absence of a mapping does not mean "
            "the activity is benign."
        )
        return
    df = pd.DataFrame(detail["mappings"])
    cols = [
        "id",
        "technique_id",
        "technique_name",
        "source",
        "review_status",
        "confidence",
        "rule_title",
        "evidence_ids",
    ]
    df["evidence_ids"] = df["evidence_ids"].map(lambda ids: ", ".join(ids))
    st.dataframe(df[[c for c in cols if c in df]], hide_index=True, width="stretch")
    st.caption(
        f"Dataset: {detail['mappings'][0]['dataset_version']}. 'candidate' = proposed "
        "by a rule (or AI), awaiting analyst review. A mapping indicates behaviour "
        "consistent with a technique; it does not prove intent."
    )
    if can_edit:
        c = st.columns([2, 1, 1, 1])
        choice = c[0].selectbox(
            "Review mapping",
            df["id"].tolist(),
            format_func=lambda m: (
                lambda r: f"#{m} {r['technique_id']} {r['technique_name']} ({r['review_status']})"
            )(df[df["id"] == m].iloc[0]),
        )
        for col, label, decision in (
            (c[1], "Confirm", "confirmed"),
            (c[2], "Reject", "rejected"),
            (c[3], "Reset", "candidate"),
        ):
            if col.button(label, width="stretch", key=f"map-{decision}") and guarded(
                services.incidents.review_mapping, token, int(choice), decision
            ):
                st.rerun()


def _links(detail: dict) -> None:
    st.caption(
        "Incidents that share a user, host or IP and occurred close in time. A link "
        "is a lead to review, not evidence that the same actor is responsible."
    )
    if not detail["links"]:
        st.caption("No related incidents found.")
        return
    for lk in detail["links"]:
        with st.container(border=True):
            html_line(
                severity_badge(lk["other_severity"]),
                f"<b>#{lk['other_id']} {esc(lk['other_title'])}</b>",
                f'<span class="tl-muted">{lk["gap_minutes"]} min apart · shares '
                f"{esc(', '.join(lk['shared_entities']))}</span>",
            )
            if st.button("Open", key=f"link-{lk['other_id']}"):
                st.session_state["incident_id"] = int(lk["other_id"])
                st.rerun()


def _similar(services: Services, token: str, iid: int, principal) -> None:
    if not has_permission(principal.role, Permission.SEARCH_SIMILAR):
        st.caption("Your role cannot run similarity search.")
        return
    st.caption(
        "Behaviourally similar past incidents (local embeddings). Similar incidents are "
        "investigative leads, not proof of a common attack."
    )
    if st.button("Find similar past incidents"):
        with st.spinner("Embedding and searching locally…"):
            results = guarded(services.retrieval.similar, token, iid)
        if results == []:
            st.caption(
                "No similar incidents found. Has the index been built? See "
                "Detections & ATT&CK → Similarity index."
            )
        elif results:
            st.dataframe(pd.DataFrame(results), hide_index=True, width="stretch")


def _notes(services: Services, token: str, iid: int, detail: dict, can_edit: bool) -> None:
    for n in detail["notes"]:
        st.markdown(
            f"**{esc(n['author'])}** · <span class='tl-muted'>{esc(n['created_at'])}</span>",
            unsafe_allow_html=True,
        )
        st.text(n["body"])
    if can_edit:
        with st.form("note", clear_on_submit=True):
            body = st.text_area("Add analyst note", max_chars=4000)
            if st.form_submit_button("Save note"):
                if guarded(services.incidents.add_note, token, iid, body):
                    st.rerun()


def _propose(services: Services, token: str, iid: int, principal) -> None:
    if not has_permission(principal.role, Permission.PROPOSE_RESPONSE):
        st.caption("Your role cannot propose response actions.")
        return
    st.markdown(
        '<span class="tl-sim">SIMULATED ACTIONS ONLY</span> Proposals require '
        "approval by a different analyst.",
        unsafe_allow_html=True,
    )
    with st.form("propose", clear_on_submit=True):
        action = st.selectbox("Action", [a.value for a in SimulatedAction])
        target = st.text_input("Target (user, host or incident)", max_chars=128)
        rationale = st.text_area("Rationale", max_chars=1000)
        if st.form_submit_button("Submit proposal"):
            if guarded(
                services.response.propose, token, iid, SimulatedAction(action), target, rationale
            ):
                st.success("Proposal submitted. Open Response Approvals to track it.")
    if st.button("Open Response Approvals"):
        nav.go("responses")
