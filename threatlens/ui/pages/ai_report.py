"""AI investigation report: generate, view, verify claims against stored event IDs."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from threatlens.security.rbac import Permission, has_permission
from threatlens.services.container import Services
from threatlens.ui.components import esc, guarded, html_line, require_incident, status_badge


def _claims_table(items: list[dict], text_key: str, ids_key: str, known: set[str]) -> None:
    rows = [
        {
            "claim": i[text_key],
            "cited events": ", ".join(i[ids_key]),
            "verified": "yes" if set(i[ids_key]) <= known else "NO",
        }
        for i in items
    ]
    if rows:
        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
    else:
        st.caption("None.")


def render(services: Services, token: str) -> None:
    st.title("AI Investigation Report")
    iid = require_incident()
    if iid is None:
        return
    principal = guarded(services.auth.resolve, token)
    detail = guarded(services.incidents.detail, token, iid)
    if not principal or not detail:
        return
    st.subheader(f"#{iid} · {detail['incident']['title']}")
    st.markdown(
        '<span class="tl-ai">AI-GENERATED · REVIEW REQUIRED</span> '
        "Reports are hypotheses for an analyst. They cannot change incidents, severity "
        "or permissions, and recommendations are never executed automatically.",
        unsafe_allow_html=True,
    )

    if has_permission(principal.role, Permission.RUN_AI_INVESTIGATION):
        st.caption(
            f"Model: `{services.settings.ollama_model}` (local Ollama). On CPU-only "
            "machines this can take several minutes."
        )
        if st.button("Generate investigation report", type="primary"):
            with st.status("Running local model and validating output…", expanded=False):
                guarded(services.investigation.investigate, token, iid)
            st.rerun()

    reports = guarded(services.investigation.reports_for_incident, token, iid) or []
    if not reports:
        st.info("No reports yet for this incident.")
        return
    choice = st.selectbox(
        "Report",
        reports,
        format_func=lambda r: (
            f"#{r['id']} · {r['created_at']} · {r['status']} · {r['model']}"
            f" · by {r['created_by_name']}"
        ),
    )
    rep = choice["report"]
    known = {e["id"] for e in detail["events"]}

    html_line(
        status_badge(choice["status"]),
        f'<span class="tl-muted">attempts {choice["attempts"]} · '
        f"{choice['duration_ms'] / 1000:.1f}s · evidence sufficiency: "
        f"<b>{esc(rep.get('evidence_sufficiency'))}</b> · "
        f"{rep['context']['events_in_context']} events in context, "
        f"{rep['context']['events_omitted']} omitted</span>",
    )
    if choice["status"] == "fallback":
        st.warning(
            "The AI model was unavailable or returned invalid output. This deterministic "
            "summary was produced from stored findings instead."
        )
    if rep.get("injection_warnings"):
        st.error(
            "Possible prompt-injection content detected in evidence (flagged by a "
            "deterministic scanner, independent of the model):"
        )
        st.dataframe(pd.DataFrame(rep["injection_warnings"]), hide_index=True, width="stretch")
    for note in choice["validation_notes"]:
        st.caption(f"Validation: {note}")

    st.markdown("#### Summary")
    st.text(rep["summary"])
    st.markdown("#### Timeline (timestamps taken from stored events)")
    if rep["timeline"]:
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "timestamp": t["timestamp"],
                        "description": t["description"],
                        "events": ", ".join(t["event_ids"]),
                    }
                    for t in rep["timeline"]
                ]
            ),
            hide_index=True,
            width="stretch",
        )
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("#### Observations (facts)")
        _claims_table(rep["observations"], "statement", "event_ids", known)
    with c2:
        st.markdown("#### Hypotheses (interpretation)")
        _claims_table(
            [
                {**h, "statement": f"[{h['confidence']}] {h['statement']}"}
                for h in rep["hypotheses"]
            ],
            "statement",
            "supporting_event_ids",
            known,
        )
    c1, c2, c3 = st.columns(3)
    for col, title, key in (
        (c1, "Alternative explanations", "alternative_explanations"),
        (c2, "Missing evidence", "missing_evidence"),
        (c3, "Suggested next steps", "next_steps"),
    ):
        with col:
            st.markdown(f"#### {title}")
            for item in rep[key] or ["—"]:
                st.text(f"• {item}")
    st.markdown("#### AI-suggested ATT&CK techniques (validated IDs only)")
    if rep["attack_techniques"]:
        st.dataframe(pd.DataFrame(rep["attack_techniques"]), hide_index=True, width="stretch")
        st.caption(
            "AI suggestions are candidates. Confirming one records it as an "
            "analyst-confirmed mapping (re-validated against the dataset and evidence)."
        )
        if (
            has_permission(principal.role, Permission.UPDATE_INCIDENT)
            and choice["status"] == "validated"
        ):
            c1, c2 = st.columns([3, 1])
            pick = c1.selectbox(
                "Suggested technique",
                range(len(rep["attack_techniques"])),
                format_func=lambda i: (
                    f"{rep['attack_techniques'][i]['technique_id']} "
                    f"{rep['attack_techniques'][i].get('technique_name', '')}"
                ),
            )
            if c2.button("Confirm mapping", width="stretch") and guarded(
                services.incidents.confirm_ai_technique, token, choice["id"], int(pick)
            ):
                st.success(
                    "Mapping confirmed. It now appears in the workspace as 'ai / confirmed'."
                )
    else:
        st.caption("None.")

    st.markdown("#### Containment recommendations")
    st.markdown(
        '<span class="tl-sim">NOT EXECUTED</span> Promote a recommendation to a '
        "proposal to send it for human approval.",
        unsafe_allow_html=True,
    )
    can_propose = (
        has_permission(principal.role, Permission.PROPOSE_RESPONSE)
        and choice["status"] == "validated"
    )
    for idx, rec in enumerate(rep["containment_recommendations"]):
        with st.container(border=True):
            st.markdown(f"**{esc(rec['action_type'])}** → `{esc(rec['target'])}`")
            st.text(rec["rationale"])
            st.caption("Evidence: " + ", ".join(rec["event_ids"]))
            if can_propose and st.button("Create proposal", key=f"prop-{choice['id']}-{idx}"):
                if guarded(services.response.propose_from_report, token, choice["id"], idx):
                    st.success("Proposal created and awaiting approval.")
    if not rep["containment_recommendations"]:
        st.caption("None.")
