"""Detection layers (Sigma subset, correlation, behavioural analytics) and ATT&CK coverage."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from threatlens.security.rbac import Permission, has_permission
from threatlens.services.container import Services
from threatlens.ui.components import guarded


def render(services: Services, token: str) -> None:
    st.title("Detections & ATT&CK Mappings")
    info = guarded(services.detection.describe_rules, token)
    if info is None:
        return
    st.caption(
        f"ATT&CK dataset: {info['attack_dataset']}. Detection runs without the AI model; "
        "no detection firing is never proof that an environment is safe."
    )
    t1, t2, t3, t4, t5 = st.tabs(
        [
            "Sigma rules",
            "Correlation rules",
            "Behavioural analytics",
            "ATT&CK coverage",
            "Similarity index",
        ]
    )
    with t1:
        st.caption(
            "Supported Sigma subset only. Unsupported constructs are rejected at load "
            "time (see docs/SIGMA_SUBSET.md)."
        )
        for r in info["sigma"]:
            with st.expander(f"[{r['level']}] {r['title']}"):
                st.write(r["description"])
                st.markdown(
                    f"**Condition:** `{r['condition']}`  \n**Techniques:** "
                    f"{', '.join(r['techniques']) or '—'}  \n**File:** `{r['file']}`  \n"
                    f"**ID:** `{r['id']}`  \n**Version:** `{r['version']}`"
                )
                st.caption("Known false positives: " + "; ".join(r["falsepositives"] or ["—"]))
        if info["rejected"]:
            st.error("Rejected rule files:")
            st.dataframe(
                pd.DataFrame(info["rejected"], columns=["file", "reason"]), hide_index=True
            )
    with t2:
        st.caption(
            f"Logic version: `{info['correlation_version']}` (changes when thresholds "
            "change, so every finding records the exact logic that produced it)."
        )
        for rid, desc in info["correlation"].items():
            st.markdown(f"**{rid}** — {desc}")
    with t3:
        st.caption(
            f"Detector logic v{info['behavior_version']}. Each detector compares an event with "
            "the same user's or host's own history and explains the result. Scores (0-1) are "
            "anomaly strength, not a probability of compromise. When history is too thin, the "
            "detector records a coverage gap instead of guessing."
        )
        for did, desc in info["behavior"].items():
            st.markdown(f"**{did}** — {desc}")
        with st.expander("Thresholds in effect"):
            st.json(info["behavior_config"])
        coverage = info["coverage"]
        st.markdown("**Coverage gaps from the last detection run**")
        if coverage is None:
            st.caption("Detection has not been run yet.")
        elif not coverage["gaps"]:
            st.success(f"No baseline gaps (run at {coverage['generated_at']}).")
        else:
            st.warning(
                "These entities lacked enough history to be judged. Unusual activity "
                "involving them would not be detected by behavioural analytics."
            )
            st.dataframe(pd.DataFrame(coverage["gaps"]), hide_index=True, width="stretch")
    with t4:
        rows = guarded(services.incidents.attack_overview, token) or []
        if rows:
            df = pd.DataFrame(rows)
            summary = (
                df.groupby(["technique_id", "technique_name", "tactics"])
                .agg(
                    incidents=("incident_id", "nunique"),
                    sources=("source", lambda s: ", ".join(sorted(set(s)))),
                )
                .reset_index()
                .sort_values("incidents", ascending=False)
            )
            st.dataframe(summary, hide_index=True, width="stretch")
            st.caption(
                "Mappings indicate behaviour consistent with a technique. They do not "
                "prove malicious intent. Review them per incident in the workspace."
            )
        else:
            st.info("No mappings yet. Run detection first.")
    with t5:
        st.caption(
            "Optional semantic search for behaviourally similar past incidents. Needs "
            "the local embedding model in Ollama. Results are leads, not proof."
        )
        st.json(services.retrieval.status())
        principal = guarded(services.auth.resolve, token)
        if (
            principal
            and has_permission(principal.role, Permission.RUN_CORRELATION)
            and st.button("Rebuild similarity index")
        ):
            with st.spinner("Embedding incident summaries locally…"):
                n = guarded(services.retrieval.reindex, token)
            if n is not None:
                st.success(f"Indexed {n} incident(s).")
