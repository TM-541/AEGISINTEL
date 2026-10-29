"""Application health and (non-secret) configuration status."""

from __future__ import annotations

import streamlit as st

from threatlens.services.container import Services
from threatlens.ui.components import guarded

RECOVERY = {
    "database": "Stop the app, back up data/threatlens.db, then run scripts/init_db.py. If the "
    "integrity check fails, restore from backup.",
    "audit_chain": "The audit log was modified outside the application. Preserve the database "
    "file for forensic review.",
    "detection_rules": "Fix or remove the rejected rule files in rules/sigma/ and restart.",
    "ollama": "Start Ollama (`ollama serve`) and pull the configured model, e.g. "
    "`ollama pull llama3.2:3b`. The app keeps working with deterministic summaries.",
    "vector_search": "Pull the embedding model (`ollama pull nomic-embed-text`) and rebuild the "
    "index from Detections & ATT&CK, or disable vector search in .env.",
}


def render(services: Services, token: str) -> None:
    st.title("Health & Configuration")
    with st.spinner("Running checks…"):
        health = guarded(services.admin.health, token)
    if health is None:
        return
    for name, check in health["checks"].items():
        ok = check.get("ok")
        with st.container(border=True):
            label = "OK" if ok else "ATTENTION"
            st.markdown(f"**{name.replace('_', ' ').title()}** — {label}")
            st.json({k: v for k, v in check.items() if k != "ok"}, expanded=False)
            if not ok and name in RECOVERY:
                st.caption("Recovery: " + RECOVERY[name])
    st.subheader("Configuration (non-secret)")
    st.json(health["config"])
