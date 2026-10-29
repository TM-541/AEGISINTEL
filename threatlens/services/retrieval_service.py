"""Semantic "similar past incidents" retrieval.

Why vectors here: analysts want *behaviourally* similar incidents ("credential dumping after
brute force"). These share techniques and tooling but not exact titles or IDs, which SQL
filters can't express well. Everything else (event search, filters, joins) stays in SQLite.

Isolation: Chroma returns candidate IDs only. Each one is re-loaded from SQLite after the
caller is authorized. IDs that do not exist, or that fail to parse, are discarded. Content
shown to users never comes from the vector store.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from pathlib import PureWindowsPath
from typing import Any

from threatlens.db.database import Database
from threatlens.errors import AIUnavailableError, NotFoundError, ThreatLensError
from threatlens.integrations.attack import load_catalog
from threatlens.integrations.vector_store import VectorStore, VectorStoreError
from threatlens.repositories import audit_repo, incident_repo
from threatlens.security.rbac import Permission
from threatlens.services.auth_service import AuthService

log = logging.getLogger(__name__)
ID_RE = re.compile(r"^incident-(\d{1,12})$")


class RetrievalUnavailableError(ThreatLensError):
    public_message = "Similar-incident search is unavailable. Check the health page."


def incident_document(
    incident: dict[str, Any],
    findings: list[dict[str, Any]],
    mappings: list[dict[str, Any]],
    events: list[dict[str, Any]],
) -> str:
    """Behavioural description without usernames, IPs or raw log text."""
    catalog = load_catalog()
    techniques = sorted({m["technique_id"] for m in mappings})
    names = [f"{t} {catalog.techniques[t].name}" for t in techniques if t in catalog.techniques]
    processes = sorted(
        {PureWindowsPath(e["process_name"]).name.lower() for e in events if e.get("process_name")}
    )[:15]
    event_types = sorted({e["event_type"] for e in events})[:15]
    rules = sorted({f["rule_title"] for f in findings})
    return (
        f"Detections: {'; '.join(rules) or 'none'}. Techniques: {'; '.join(names) or 'none'}."
        f" Event types: {', '.join(event_types)}. Processes: {', '.join(processes) or 'none'}."
        f" Severity: {incident['severity']}."
    )


class RetrievalService:
    def __init__(
        self,
        db: Database,
        auth: AuthService,
        store_factory: Callable[[], VectorStore] | None,
        *,
        enabled: bool,
    ) -> None:
        self.db = db
        self.auth = auth
        self._factory = store_factory
        self.enabled = enabled and store_factory is not None
        self._store: VectorStore | None = None

    def _get_store(self) -> VectorStore:
        if not self.enabled or self._factory is None:
            raise RetrievalUnavailableError("Vector search is disabled in configuration.")
        if self._store is None:
            try:
                self._store = self._factory()
            except VectorStoreError as exc:
                log.warning("vector store unavailable", extra={"error": str(exc)})
                raise RetrievalUnavailableError() from exc
        return self._store

    def _document_for(self, conn, incident_id: int) -> tuple[str, dict[str, Any]]:
        incident = incident_repo.get_incident(conn, incident_id)
        if incident is None:
            raise NotFoundError()
        doc = incident_document(
            dict(incident),
            incident_repo.findings_for_incident(conn, incident_id),
            incident_repo.mappings_for_incident(conn, incident_id),
            [dict(r) for r in incident_repo.incident_events(conn, incident_id, limit=500)],
        )
        return doc, {"incident_id": incident_id, "severity": incident["severity"]}

    def reindex(self, token: str) -> int:
        """Deterministic rebuild: clear the collection and re-embed every incident."""
        actor = self.auth.authorize(token, Permission.RUN_CORRELATION)
        store = self._get_store()
        with self.db.connect() as conn:
            ids = [r[0] for r in conn.execute("SELECT id FROM incidents ORDER BY id")]
            items = [(f"incident-{i}", *self._document_for(conn, i)) for i in ids]
        try:
            store.clear()
            for start in range(0, len(items), 32):
                store.upsert(items[start : start + 32])
        except (AIUnavailableError, VectorStoreError) as exc:
            raise RetrievalUnavailableError() from exc
        with self.db.transaction() as conn:
            audit_repo.append(
                conn,
                action="vector.reindex",
                outcome="success",
                actor_id=actor.user_id,
                actor_username=actor.username,
                details={"indexed": len(items)},
            )
        return len(items)

    def remove(self, token: str, incident_ids: list[int]) -> None:
        self.auth.authorize(token, Permission.MANAGE_SYSTEM)
        self._get_store().delete([f"incident-{i}" for i in incident_ids])

    def similar(self, token: str, incident_id: int, k: int = 5) -> list[dict[str, Any]]:
        self.auth.authorize(token, Permission.SEARCH_SIMILAR)
        k = max(1, min(k, 20))
        store = self._get_store()
        with self.db.connect() as conn:
            doc, _ = self._document_for(conn, incident_id)
        try:
            candidates = store.query(doc, k + 5)
        except (AIUnavailableError, VectorStoreError) as exc:
            raise RetrievalUnavailableError() from exc
        results = []
        with self.db.connect() as conn:
            for vector_id, distance, _meta in candidates:
                m = ID_RE.fullmatch(vector_id)
                if not m or int(m.group(1)) == incident_id:
                    continue
                row = incident_repo.get_incident(conn, int(m.group(1)))
                if row is None:  # stale or foreign vector: never surfaced
                    continue
                results.append(
                    {
                        "incident_id": row["id"],
                        "title": row["title"],
                        "severity": row["severity"],
                        "status": row["status"],
                        "similarity": round(1 - distance, 4),
                    }
                )
                if len(results) >= k:
                    break
        return results

    def status(self) -> dict[str, Any]:
        if not self.enabled:
            return {"enabled": False}
        try:
            return {"enabled": True, "available": True, "indexed": self._get_store().count()}
        except RetrievalUnavailableError:
            return {"enabled": True, "available": False}
