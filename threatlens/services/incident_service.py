"""Incident queue, investigation detail, status workflow, assignment and notes."""

from __future__ import annotations

import json
import uuid
from typing import Any

from threatlens.db.database import Database
from threatlens.errors import ConflictError, NotFoundError, ValidationFailedError
from threatlens.integrations.attack import load_catalog
from threatlens.models.domain import Disposition, IncidentStatus, Role, Severity
from threatlens.repositories import audit_repo, event_repo, incident_repo, user_repo
from threatlens.security.rbac import Permission
from threatlens.services.auth_service import AuthService
from threatlens.timeutil import utcnow_iso

S = IncidentStatus
ALLOWED_TRANSITIONS: dict[IncidentStatus, set[IncidentStatus]] = {
    S.NEW: {S.TRIAGE, S.INVESTIGATING, S.FALSE_POSITIVE},
    S.TRIAGE: {S.INVESTIGATING, S.FALSE_POSITIVE, S.RESOLVED},
    S.INVESTIGATING: {S.CONTAINED, S.RESOLVED, S.FALSE_POSITIVE},
    S.CONTAINED: {S.RESOLVED, S.INVESTIGATING},
    S.RESOLVED: {S.INVESTIGATING},
    S.FALSE_POSITIVE: {S.TRIAGE},
}


class IncidentService:
    def __init__(self, db: Database, auth: AuthService) -> None:
        self.db = db
        self.auth = auth

    def list_incidents(self, token: str, **filters: Any) -> list[dict[str, Any]]:
        self.auth.authorize(token, Permission.VIEW_INCIDENTS)
        with self.db.connect() as conn:
            return [dict(r) for r in incident_repo.list_incidents(conn, **filters)]

    def count(self, token: str, **filters: Any) -> int:
        self.auth.authorize(token, Permission.VIEW_INCIDENTS)
        with self.db.connect() as conn:
            return incident_repo.count_incidents(conn, **filters)

    def detail(self, token: str, incident_id: int) -> dict[str, Any]:
        self.auth.authorize(token, Permission.VIEW_INCIDENTS)
        catalog = load_catalog()
        with self.db.connect() as conn:
            incident = incident_repo.get_incident(conn, incident_id)
            if incident is None:
                raise NotFoundError()
            mappings = incident_repo.mappings_for_incident(conn, incident_id)
            for m in mappings:
                t = catalog.techniques.get(m["technique_id"])
                m["technique_name"] = t.name if t else "(not in loaded dataset)"
                m["tactics"] = list(t.tactics) if t else []
                m["url"] = t.url if t else ""
            return {
                "incident": dict(incident),
                "events": [dict(r) for r in incident_repo.incident_events(conn, incident_id)],
                "findings": incident_repo.findings_for_incident(conn, incident_id),
                "mappings": mappings,
                "notes": [dict(r) for r in incident_repo.notes(conn, incident_id)],
                "indicators": incident_repo.indicators_for_incident(conn, incident_id),
                "links": incident_repo.links_for_incident(conn, incident_id),
            }

    # --- analyst judgement -------------------------------------------------------------------

    def flag_events(
        self, token: str, event_ids: list[str], *, title: str, reason: str, severity: Severity
    ) -> int:
        """Open an incident for activity no rule or detector caught.

        No rule match is not proof of safety. This lets an analyst put their own suspicion on
        the record, with the evidence, for investigation.
        """
        actor = self.auth.authorize(token, Permission.UPDATE_INCIDENT)
        severity = Severity(severity)
        ids = list(dict.fromkeys(e.strip() for e in event_ids if e and e.strip()))
        title, reason = (title or "").strip(), (reason or "").strip()
        if not 1 <= len(ids) <= 200:
            raise ValidationFailedError("Select between 1 and 200 events to flag.")
        if not 5 <= len(title) <= 200 or not 10 <= len(reason) <= 2000:
            raise ValidationFailedError(
                "A title (5-200 characters) and a reason (10-2000 characters) are required."
            )
        with self.db.transaction() as conn:
            events = event_repo.get_events(conn, ids)
            if len(events) != len(ids):
                raise ValidationFailedError("One or more selected events do not exist.")
            cur = conn.execute(
                "INSERT INTO incidents (title, description, severity, correlation_key, rule_id,"
                " first_seen, last_seen, detection_status, confidence, confidence_rationale,"
                " created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    title,
                    reason,
                    severity.value,
                    f"ANALYST|{uuid.uuid4().hex}",
                    "ANALYST-FLAG",
                    events[0]["timestamp"],
                    events[-1]["timestamp"],
                    "suspicious_unmatched",
                    "low",
                    "Raised by an analyst for review; no automated signal attached yet.",
                    utcnow_iso(),
                    utcnow_iso(),
                ),
            )
            incident_id = int(cur.lastrowid or 0)
            incident_repo.link_incident_events(conn, incident_id, ids)
            incident_repo.add_note(
                conn, incident_id, actor.user_id, f"[Flagged by analyst] {reason}"
            )
            audit_repo.append(
                conn,
                action="incident.flag",
                outcome="success",
                actor_id=actor.user_id,
                actor_username=actor.username,
                target_type="incident",
                target_id=incident_id,
                details={"events": len(ids), "severity": severity.value},
            )
        return incident_id

    def set_disposition(
        self, token: str, incident_id: int, disposition: Disposition, note: str
    ) -> bool:
        actor = self.auth.authorize(token, Permission.UPDATE_INCIDENT)
        disposition = Disposition(disposition)
        note = (note or "").strip()
        if not 5 <= len(note) <= 2000:
            raise ValidationFailedError("A justification of 5-2000 characters is required.")
        with self.db.transaction() as conn:
            incident = incident_repo.get_incident(conn, incident_id)
            if incident is None:
                raise NotFoundError()
            conn.execute(
                "UPDATE incidents SET disposition = ?, disposition_by = ?, disposition_at = ?,"
                " disposition_note = ?, updated_at = ? WHERE id = ?",
                (disposition.value, actor.user_id, utcnow_iso(), note, utcnow_iso(), incident_id),
            )
            audit_repo.append(
                conn,
                action="incident.disposition",
                outcome="success",
                actor_id=actor.user_id,
                actor_username=actor.username,
                target_type="incident",
                target_id=incident_id,
                details={
                    "from": incident["disposition"],
                    "to": disposition.value,
                    "note": note[:500],
                },
            )
        return True

    def review_mapping(self, token: str, mapping_id: int, decision: str) -> bool:
        actor = self.auth.authorize(token, Permission.UPDATE_INCIDENT)
        if decision not in ("confirmed", "rejected", "candidate"):
            raise ValidationFailedError("Unknown review decision.")
        with self.db.transaction() as conn:
            row = conn.execute(
                "SELECT incident_id, technique_id FROM attack_mappings WHERE id = ?", (mapping_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError()
            conn.execute(
                "UPDATE attack_mappings SET review_status = ?, reviewed_by = ?, reviewed_at = ?"
                " WHERE id = ?",
                (decision, actor.user_id, utcnow_iso(), mapping_id),
            )
            audit_repo.append(
                conn,
                action="attack.review",
                outcome="success",
                actor_id=actor.user_id,
                actor_username=actor.username,
                target_type="incident",
                target_id=row["incident_id"],
                details={"technique": row["technique_id"], "decision": decision},
            )
        return True

    def confirm_ai_technique(self, token: str, report_id: int, index: int) -> bool:
        """Promote a validated AI-suggested technique to an analyst-confirmed mapping."""
        actor = self.auth.authorize(token, Permission.UPDATE_INCIDENT)
        catalog = load_catalog()
        with self.db.transaction() as conn:
            row = conn.execute(
                "SELECT incident_id, status, report_json FROM investigation_reports WHERE id = ?",
                (report_id,),
            ).fetchone()
            if row is None:
                raise NotFoundError()
            if row["status"] != "validated":
                raise ValidationFailedError("Only validated AI reports can supply mappings.")
            techniques = json.loads(row["report_json"]).get("attack_techniques", [])
            if not 0 <= index < len(techniques):
                raise NotFoundError()
            t = techniques[index]
            tech = catalog.get(str(t["technique_id"]))  # re-validate; never trust stored JSON
            evidence = set(incident_repo.incident_event_ids(conn, row["incident_id"]))
            cited = [e for e in t.get("event_ids", []) if e in evidence]
            if not cited:
                raise ValidationFailedError("The suggestion cites no evidence in this incident.")
            conn.execute(
                "INSERT OR IGNORE INTO attack_mappings (incident_id, finding_id, technique_id,"
                " source, confidence, rationale, evidence_ids, dataset_version, created_at,"
                " review_status, reviewed_by, reviewed_at)"
                " VALUES (?, NULL, ?, 'ai', ?, ?, ?, ?, ?, 'confirmed', ?, ?)",
                (
                    row["incident_id"],
                    tech.id,
                    t.get("confidence", "low"),
                    f"[AI-suggested, analyst-confirmed] {str(t.get('rationale', ''))[:800]}",
                    json.dumps(cited),
                    catalog.label,
                    utcnow_iso(),
                    actor.user_id,
                    utcnow_iso(),
                ),
            )
            audit_repo.append(
                conn,
                action="attack.confirm_ai",
                outcome="success",
                actor_id=actor.user_id,
                actor_username=actor.username,
                target_type="incident",
                target_id=row["incident_id"],
                details={"technique": tech.id, "report_id": report_id},
            )
        return True

    def change_status(
        self, token: str, incident_id: int, new_status: IncidentStatus, reason: str = ""
    ) -> bool:
        actor = self.auth.authorize(token, Permission.UPDATE_INCIDENT)
        new_status = IncidentStatus(new_status)
        with self.db.transaction() as conn:
            incident = incident_repo.get_incident(conn, incident_id)
            if incident is None:
                raise NotFoundError()
            current = IncidentStatus(incident["status"])
            if new_status not in ALLOWED_TRANSITIONS[current]:
                raise ValidationFailedError(
                    f"Cannot move an incident from '{current.value}' to '{new_status.value}'."
                )
            if not incident_repo.update_status(conn, incident_id, new_status.value, current.value):
                raise ConflictError()
            audit_repo.append(
                conn,
                action="incident.status",
                outcome="success",
                actor_id=actor.user_id,
                actor_username=actor.username,
                target_type="incident",
                target_id=incident_id,
                details={"from": current.value, "to": new_status.value, "reason": reason[:500]},
            )
        return True

    def assign(self, token: str, incident_id: int, user_id: int | None) -> bool:
        actor = self.auth.authorize(token, Permission.UPDATE_INCIDENT)
        with self.db.transaction() as conn:
            if incident_repo.get_incident(conn, incident_id) is None:
                raise NotFoundError()
            if user_id is not None:
                assignee = user_repo.get_user(conn, user_id)
                if (
                    assignee is None
                    or not assignee.is_active
                    or assignee.role not in (Role.ANALYST, Role.ADMIN)
                ):
                    raise ValidationFailedError(
                        "Incidents can only be assigned to active analysts."
                    )
            incident_repo.assign(conn, incident_id, user_id)
            audit_repo.append(
                conn,
                action="incident.assign",
                outcome="success",
                actor_id=actor.user_id,
                actor_username=actor.username,
                target_type="incident",
                target_id=incident_id,
                details={"assignee_id": user_id},
            )
        return True

    def add_note(self, token: str, incident_id: int, body: str) -> int:
        actor = self.auth.authorize(token, Permission.UPDATE_INCIDENT)
        body = (body or "").strip()
        if not 1 <= len(body) <= 4000:
            raise ValidationFailedError("Notes must be 1-4000 characters.")
        with self.db.transaction() as conn:
            if incident_repo.get_incident(conn, incident_id) is None:
                raise NotFoundError()
            note_id = incident_repo.add_note(conn, incident_id, actor.user_id, body)
            audit_repo.append(
                conn,
                action="incident.note",
                outcome="success",
                actor_id=actor.user_id,
                actor_username=actor.username,
                target_type="incident",
                target_id=incident_id,
            )
        return note_id

    def attack_overview(self, token: str) -> list[dict[str, Any]]:
        self.auth.authorize(token, Permission.VIEW_RULES)
        catalog = load_catalog()
        with self.db.connect() as conn:
            rows = [dict(r) for r in incident_repo.all_mappings(conn)]
        for r in rows:
            t = catalog.techniques.get(r["technique_id"])
            r["technique_name"] = t.name if t else "(unknown)"
            r["tactics"] = ", ".join(t.tactics) if t else ""
        return rows

    def dashboard_stats(self, token: str) -> dict[str, Any]:
        self.auth.authorize(token, Permission.VIEW_DASHBOARD)
        with self.db.connect() as conn:
            q = conn.execute
            return {
                "events": q("SELECT COUNT(*) FROM events").fetchone()[0],
                "imports": q("SELECT COUNT(*) FROM imports").fetchone()[0],
                "incidents_open": q(
                    "SELECT COUNT(*) FROM incidents WHERE status NOT IN"
                    " ('resolved','false_positive')"
                ).fetchone()[0],
                "incidents_by_severity": {
                    r[0]: r[1]
                    for r in q(
                        "SELECT severity, COUNT(*) FROM incidents WHERE status NOT IN"
                        " ('resolved','false_positive') GROUP BY severity"
                    )
                },
                "incidents_by_status": {
                    r[0]: r[1] for r in q("SELECT status, COUNT(*) FROM incidents GROUP BY status")
                },
                "events_by_hour": [
                    dict(r)
                    for r in q(
                        "SELECT substr(timestamp, 1, 13) || ':00Z' AS hour, COUNT(*) AS events"
                        " FROM events GROUP BY hour ORDER BY hour"
                    )
                ],
                "events_by_category": {
                    r[0]: r[1] for r in q("SELECT category, COUNT(*) FROM events GROUP BY category")
                },
                "incidents_by_detection": {
                    r[0]: r[1]
                    for r in q(
                        "SELECT detection_status, COUNT(*) FROM incidents WHERE status NOT IN"
                        " ('resolved','false_positive') GROUP BY detection_status"
                    )
                },
                "incidents_by_disposition": {
                    r[0]: r[1]
                    for r in q("SELECT disposition, COUNT(*) FROM incidents GROUP BY disposition")
                },
                "pending_approvals": q(
                    "SELECT COUNT(*) FROM response_proposals WHERE status = 'pending'"
                ).fetchone()[0],
                "top_techniques": [
                    dict(r)
                    for r in q(
                        "SELECT technique_id, COUNT(DISTINCT incident_id) AS incidents"
                        " FROM attack_mappings WHERE review_status != 'rejected'"
                        " GROUP BY technique_id"
                        " ORDER BY incidents DESC LIMIT 8"
                    )
                ],
            }

    def event_lookup(self, token: str, event_ids: list[str]) -> list[dict[str, Any]]:
        self.auth.authorize(token, Permission.VIEW_EVENTS)
        with self.db.connect() as conn:
            return [dict(r) for r in event_repo.get_events(conn, event_ids[:500])]
