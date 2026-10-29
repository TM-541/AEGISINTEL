"""Human-approved, SIMULATED response actions.

State machine: pending → approved → executed, or pending → rejected.
* Every transition is a conditional ``UPDATE ... WHERE status = <expected>`` in a write
  transaction. Replays and double decisions fail with ConflictError.
* Approval and execution each need an explicit ``confirm=True`` and a written reason.
* Two-person rule (on by default): whoever proposed an action cannot approve it.
* AI recommendations become proposals only when an analyst promotes one from a stored,
  validated report. The model never creates proposals.
* No action touches a real system. Results are labelled SIMULATED.
"""

from __future__ import annotations

import json
import secrets
from typing import Any

from threatlens.config import Settings
from threatlens.db.database import Database
from threatlens.errors import (
    AuthorizationError,
    ConflictError,
    NotFoundError,
    ValidationFailedError,
)
from threatlens.models.domain import ProposalStatus
from threatlens.models.report import SimulatedAction
from threatlens.repositories import audit_repo, incident_repo
from threatlens.security.rbac import Permission
from threatlens.services.auth_service import AuthService
from threatlens.timeutil import utcnow_iso

SIMULATION_TEXT = {
    SimulatedAction.ESCALATE_INCIDENT: "Incident flagged for escalation to tier-2 (note added).",
    SimulatedAction.PREPARE_CHECKLIST: "Investigation checklist generated for the incident.",
    SimulatedAction.CONTAINMENT_PLAN: "Proposed containment plan generated for review.",
    SimulatedAction.SIMULATE_ACCOUNT_DISABLE: "LAB SIMULATION: account would be disabled in the "
    "identity provider. No real account was changed.",
    SimulatedAction.SIMULATE_HOST_ISOLATION: "LAB SIMULATION: host would be network-isolated by "
    "EDR. No real host was changed.",
    SimulatedAction.SIMULATE_PASSWORD_RESET: "LAB SIMULATION: password reset would be forced. "
    "No real credential was changed.",
}
CHECKLIST = [
    "Confirm the affected user and host with the asset owner",
    "Preserve volatile evidence (memory, running processes) before containment",
    "Review authentication logs for the account across all hosts (±24h)",
    "Check for persistence: scheduled tasks, services, run keys, new local accounts",
    "Identify lateral movement from the host",
    "Document findings and decisions in the incident notes",
]


def _reason(text: str) -> str:
    text = (text or "").strip()
    if not 5 <= len(text) <= 1000:
        raise ValidationFailedError("A reason of 5-1000 characters is required.")
    return text


class ResponseService:
    def __init__(self, db: Database, auth: AuthService, settings: Settings) -> None:
        self.db = db
        self.auth = auth
        self.settings = settings

    # --- proposals ------------------------------------------------------------------------

    def propose(
        self,
        token: str,
        incident_id: int,
        action_type: SimulatedAction,
        target: str,
        rationale: str,
    ) -> int:
        actor = self.auth.authorize(token, Permission.PROPOSE_RESPONSE)
        action = SimulatedAction(action_type)
        target = (target or "").strip()[:128]
        if not target:
            raise ValidationFailedError("A target is required.")
        return self._create(
            actor,
            incident_id,
            action,
            target,
            _reason(rationale),
            "analyst",
            idempotency_key=f"analyst:{secrets.token_hex(16)}",
        )

    def propose_from_report(self, token: str, report_id: int, index: int) -> int:
        actor = self.auth.authorize(token, Permission.PROPOSE_RESPONSE)
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT incident_id, status, report_json FROM investigation_reports WHERE id = ?",
                (report_id,),
            ).fetchone()
        if row is None:
            raise NotFoundError()
        if row["status"] != "validated":
            raise ValidationFailedError("Only validated AI reports can produce proposals.")
        recs = json.loads(row["report_json"]).get("containment_recommendations", [])
        if not 0 <= index < len(recs):
            raise NotFoundError()
        rec = recs[index]
        action = SimulatedAction(rec["action_type"])  # re-validated against the allow-list
        return self._create(
            actor,
            row["incident_id"],
            action,
            str(rec["target"])[:128],
            f"[AI-suggested] {str(rec['rationale'])[:900]}",
            "ai",
            idempotency_key=f"report:{report_id}:{index}",
        )

    def _create(
        self,
        actor,
        incident_id: int,
        action: SimulatedAction,
        target: str,
        rationale: str,
        source: str,
        *,
        idempotency_key: str,
    ) -> int:
        with self.db.transaction() as conn:
            if incident_repo.get_incident(conn, incident_id) is None:
                raise NotFoundError()
            dup = conn.execute(
                "SELECT 1 FROM response_proposals WHERE idempotency_key = ? OR (incident_id = ?"
                " AND action_type = ? AND target = ? AND status = 'pending')",
                (idempotency_key, incident_id, action.value, target),
            ).fetchone()
            if dup:
                raise ConflictError("An identical proposal already exists.")
            cur = conn.execute(
                "INSERT INTO response_proposals (incident_id, action_type, target, rationale,"
                " source, proposed_by, idempotency_key, created_at) VALUES (?,?,?,?,?,?,?,?)",
                (
                    incident_id,
                    action.value,
                    target,
                    rationale,
                    source,
                    actor.user_id,
                    idempotency_key,
                    utcnow_iso(),
                ),
            )
            proposal_id = int(cur.lastrowid or 0)
            audit_repo.append(
                conn,
                action="response.propose",
                outcome="success",
                actor_id=actor.user_id,
                actor_username=actor.username,
                target_type="proposal",
                target_id=proposal_id,
                details={"incident_id": incident_id, "action": action.value, "source": source},
            )
        return proposal_id

    # --- decisions --------------------------------------------------------------------------

    def decide(
        self, token: str, proposal_id: int, *, approve: bool, reason: str, confirm: bool
    ) -> bool:
        actor = self.auth.authorize(token, Permission.DECIDE_RESPONSE)
        reason = _reason(reason)
        if not confirm:
            raise ValidationFailedError("Explicit confirmation is required.")
        new = ProposalStatus.APPROVED if approve else ProposalStatus.REJECTED
        with self.db.connect() as conn:
            proposal = conn.execute(
                "SELECT * FROM response_proposals WHERE id = ?", (proposal_id,)
            ).fetchone()
        if proposal is None:
            raise NotFoundError()
        if (
            approve
            and self.settings.response_require_two_person
            and proposal["proposed_by"] == actor.user_id
        ):
            self.auth.audit_denied(
                "response.approve",
                actor,
                target_type="proposal",
                target_id=proposal_id,
                reason="self_approval",
            )
            raise AuthorizationError("A different analyst must approve this proposal.")
        with self.db.transaction() as conn:
            cur = conn.execute(
                "UPDATE response_proposals SET status = ?, decided_by = ?, decided_at = ?,"
                " decision_reason = ? WHERE id = ? AND status = 'pending'",
                (new.value, actor.user_id, utcnow_iso(), reason, proposal_id),
            )
            if cur.rowcount != 1:
                raise ConflictError("This proposal has already been decided.")
            audit_repo.append(
                conn,
                action=f"response.{'approve' if approve else 'reject'}",
                outcome="success",
                actor_id=actor.user_id,
                actor_username=actor.username,
                target_type="proposal",
                target_id=proposal_id,
                details={"reason": reason},
            )
        return True

    def execute(self, token: str, proposal_id: int, *, confirm: bool) -> dict[str, Any]:
        actor = self.auth.authorize(token, Permission.DECIDE_RESPONSE)
        if not confirm:
            raise ValidationFailedError("Explicit confirmation is required.")
        with self.db.transaction() as conn:
            proposal = conn.execute(
                "SELECT * FROM response_proposals WHERE id = ?", (proposal_id,)
            ).fetchone()
            if proposal is None:
                raise NotFoundError()
            action = SimulatedAction(proposal["action_type"])
            result = {
                "SIMULATED": True,
                "action": action.value,
                "target": proposal["target"],
                "outcome": SIMULATION_TEXT[action],
                "executed_by": actor.username,
            }
            if action == SimulatedAction.PREPARE_CHECKLIST:
                result["checklist"] = CHECKLIST
            cur = conn.execute(
                "UPDATE response_proposals SET status = 'executed', executed_at = ?,"
                " result_json = ? WHERE id = ? AND status = 'approved'",
                (utcnow_iso(), json.dumps(result), proposal_id),
            )
            if cur.rowcount != 1:
                raise ConflictError("Only approved, not-yet-executed proposals can run.")
            if action == SimulatedAction.ESCALATE_INCIDENT:
                incident_repo.add_note(
                    conn,
                    proposal["incident_id"],
                    actor.user_id,
                    f"[SIMULATED ACTION] Escalated via proposal #{proposal_id}.",
                )
            audit_repo.append(
                conn,
                action="response.execute_simulated",
                outcome="success",
                actor_id=actor.user_id,
                actor_username=actor.username,
                target_type="proposal",
                target_id=proposal_id,
                details={"action": action.value, "simulated": True},
            )
        return result

    # --- queries ----------------------------------------------------------------------------

    def list_proposals(
        self, token: str, *, status: str | None = None, incident_id: int | None = None
    ) -> list[dict[str, Any]]:
        self.auth.authorize(token, Permission.VIEW_INCIDENTS)
        clauses: list[str] = []
        params: list[Any] = []
        if status:
            clauses.append("p.status = ?")
            params.append(ProposalStatus(status).value)
        if incident_id is not None:
            clauses.append("p.incident_id = ?")
            params.append(incident_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT p.*, i.title AS incident_title, pu.username AS proposed_by_name,"  # nosec B608 # noqa: S608
                " du.username AS decided_by_name FROM response_proposals p"
                " JOIN incidents i ON i.id = p.incident_id"
                " JOIN users pu ON pu.id = p.proposed_by"
                f" LEFT JOIN users du ON du.id = p.decided_by {where}"
                " ORDER BY p.id DESC",
                params,
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["result"] = json.loads(d.pop("result_json")) if d.get("result_json") else None
            out.append(d)
        return out
