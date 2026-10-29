from __future__ import annotations

import json
import threading

import pytest

from tests.test_investigation import FakeOllama, good_report, make_services, seed
from threatlens.errors import (
    AuthorizationError,
    ConflictError,
    NotFoundError,
    ValidationFailedError,
)
from threatlens.models.domain import Role
from threatlens.models.report import SimulatedAction
from threatlens.repositories import audit_repo

A2_PW = "Second-Analyst-Pass-31"


@pytest.fixture()
def ctx(settings):
    fake = FakeOllama([])
    services = make_services(settings, fake)
    admin, iid, ids, _ = seed(services)
    services.users.create_user(admin, username="analyst2", password=A2_PW, role=Role.ANALYST)
    services.users.create_user(
        admin, username="viewer1", password="Viewer-Strong-Pass-77", role=Role.VIEWER
    )
    return {
        "s": services,
        "fake": fake,
        "admin": admin,
        "iid": iid,
        "ids": ids,
        "a2": services.auth.login("analyst2", A2_PW),
        "viewer": services.auth.login("viewer1", "Viewer-Strong-Pass-77"),
    }


def _propose(c, token=None, action=SimulatedAction.SIMULATE_HOST_ISOLATION):
    return c["s"].response.propose(
        token or c["admin"], c["iid"], action, "ws-fin-07", "Credential dumping observed on host"
    )


def test_full_lifecycle_is_simulated_and_audited(ctx):
    pid = _propose(ctx)
    ctx["s"].response.decide(ctx["a2"], pid, approve=True, reason="Evidence is clear", confirm=True)
    result = ctx["s"].response.execute(ctx["a2"], pid, confirm=True)
    assert result["SIMULATED"] is True and "No real host was changed" in result["outcome"]
    [p] = ctx["s"].response.list_proposals(ctx["admin"])
    assert p["status"] == "executed" and p["decided_by_name"] == "analyst2"
    assert p["decision_reason"] == "Evidence is clear" and p["result"]["SIMULATED"]
    with ctx["s"].db.connect() as conn:
        actions = [r["action"] for r in audit_repo.list_events(conn)]
        assert {"response.propose", "response.approve", "response.execute_simulated"} <= set(
            actions
        )
        assert audit_repo.verify_chain(conn).ok


def test_proposer_cannot_self_approve(ctx):
    pid = _propose(ctx)
    with pytest.raises(AuthorizationError):
        ctx["s"].response.decide(ctx["admin"], pid, approve=True, reason="looks fine", confirm=True)
    with ctx["s"].db.connect() as conn:
        assert audit_repo.list_events(conn, action="response.approve")[0]["outcome"] == "denied"


def test_proposer_may_reject_own_proposal(ctx):
    pid = _propose(ctx)
    ctx["s"].response.decide(ctx["admin"], pid, approve=False, reason="withdrawn", confirm=True)
    assert ctx["s"].response.list_proposals(ctx["admin"])[0]["status"] == "rejected"


def test_two_person_rule_can_be_disabled_for_single_user_labs(ctx):
    ctx["s"].settings.response_require_two_person = False
    pid = _propose(ctx)
    ctx["s"].response.decide(ctx["admin"], pid, approve=True, reason="lab mode", confirm=True)


def test_viewer_cannot_propose_or_decide(ctx):
    pid = _propose(ctx)
    with pytest.raises(AuthorizationError):
        _propose(ctx, token=ctx["viewer"], action=SimulatedAction.ESCALATE_INCIDENT)
    with pytest.raises(AuthorizationError):
        ctx["s"].response.decide(
            ctx["viewer"], pid, approve=True, reason="sure thing", confirm=True
        )
    with pytest.raises(AuthorizationError):
        ctx["s"].response.execute(ctx["viewer"], pid, confirm=True)


@pytest.mark.parametrize(
    "kwargs,exc",
    [
        ({"approve": True, "reason": "ok fine", "confirm": False}, ValidationFailedError),
        ({"approve": True, "reason": "", "confirm": True}, ValidationFailedError),
        ({"approve": True, "reason": "x" * 2000, "confirm": True}, ValidationFailedError),
    ],
)
def test_decision_requires_confirmation_and_reason(ctx, kwargs, exc):
    pid = _propose(ctx)
    with pytest.raises(exc):
        ctx["s"].response.decide(ctx["a2"], pid, **kwargs)
    assert ctx["s"].response.list_proposals(ctx["admin"])[0]["status"] == "pending"


def test_replay_and_double_decisions_rejected(ctx):
    pid = _propose(ctx)
    ctx["s"].response.decide(ctx["a2"], pid, approve=True, reason="approved once", confirm=True)
    with pytest.raises(ConflictError):
        ctx["s"].response.decide(
            ctx["a2"], pid, approve=True, reason="approved twice", confirm=True
        )
    with pytest.raises(ConflictError):
        ctx["s"].response.decide(
            ctx["a2"], pid, approve=False, reason="flip to reject", confirm=True
        )
    ctx["s"].response.execute(ctx["a2"], pid, confirm=True)
    with pytest.raises(ConflictError):
        ctx["s"].response.execute(ctx["a2"], pid, confirm=True)


def test_cannot_execute_pending_or_rejected(ctx):
    pid = _propose(ctx)
    with pytest.raises(ConflictError):
        ctx["s"].response.execute(ctx["a2"], pid, confirm=True)
    ctx["s"].response.decide(ctx["a2"], pid, approve=False, reason="not justified", confirm=True)
    with pytest.raises(ConflictError):
        ctx["s"].response.execute(ctx["a2"], pid, confirm=True)


def test_concurrent_approvals_only_one_wins(ctx):
    pid = _propose(ctx)
    outcomes: list[str] = []

    def attempt():
        try:
            ctx["s"].response.decide(ctx["a2"], pid, approve=True, reason="race test", confirm=True)
            outcomes.append("ok")
        except ConflictError:
            outcomes.append("conflict")

    threads = [threading.Thread(target=attempt) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert outcomes.count("ok") == 1 and outcomes.count("conflict") == 4


def test_duplicate_pending_proposal_rejected(ctx):
    _propose(ctx)
    with pytest.raises(ConflictError):
        _propose(ctx)


def test_unknown_action_type_rejected(ctx):
    with pytest.raises(ValueError):
        ctx["s"].response.propose(ctx["admin"], ctx["iid"], "run_powershell", "ws", "because")


def test_ai_recommendation_becomes_proposal_only_on_request(ctx):
    ctx["fake"].replies.append(good_report(ctx["ids"]))
    report = ctx["s"].investigation.investigate(ctx["admin"], ctx["iid"])
    assert ctx["s"].response.list_proposals(ctx["admin"]) == []  # nothing created automatically
    pid = ctx["s"].response.propose_from_report(ctx["admin"], report["id"], 0)
    [p] = ctx["s"].response.list_proposals(ctx["admin"])
    assert p["id"] == pid and p["source"] == "ai" and p["status"] == "pending"
    assert p["rationale"].startswith("[AI-suggested]")
    with pytest.raises(ConflictError):  # one proposal per recommendation
        ctx["s"].response.propose_from_report(ctx["admin"], report["id"], 0)
    with pytest.raises(NotFoundError):
        ctx["s"].response.propose_from_report(ctx["admin"], report["id"], 5)


def test_fallback_reports_cannot_produce_proposals(ctx):
    ctx["fake"].replies.extend(["garbage"] * 3)
    report = ctx["s"].investigation.investigate(ctx["admin"], ctx["iid"])
    with pytest.raises(ValidationFailedError):
        ctx["s"].response.propose_from_report(ctx["admin"], report["id"], 0)


def test_tampered_report_action_is_revalidated(ctx):
    ctx["fake"].replies.append(good_report(ctx["ids"]))
    report = ctx["s"].investigation.investigate(ctx["admin"], ctx["iid"])
    with ctx["s"].db.transaction() as conn:
        data = json.loads(
            conn.execute(
                "SELECT report_json FROM investigation_reports WHERE id=?", (report["id"],)
            ).fetchone()[0]
        )
        data["containment_recommendations"][0]["action_type"] = "format_disk"
        conn.execute(
            "UPDATE investigation_reports SET report_json=? WHERE id=?",
            (json.dumps(data), report["id"]),
        )
    with pytest.raises(ValueError):
        ctx["s"].response.propose_from_report(ctx["admin"], report["id"], 0)


def test_escalation_adds_simulated_note(ctx):
    pid = _propose(ctx, action=SimulatedAction.ESCALATE_INCIDENT)
    ctx["s"].response.decide(ctx["a2"], pid, approve=True, reason="needs tier 2", confirm=True)
    ctx["s"].response.execute(ctx["a2"], pid, confirm=True)
    notes = ctx["s"].incidents.detail(ctx["admin"], ctx["iid"])["notes"]
    assert notes[-1]["body"].startswith("[SIMULATED ACTION]")


# --- audit & health (admin service) -----------------------------------------------------


def test_audit_log_admin_only_and_chain_ok(ctx):
    rows = ctx["s"].admin.audit_log(ctx["admin"])
    assert rows and ctx["s"].admin.verify_audit_chain(ctx["admin"])["ok"]
    with pytest.raises(AuthorizationError):
        ctx["s"].admin.audit_log(ctx["a2"])
    with pytest.raises(AuthorizationError):
        ctx["s"].admin.audit_log(ctx["viewer"])


def test_health_hides_internal_paths_from_non_admins(ctx):
    admin_view = ctx["s"].admin.health(ctx["admin"])
    viewer_view = ctx["s"].admin.health(ctx["viewer"])
    assert "data_dir" in admin_view["config"] and "data_dir" not in viewer_view["config"]
    assert "ollama_host" not in viewer_view["config"]
    checks = viewer_view["checks"]
    assert checks["database"]["ok"] and checks["audit_chain"]["ok"]
    assert checks["detection_rules"]["loaded"] == 6 and checks["detection_rules"]["rejected"] == []
    assert checks["ollama"]["available"] is True  # the fake transport answers /api/version


def test_health_reports_ollama_down(settings):
    import httpx

    from tests.conftest import ADMIN_PW
    from threatlens.integrations.ollama import OllamaClient
    from threatlens.services.container import build_services

    def down(request):
        raise httpx.ConnectError("refused")

    services = build_services(
        settings,
        ollama_client=OllamaClient(
            settings.ollama_host, timeout=1, transport=httpx.MockTransport(down)
        ),
    )
    code = services.auth.issue_setup_code()
    services.auth.create_initial_admin(setup_code=code, username="admin", password=ADMIN_PW)
    token = services.auth.login("admin", ADMIN_PW)
    health = services.admin.health(token)
    assert health["checks"]["ollama"]["ok"] is False and health["checks"]["database"]["ok"]
