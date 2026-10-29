from __future__ import annotations

import json
from pathlib import Path

import pytest

from threatlens.detection.correlation import CorrelationConfig, brute_force, password_spray
from threatlens.errors import AuthorizationError, ValidationFailedError
from threatlens.ingest.normalize import SourceType, normalize
from threatlens.integrations.attack import (
    AttackCatalog,
    UnknownTechniqueError,
    load_catalog,
)
from threatlens.integrations.sigma import SigmaRuleError, event_view, load_rules, parse_rule
from threatlens.models.domain import IncidentStatus
from threatlens.repositories import audit_repo

ROOT = Path(__file__).resolve().parent.parent
SUBSET = json.loads((ROOT / "threatlens/integrations/data/attack_subset.json").read_text("utf-8"))


@pytest.fixture(scope="module")
def catalog() -> AttackCatalog:
    # Tests pin to the bundled subset so results do not depend on a local full download.
    return AttackCatalog(SUBSET, dataset_name="bundled subset")


@pytest.fixture(scope="module")
def rules(catalog):
    result = load_rules(ROOT / "rules" / "sigma", catalog)
    assert result.errors == []
    return {r.title: r for r in result.rules}


def proc(cmd: str, image: str, parent: str = "C:\\Windows\\explorer.exe", **extra) -> dict:
    record = {
        "timestamp": "2026-10-20T10:00:00Z",
        "event_type": "process_creation",
        "Image": image,
        "CommandLine": cmd,
        "ParentImage": parent,
        "host": "ws-1",
        **extra,
    }
    return event_view(normalize(record, SourceType.ENDPOINT).model_dump(mode="json"))


PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"


# --- ATT&CK catalogue -------------------------------------------------------------------


def test_catalog_validates_ids(catalog):
    assert catalog.get("t1059.001").name == "PowerShell"
    for bad in ["T9999", "T1059.999", "TA0001", "1059", "T1059.001; DROP", ""]:
        with pytest.raises(UnknownTechniqueError):
            catalog.get(bad)


def test_revoked_technique_reports_replacement(catalog):
    with pytest.raises(UnknownTechniqueError, match="revoked.*T1685.005"):
        catalog.get("T1070.001")


def test_subset_has_provenance():
    assert SUBSET["source"].startswith("https://raw.githubusercontent.com/mitre/cti/")
    assert len(SUBSET["source_sha256"]) == 64 and SUBSET["retrieved_at"]


def test_load_catalog_returns_dataset_label():
    assert "retrieved" in load_catalog().label


# --- Sigma subset: positives and negatives ---------------------------------------------


@pytest.mark.parametrize(
    "title,view,expected",
    [
        ("PowerShell Encoded Command", lambda: proc("powershell.exe -NoP -enc SQBFAFgA", PS), True),
        ("PowerShell Encoded Command", lambda: proc("powershell.exe -File inv.ps1", PS), False),
        (
            "PowerShell Encoded Command",  # filtered parent (deployment agent)
            lambda: proc("powershell.exe -enc AAAA", PS, parent="C:\\ccm\\CcmExec.exe"),
            False,
        ),
        (
            "LSASS Memory Dump via ProcDump",
            lambda: proc(
                "procdump64.exe -accepteula -ma lsass.exe out.dmp", "C:\\t\\procdump64.exe"
            ),
            True,
        ),
        (
            "LSASS Memory Dump via ProcDump",  # procdump on another process is not LSASS dumping
            lambda: proc("procdump64.exe -ma notepad.exe", "C:\\t\\procdump64.exe"),
            False,
        ),
        (
            "Scheduled Task Created to Run as SYSTEM or at Logon",
            lambda: proc("schtasks.exe /create /tn x /tr y /sc onlogon", "C:\\W\\schtasks.exe"),
            True,
        ),
        (
            "Scheduled Task Created to Run as SYSTEM or at Logon",
            lambda: proc("schtasks.exe /query", "C:\\W\\schtasks.exe"),
            False,
        ),
        (
            "Local User Account Created via net.exe",
            lambda: proc("net.exe user bob /add", "C:\\W\\net.exe"),
            True,
        ),
        (
            "Local User Account Created via net.exe",
            lambda: proc("net.exe user bob", "C:\\W\\net.exe"),
            False,
        ),
        (
            "Windows Event Log Cleared",
            lambda: proc("wevtutil.exe cl Security", "C:\\W\\wevtutil.exe"),
            True,
        ),
        (
            "Windows Event Log Cleared",
            lambda: proc("wevtutil.exe qe Security", "C:\\W\\wevtutil.exe"),
            False,
        ),
    ],
)
def test_sigma_rule_matches(rules, title, view, expected):
    hits = rules[title].evaluate(view())
    assert (hits is not None) is expected
    if expected:
        assert hits  # matched fields are explained


def test_sigma_explains_matched_fields(rules):
    hits = rules["LSASS Memory Dump via ProcDump"].evaluate(
        proc("procdump64.exe -ma lsass.exe d.dmp", "C:\\t\\procdump64.exe")
    )
    assert "CommandLine" in hits and "lsass" in hits["CommandLine"]


def test_sigma_case_insensitive(rules):
    v = proc("POWERSHELL.EXE -ENC AAAA", PS.upper())
    assert rules["PowerShell Encoded Command"].evaluate(v) is not None


def test_logsource_filter_excludes_other_categories(rules):
    record = {
        "timestamp": "2026-10-20T10:00:00Z",
        "event_type": "4625",
        "Image": PS,
        "CommandLine": "powershell -enc AAAA",
    }
    view = event_view(normalize(record, SourceType.AUTH).model_dump(mode="json"))
    assert rules["PowerShell Encoded Command"].evaluate(view) is None


BASE_RULE = """
title: t
id: 11111111-2222-3333-4444-555555555555
level: high
logsource: {product: windows, category: process_creation}
detection:
  sel: {CommandLine|contains: x}
  condition: %s
tags: [%s]
"""


@pytest.mark.parametrize(
    "condition,tags,msg",
    [
        ("sel | count() > 5", "attack.t1059.001", "aggregation"),
        ("sel and missing", "attack.t1059.001", "unknown identifier"),
        ("(sel", "attack.t1059.001", "end of condition|parenthes"),
        ("sel", "attack.t9999", "not in the loaded"),
        ("sel", "attack.t1070.001", "revoked"),
        ("1 of nothing*", "attack.t1059.001", "matches no selection"),
    ],
)
def test_invalid_rules_rejected(catalog, condition, tags, msg):
    with pytest.raises(SigmaRuleError, match=msg):
        parse_rule(BASE_RULE % (condition, tags), catalog)


@pytest.mark.parametrize(
    "mutation,msg",
    [
        (("CommandLine|contains: x", "CommandLine|base64offset: x"), "unsupported modifier"),
        (("category: process_creation", "category: dns_query"), "unsupported logsource"),
        (("11111111-2222-3333-4444-555555555555", "not-a-uuid"), "UUID"),
        (("level: high", "level: severe"), "unsupported level"),
        (("CommandLine|contains: x", "CommandLine|re: '(unclosed'"), "invalid regular expression"),
    ],
)
def test_unsupported_constructs_rejected(catalog, mutation, msg):
    text = (BASE_RULE % ("sel", "attack.t1059.001")).replace(*mutation)
    with pytest.raises(SigmaRuleError, match=msg):
        parse_rule(text, catalog)


def test_yaml_with_python_tags_not_executed(catalog):
    with pytest.raises(SigmaRuleError):
        parse_rule("!!python/object/apply:os.system ['echo pwned']", catalog)


# --- correlation ------------------------------------------------------------------------


def _auth(ts_sec: int, user: str, ok: bool, ip: str = "203.0.113.5") -> dict:
    record = {
        "timestamp": 1792836000 + ts_sec,
        "event_type": "4624" if ok else "4625",
        "user": user,
        "src_ip": ip,
        "n": ts_sec,
    }
    return normalize(record, SourceType.AUTH).model_dump(mode="json")


def test_brute_force_then_success_detected():
    events = [_auth(i * 10, "bob", False) for i in range(8)] + [_auth(200, "bob", True)]
    [f] = brute_force(events, CorrelationConfig())
    assert f.rule_id == "TL-CR-001" and len(f.event_ids) == 9
    assert f.matched_fields["success_event"] == events[-1]["id"]


def test_below_threshold_not_detected():
    events = [_auth(i * 10, "bob", False) for i in range(7)] + [_auth(200, "bob", True)]
    assert brute_force(events, CorrelationConfig()) == []


def test_failures_outside_window_not_detected():
    events = [_auth(i * 120, "bob", False) for i in range(8)]  # 14 minutes span > 10
    assert brute_force(events, CorrelationConfig()) == []


def test_success_from_different_ip_is_cr003_not_cr001():
    events = [_auth(i * 10, "bob", False) for i in range(8)] + [
        _auth(200, "bob", True, "192.0.2.9")
    ]
    [f] = brute_force(events, CorrelationConfig())
    assert f.rule_id == "TL-CR-003"


def test_password_spray_detected_and_configurable():
    events = [_auth(i * 10, f"user{i}", False) for i in range(5)]
    assert password_spray(events, CorrelationConfig())[0].rule_id == "TL-CR-002"
    assert password_spray(events, CorrelationConfig(spray_distinct_users=6)) == []


# --- end-to-end detection service -------------------------------------------------------


def _load_samples(services, token):
    for name, src in [
        ("auth_events.jsonl", SourceType.AUTH),
        ("endpoint_events.json", SourceType.ENDPOINT),
        ("alerts.csv", SourceType.ALERT),
    ]:
        data = (ROOT / "sample_data" / name).read_bytes()
        p = services.ingestion.preview(token, name, data, src)
        services.ingestion.commit(token, name, data, src, confirmed_sha256=p.file_sha256)


def test_sample_scenario_produces_expected_incidents(services, analyst_token):
    _load_samples(services, analyst_token)
    summary = services.detection.run(analyst_token)
    incidents = services.incidents.list_incidents(analyst_token)
    rules = {i["rule_id"] for i in incidents}
    assert {"TL-CR-001", "TL-CR-002", "SIGMA-HOST-CLUSTER"} <= rules
    host = next(i for i in incidents if i["title"] == "Suspicious activity on ws-fin-07")
    assert host["severity"] == "critical"
    detail = services.incidents.detail(analyst_token, host["id"])
    techniques = {m["technique_id"] for m in detail["mappings"]}
    assert {"T1059.001", "T1003.001", "T1053.005", "T1136.001", "T1685.005"} <= techniques
    event_ids = {e["id"] for e in detail["events"]}
    for f in detail["findings"]:  # every finding's evidence is linked to the incident
        assert set(f["event_ids"]) <= event_ids
    for m in detail["mappings"]:
        assert m["source"] == "rule" and set(m["evidence_ids"]) <= event_ids
    # Same-host EDR alerts in the window are attached as context (no finding, no severity).
    alert_ids = {e["id"] for e in detail["events"] if e["source_type"] == "alert"}
    assert len(alert_ids) == 2
    # The low-severity alert on another host was not pulled in.
    assert not any(e["host"] == "ws-eng-11" for e in detail["events"])
    # Benign background noise did not generate incidents for other users.
    assert not any("a.khan" in i["title"] for i in incidents)
    assert summary.incidents_new == len(incidents)


def test_detection_is_idempotent(services, analyst_token):
    _load_samples(services, analyst_token)
    first = services.detection.run(analyst_token)
    second = services.detection.run(analyst_token)
    assert second.findings_new == 0 and second.incidents_new == 0
    assert second.findings_total == first.findings_total


def test_viewer_cannot_run_detection_or_update(services, viewer_token, analyst_token):
    _load_samples(services, analyst_token)
    services.detection.run(analyst_token)
    incident_id = services.incidents.list_incidents(viewer_token)[0]["id"]
    with pytest.raises(AuthorizationError):
        services.detection.run(viewer_token)
    with pytest.raises(AuthorizationError):
        services.incidents.change_status(viewer_token, incident_id, IncidentStatus.RESOLVED)


def test_incident_state_machine(services, analyst_token):
    _load_samples(services, analyst_token)
    services.detection.run(analyst_token)
    iid = services.incidents.list_incidents(analyst_token)[0]["id"]
    with pytest.raises(ValidationFailedError):
        services.incidents.change_status(analyst_token, iid, IncidentStatus.CONTAINED)
    services.incidents.change_status(analyst_token, iid, IncidentStatus.INVESTIGATING, "triaged")
    services.incidents.change_status(analyst_token, iid, IncidentStatus.CONTAINED)
    assert services.incidents.detail(analyst_token, iid)["incident"]["status"] == "contained"
    with services.db.connect() as conn:
        assert len(audit_repo.list_events(conn, action="incident.status")) == 2


def test_assignment_only_to_active_analysts(services, admin_token, analyst_token, viewer_token):
    _load_samples(services, analyst_token)
    services.detection.run(analyst_token)
    iid = services.incidents.list_incidents(analyst_token)[0]["id"]
    viewer_id = services.auth.resolve(viewer_token).user_id
    with pytest.raises(ValidationFailedError):
        services.incidents.assign(analyst_token, iid, viewer_id)
    me = services.auth.resolve(analyst_token).user_id
    services.incidents.assign(analyst_token, iid, me)
    assert services.incidents.detail(analyst_token, iid)["incident"]["assignee"] == "analyst1"


def test_dashboard_stats_reflect_stored_data(services, analyst_token):
    stats = services.incidents.dashboard_stats(analyst_token)
    assert stats["events"] == 0 and stats["incidents_open"] == 0
    _load_samples(services, analyst_token)
    services.detection.run(analyst_token)
    stats = services.incidents.dashboard_stats(analyst_token)
    assert stats["events"] > 0
    assert sum(stats["incidents_by_severity"].values()) == stats["incidents_open"]
