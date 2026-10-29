"""Behavioural analytics, assessment, linking, provenance and analyst-judgement tests."""

from __future__ import annotations

import json

import pytest

from tests.test_investigation import FakeOllama, good_report, make_services, seed
from threatlens.detection import assessment, behavior
from threatlens.detection.behavior import BehaviorConfig, analyze, network_of
from threatlens.errors import AuthorizationError, NotFoundError, ValidationFailedError
from threatlens.ingest.normalize import SourceType, normalize
from threatlens.models.domain import Disposition, Role, Severity

DAY = 1792800000  # 2026-10-24T00:00:00Z (a fixed synthetic day)


def logon(user: str, hour: int, ip: str, minute: int = 0, day: int = 0) -> dict:
    record = {
        "timestamp": DAY + day * 86400 + hour * 3600 + minute * 60,
        "event_type": "4624",
        "user": user,
        "src_ip": ip,
        "n": f"{day}-{hour}-{minute}",
    }
    return normalize(record, SourceType.AUTH).model_dump(mode="json")


def proc(host: str, image: str, n: int) -> dict:
    record = {
        "timestamp": DAY + 3600 * 9 + n,
        "event_type": "process_creation",
        "host": host,
        "Image": f"C:\\W\\{image}",
        "CommandLine": image,
        "n": n,
    }
    return normalize(record, SourceType.ENDPOINT).model_dump(mode="json")


def ordered(events):
    return sorted(events, key=lambda e: (e["timestamp"], e["id"]))


# --- BH-001 new logon network ------------------------------------------------------------


def test_new_network_flagged_only_after_baseline():
    base = [logon("bob", 9 + i, "198.51.100.10") for i in range(5)]
    hit = logon("bob", 15, "203.0.113.9")
    res = analyze(ordered([*base, hit]))
    [ind] = [i for i in res.indicators if i.detector_id == "BH-001"]
    assert ind.event_ids == [hit["id"]] and ind.baseline["prior_successful_logons"] == 5
    assert "203.0.113.0/24" in ind.rationale and 0 < ind.score < 1


def test_same_network_different_host_address_is_not_anomalous():
    events = [logon("bob", 9 + i, f"198.51.100.{10 + i}") for i in range(7)]
    assert [i for i in analyze(ordered(events)).indicators if i.detector_id == "BH-001"] == []


def test_insufficient_baseline_reports_gap_not_indicator():
    events = [logon("bob", 9, "198.51.100.10"), logon("bob", 10, "203.0.113.9")]
    res = analyze(ordered(events))
    assert not [i for i in res.indicators if i.detector_id == "BH-001"]
    assert any(g["detector"] == "BH-001" and g["entity"] == "user:bob" for g in res.coverage_gaps)


def test_baseline_is_past_only():
    # The novel logon comes first: later logons from the same network must not hide it,
    # and it must not count as its own baseline.
    first = logon("bob", 8, "203.0.113.9")
    later = [logon("bob", 9 + i, "198.51.100.10") for i in range(6)]
    res = analyze(ordered([first, *later]))
    assert not [i for i in res.indicators if i.detector_id == "BH-001"]


def test_network_of_handles_ipv6_and_garbage():
    assert network_of("2001:db8::1") == "2001:db8::/64"
    assert network_of("not-an-ip") is None


# --- BH-002 rare process ------------------------------------------------------------------


def test_rare_process_flagged_and_common_ones_not():
    events = [proc("ws1", "excel.exe", n) for n in range(15)] + [proc("ws1", "certutil.exe", 99)]
    inds = [i for i in analyze(ordered(events)).indicators if i.detector_id == "BH-002"]
    assert [i.rationale.split("'")[1] for i in inds] == ["certutil.exe"]
    assert inds[0].baseline["process_events_on_host"] == 16


def test_rare_process_needs_host_history():
    events = [proc("ws1", "excel.exe", n) for n in range(3)] + [proc("ws1", "certutil.exe", 9)]
    res = analyze(ordered(events))
    assert not [i for i in res.indicators if i.detector_id == "BH-002"]
    assert any(g["detector"] == "BH-002" for g in res.coverage_gaps)


# --- BH-003 off-hours ---------------------------------------------------------------------


def test_off_hours_flagged_with_tolerance():
    base = [logon("ann", 9 + (i % 8), "198.51.100.10", day=-1 if i < 8 else 0) for i in range(9)]
    in_tolerance = logon("ann", 18, "198.51.100.10", minute=30)  # 2h past observed max (16)
    night = logon("ann", 3, "198.51.100.10", minute=5, day=1)
    inds = [
        i
        for i in analyze(ordered([*base, in_tolerance, night])).indicators
        if i.detector_id == "BH-003"
    ]
    assert [i.event_ids for i in inds] == [[night["id"]]]
    assert "travel" in inds[0].rationale  # benign explanations are stated


def test_scores_are_bounded_and_deterministic():
    events = [logon("bob", 9 + i, "198.51.100.10") for i in range(5)]
    events.append(logon("bob", 16, "203.0.113.9"))
    a, b = analyze(ordered(events)), analyze(ordered(events))
    assert [(i.fingerprint, i.score) for i in a.indicators] == [
        (i.fingerprint, i.score) for i in b.indicators
    ]
    assert all(0 <= i.score <= 0.95 for i in a.indicators)


def test_describe_mentions_thresholds():
    text = " ".join(behavior.describe(BehaviorConfig(min_baseline_logons=7)).values())
    assert ">= 7 earlier logons" in text


# --- assessment & links (pure) ------------------------------------------------------------


@pytest.mark.parametrize(
    "ev,expected",
    [
        (assessment.Evidence(sigma_rules=1, behavior_indicators=2), "high"),
        (assessment.Evidence(sigma_rules=1, correlation_rules=1), "high"),
        (assessment.Evidence(sigma_rules=3), "high"),
        (assessment.Evidence(sigma_rules=1), "medium"),
        (assessment.Evidence(behavior_indicators=4), "low"),
        (assessment.Evidence(analyst_flagged=True), "low"),
    ],
)
def test_confidence_model(ev, expected):
    confidence, rationale = assessment.assess_confidence(ev)
    assert confidence == expected and rationale


def test_detection_status_preserves_analyst_flag_until_rules_match():
    flagged = "suspicious_unmatched"
    assert assessment.detection_status(assessment.Evidence(), flagged) == flagged
    assert (
        assessment.detection_status(assessment.Evidence(behavior_indicators=1), flagged) == flagged
    )
    assert (
        assessment.detection_status(assessment.Evidence(sigma_rules=1), flagged)
        == "known_detection"
    )


def test_links_need_shared_entity_and_proximity():
    prof = assessment.IncidentProfile
    profiles = [
        prof(1, "2026-10-20T10:00:00.000Z", "2026-10-20T10:10:00.000Z", {"user:j", "host:a"}),
        prof(2, "2026-10-20T10:30:00.000Z", "2026-10-20T10:40:00.000Z", {"host:a"}),
        prof(3, "2026-10-20T10:30:00.000Z", "2026-10-20T10:40:00.000Z", {"host:zzz"}),
        prof(4, "2026-10-20T18:00:00.000Z", "2026-10-20T18:10:00.000Z", {"user:j"}),
    ]
    links = assessment.find_links(profiles)
    assert [(lk.a, lk.b, lk.shared) for lk in links] == [(1, 2, ("host:a",))]
    assert "not evidence of a common actor" in links[0].rationale


# --- end-to-end on the sample scenario ----------------------------------------------------


@pytest.fixture()
def world(settings):
    fake = FakeOllama([])
    services = make_services(settings, fake)
    admin, host_iid, ids, _ = seed(services)
    services.users.create_user(
        admin, username="viewer1", password="Viewer-Strong-Pass-77", role=Role.VIEWER
    )
    return {
        "s": services,
        "fake": fake,
        "admin": admin,
        "host": host_iid,
        "ids": ids,
        "viewer": services.auth.login("viewer1", "Viewer-Strong-Pass-77"),
    }


def by_title(world):
    return {i["title"]: i for i in world["s"].incidents.list_incidents(world["admin"])}


def test_scenario_layers_and_assessment(world):
    inc = by_title(world)
    host = inc["Suspicious activity on ws-fin-07"]
    assert (host["severity"], host["confidence"], host["detection_status"]) == (
        "critical",
        "high",
        "known_detection",
    )
    brute = inc["Brute force followed by successful logon (j.doe)"]
    assert brute["confidence"] == "high"  # correlation rule + BH-001 agree
    spray = inc["Password spraying from a single source (203.0.113.45)"]
    assert spray["confidence"] == "medium"
    for title in ("Anomalous behaviour on ws-hr-02", "Anomalous behaviour for user c.nguyen"):
        assert (inc[title]["detection_status"], inc[title]["confidence"]) == (
            "anomalous_behavior",
            "low",
        )
        assert inc[title]["severity"] in ("low", "medium")
    assert all(i["disposition"] == "undetermined" for i in inc.values())  # never automatic


def test_unmatched_activity_is_surfaced_with_evidence(world):
    inc = by_title(world)["Anomalous behaviour on ws-hr-02"]
    detail = world["s"].incidents.detail(world["admin"], inc["id"])
    assert detail["findings"] == []  # no rule matched...
    [ind] = detail["indicators"]  # ...but the behavioural layer explains why it's here
    assert ind["detector_id"] == "BH-002" and "certutil.exe" in ind["rationale"]
    assert set(ind["event_ids"]) <= {e["id"] for e in detail["events"]}


def test_anomalies_never_raise_rule_severity(world):
    host = by_title(world)["Suspicious activity on ws-fin-07"]
    detail = world["s"].incidents.detail(world["admin"], host["id"])
    assert len(detail["indicators"]) == 4 and host["severity"] == "critical"


def test_links_surface_related_incidents(world):
    inc = by_title(world)
    brute = inc["Brute force followed by successful logon (j.doe)"]
    links = world["s"].incidents.detail(world["admin"], brute["id"])["links"]
    others = {lk["other_title"] for lk in links}
    assert "Suspicious activity on ws-fin-07" in others
    assert all("not evidence of a common actor" in lk["rationale"] for lk in links)


def test_rerun_is_idempotent_and_keeps_analyst_work(world):
    s, admin = world["s"], world["admin"]
    iid = by_title(world)["Anomalous behaviour on ws-hr-02"]["id"]
    s.incidents.set_disposition(
        admin, iid, Disposition.BENIGN_CONFIRMED, "IT confirmed certutil was used to fetch a patch."
    )
    before = {i["id"]: i for i in s.incidents.list_incidents(admin)}
    summary = s.detection.run(admin)
    after = {i["id"]: i for i in s.incidents.list_incidents(admin)}
    assert summary.incidents_new == 0 and summary.indicators_new == 0
    assert summary.links_new == 0 and before.keys() == after.keys()
    assert after[iid]["disposition"] == "benign_confirmed"


def test_rule_versions_and_provenance_recorded(world):
    with world["s"].db.connect() as conn:
        versions = {r[0]: r[1] for r in conn.execute("SELECT engine, rule_version FROM findings")}
        row = conn.execute(
            "SELECT original_timestamp, normalization_notes FROM events"
            " WHERE source_type = 'auth' LIMIT 1"
        ).fetchone()
    assert "+sha256:" in versions["sigma"] and "+cfg:" in versions["correlation"]
    assert row[0] and "Windows event ID" in json.loads(row[1])[0]


def test_coverage_gaps_exposed_with_rules(world):
    info = world["s"].detection.describe_rules(world["admin"])
    assert set(info["behavior"]) == {"BH-001", "BH-002", "BH-003"}
    assert info["coverage"] is not None and "gaps" in info["coverage"]


# --- analyst flag, disposition, mapping review --------------------------------------------


def test_flag_events_creates_unmatched_incident(world):
    s, admin = world["s"], world["admin"]
    events = [
        e["id"]
        for e in s.ingestion.search(
            admin,
            __import__("threatlens.repositories.event_repo", fromlist=["EventFilter"]).EventFilter(
                usernames=["e.schmidt"], limit=2
            ),
        )
    ]
    iid = s.incidents.flag_events(
        admin,
        events,
        title="Odd e.schmidt activity",
        reason="Logons outside normal pattern per HR.",
        severity=Severity.MEDIUM,
    )
    detail = s.incidents.detail(admin, iid)
    inc = detail["incident"]
    assert (inc["detection_status"], inc["confidence"], inc["rule_id"]) == (
        "suspicious_unmatched",
        "low",
        "ANALYST-FLAG",
    )
    assert {e["id"] for e in detail["events"]} == set(events)
    s.detection.run(admin)  # re-detection keeps the analyst provenance
    assert s.incidents.detail(admin, iid)["incident"]["detection_status"] == "suspicious_unmatched"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"event_ids": [], "title": "Valid title", "reason": "long enough reason"},
        {
            "event_ids": ["EVT-doesnotexist00"],
            "title": "Valid title",
            "reason": "long enough reason",
        },
        {"event_ids": ["x"], "title": "x", "reason": "long enough reason"},
        {"event_ids": ["x"], "title": "Valid title", "reason": "short"},
    ],
)
def test_flag_events_validation(world, kwargs):
    with pytest.raises(ValidationFailedError):
        world["s"].incidents.flag_events(world["admin"], severity=Severity.LOW, **kwargs)


def test_viewer_cannot_flag_dispose_or_review(world):
    s, viewer = world["s"], world["viewer"]
    with pytest.raises(AuthorizationError):
        s.incidents.flag_events(
            viewer,
            world["ids"][:1],
            title="Valid title",
            reason="long enough reason",
            severity=Severity.LOW,
        )
    with pytest.raises(AuthorizationError):
        s.incidents.set_disposition(
            viewer, world["host"], Disposition.FALSE_POSITIVE, "trying to hide it"
        )
    mapping = s.incidents.detail(world["admin"], world["host"])["mappings"][0]
    with pytest.raises(AuthorizationError):
        s.incidents.review_mapping(viewer, mapping["id"], "rejected")


def test_disposition_requires_note_and_is_audited(world):
    s, admin = world["s"], world["admin"]
    with pytest.raises(ValidationFailedError):
        s.incidents.set_disposition(admin, world["host"], Disposition.TRUE_POSITIVE, "")
    s.incidents.set_disposition(
        admin, world["host"], Disposition.TRUE_POSITIVE, "LSASS dump confirmed by memory forensics."
    )
    inc = s.incidents.detail(admin, world["host"])["incident"]
    assert inc["disposition"] == "true_positive" and inc["disposition_by"]
    assert inc["severity"] == "critical"  # verdict does not rewrite severity
    rows = s.admin.audit_log(admin, action="incident.disposition")
    assert rows and rows[0]["outcome"] == "success"


def test_mapping_review_and_dashboard_excludes_rejected(world):
    s, admin = world["s"], world["admin"]
    mappings = s.incidents.detail(admin, world["host"])["mappings"]
    assert {m["review_status"] for m in mappings} == {"candidate"}
    target = next(m for m in mappings if m["technique_id"] == "T1136.001")
    s.incidents.review_mapping(admin, target["id"], "rejected")
    techniques = {t["technique_id"] for t in s.incidents.dashboard_stats(admin)["top_techniques"]}
    assert "T1136.001" not in techniques
    with pytest.raises(ValidationFailedError):
        s.incidents.review_mapping(admin, target["id"], "approved-by-ai")
    with pytest.raises(NotFoundError):
        s.incidents.review_mapping(admin, 999_999, "confirmed")


def test_confirm_ai_technique_requires_validated_report_and_local_evidence(world):
    s, admin, fake = world["s"], world["admin"], world["fake"]
    fake.replies.append(good_report(world["ids"]))
    report = s.investigation.investigate(admin, world["host"])
    s.incidents.confirm_ai_technique(admin, report["id"], 0)
    confirmed = [
        m for m in s.incidents.detail(admin, world["host"])["mappings"] if m["source"] == "ai"
    ]
    assert confirmed and confirmed[0]["review_status"] == "confirmed"
    assert confirmed[0]["rationale"].startswith("[AI-suggested, analyst-confirmed]")
    fake.replies.extend(["garbage"] * 3)
    fallback = s.investigation.investigate(admin, world["host"])
    with pytest.raises((ValidationFailedError, NotFoundError)):
        s.incidents.confirm_ai_technique(admin, fallback["id"], 0)


def test_ai_context_includes_indicators_labelled_as_not_probability(world):
    s, admin, fake = world["s"], world["admin"], world["fake"]
    fake.replies.append(good_report(world["ids"]))
    s.investigation.investigate(admin, world["host"])
    user_msg = fake.requests[-1]["messages"][1]["content"]
    assert "statistical_indicators" in user_msg
    assert "not a probability of compromise" in user_msg
    assert '"confidence": "high"' in user_msg


def test_logon_detectors_are_linear_not_quadratic(monkeypatch):
    """Regression: BH-001/BH-003 once rebuilt each user's history per event (O(n^2)),
    which took 378 s at 18k events. Count work instead of timing it (deterministic)."""
    calls = {"net": 0, "iso": 0}
    real_net, real_iso = behavior.network_of, behavior.from_iso

    def counting_net(ip):
        calls["net"] += 1
        return real_net(ip)

    def counting_iso(ts):
        calls["iso"] += 1
        return real_iso(ts)

    monkeypatch.setattr(behavior, "network_of", counting_net)
    monkeypatch.setattr(behavior, "from_iso", counting_iso)
    n = 400
    events = ordered(
        [logon("bob", 9 + (i % 8), "198.51.100.10", minute=i % 60, day=i // 60) for i in range(n)]
    )
    analyze(events)
    assert calls["net"] == n  # one network lookup per logon
    assert calls["iso"] == n  # one timestamp parse per logon
