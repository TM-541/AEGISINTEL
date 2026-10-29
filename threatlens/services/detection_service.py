"""Multi-layer detection: Sigma subset, correlation rules and behavioural analytics.

Pipeline (one transaction, idempotent, independent of the LLM):
1. **Known detections**: correlation findings become incidents (rule + entity + first event).
   Sigma matches on one host are clustered (< ``HOST_CLUSTER_GAP`` apart) into
   "Suspicious activity on <host>" incidents. Same-host third-party alerts are attached as
   context.
2. **Behavioural indicators**: each anomaly attaches to an incident that already holds its
   evidence, or to one sharing its entity close in time. Otherwise unattached anomalies are
   clustered into "Anomalous behaviour" incidents (low severity, low confidence).
3. **Assessment**: confidence and detection status are recomputed for every incident from the
   evidence it holds. Severity is never raised by anomalies, and disposition is never touched.
4. **Linking**: incidents sharing an entity close in time are linked as leads for review.
5. **Coverage**: entities whose baseline was too thin are recorded as coverage gaps.

Findings are unique on ``(rule_id, fingerprint)``, indicators on
``(detector_id, fingerprint)``, incidents on ``correlation_key``, and links on the pair.
Re-running over the same data changes nothing.
"""

from __future__ import annotations

import json
import logging
import time
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

from threatlens.db.database import Database
from threatlens.detection import assessment, behavior
from threatlens.detection.correlation import CorrelationConfig, Finding, brute_force, password_spray
from threatlens.integrations.attack import AttackCatalog, load_catalog
from threatlens.integrations.sigma import RuleLoadResult, SigmaRule, event_view, load_rules
from threatlens.models.domain import Severity
from threatlens.repositories import audit_repo, event_repo, incident_repo
from threatlens.security.rbac import Permission
from threatlens.services.auth_service import AuthService
from threatlens.timeutil import from_iso, utcnow_iso

log = logging.getLogger(__name__)

RULES_DIR = Path(__file__).resolve().parent.parent.parent / "rules" / "sigma"
HOST_CLUSTER_GAP = timedelta(minutes=60)
COVERAGE_KEY = "behavior_coverage"
LEVEL_TO_CONFIDENCE = {
    "critical": "high",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "low",
}


@dataclass(frozen=True)
class DetectionSummary:
    events_scanned: int
    findings_total: int
    findings_new: int
    incidents_new: int
    incidents_updated: int
    duration_ms: int
    indicators_total: int = 0
    indicators_new: int = 0
    anomaly_incidents_new: int = 0
    links_new: int = 0
    coverage_gaps: int = 0


def sigma_findings(rules: list[SigmaRule], events: list[dict[str, Any]]) -> list[Finding]:
    findings = []
    for row in events:
        view = event_view(row)
        for rule in rules:
            hits = rule.evaluate(view)
            if hits is None:
                continue
            findings.append(
                Finding(
                    rule_id=rule.id,
                    rule_title=rule.title,
                    engine="sigma",
                    severity=Severity(rule.level),
                    fingerprint=row["id"],
                    event_ids=[row["id"]],
                    matched_fields=hits,
                    techniques=[(t, LEVEL_TO_CONFIDENCE[rule.level]) for t in rule.techniques],
                    rationale=(
                        f"Sigma rule '{rule.title}' matched "
                        + ", ".join(f"{k}={str(v)[:80]!r}" for k, v in hits.items())
                    ),
                    entity=f"host:{row.get('host') or 'unknown'}",
                    first_seen=row["timestamp"],
                    last_seen=row["timestamp"],
                    rule_version=rule.version,
                )
            )
    return findings


def cluster_host_findings(findings: list[Finding]) -> list[list[Finding]]:
    by_host: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_host[f.entity].append(f)
    clusters: list[list[Finding]] = []
    for items in by_host.values():
        items.sort(key=lambda f: (f.first_seen, f.rule_id))
        current = [items[0]]
        for f in items[1:]:
            if from_iso(f.first_seen) - from_iso(current[-1].last_seen) <= HOST_CLUSTER_GAP:
                current.append(f)
            else:
                clusters.append(current)
                current = [f]
        clusters.append(current)
    return clusters


def cluster_indicators(indicators: list[behavior.Indicator]) -> list[list[behavior.Indicator]]:
    by_entity: dict[str, list[behavior.Indicator]] = defaultdict(list)
    for ind in indicators:
        by_entity[ind.entity].append(ind)
    clusters: list[list[behavior.Indicator]] = []
    for items in by_entity.values():
        items.sort(key=lambda i: (i.observed_at, i.fingerprint))
        current = [items[0]]
        for ind in items[1:]:
            gap = from_iso(ind.observed_at) - from_iso(current[-1].observed_at)
            if gap <= HOST_CLUSTER_GAP:
                current.append(ind)
            else:
                clusters.append(current)
                current = [ind]
        clusters.append(current)
    return clusters


def related_alert_ids(events: list[dict[str, Any]], host: str, cluster: list[Finding]) -> list[str]:
    """Third-party alerts on the same host within the cluster window (± gap).

    They are linked as context evidence only. They create no finding and do not change
    severity.
    """
    start = from_iso(min(f.first_seen for f in cluster)) - HOST_CLUSTER_GAP
    end = from_iso(max(f.last_seen for f in cluster)) + HOST_CLUSTER_GAP
    return [
        e["id"]
        for e in events
        if e["source_type"] == "alert"
        and e.get("host") == host
        and start <= from_iso(e["timestamp"]) <= end
    ]


def choose_incident(ind: behavior.Indicator, profiles: list[dict[str, Any]]) -> int | None:
    """Prefer an incident that already holds the indicator's evidence, else one that shares
    the entity within the clustering window. Highest severity wins ties."""

    def rank(p: dict[str, Any]) -> int:
        return Severity(p["severity"]).rank

    holding = [p for p in profiles if p["event_ids"] & set(ind.event_ids)]
    if holding:
        return int(max(holding, key=rank)["id"])
    t = from_iso(ind.observed_at)
    near = [
        p
        for p in profiles
        if ind.entity in p["entities"]
        and from_iso(p["first_seen"]) - HOST_CLUSTER_GAP
        <= t
        <= from_iso(p["last_seen"]) + HOST_CLUSTER_GAP
    ]
    return int(max(near, key=rank)["id"]) if near else None


class DetectionService:
    def __init__(
        self,
        db: Database,
        auth: AuthService,
        *,
        rules_dir: Path = RULES_DIR,
        config: CorrelationConfig | None = None,
        behavior_config: behavior.BehaviorConfig | None = None,
        catalog: AttackCatalog | None = None,
    ) -> None:
        self.db = db
        self.auth = auth
        self.config = config or CorrelationConfig()
        self.behavior_config = behavior_config or behavior.BehaviorConfig()
        self.catalog = catalog or load_catalog()
        self.rules_dir = rules_dir
        self._rules: RuleLoadResult | None = None

    @property
    def rules(self) -> RuleLoadResult:
        if self._rules is None:
            self._rules = load_rules(self.rules_dir, self.catalog)
            for name, err in self._rules.errors:
                log.warning("sigma rule rejected", extra={"rule_file": name, "error": err})
        return self._rules

    def describe_rules(self, token: str) -> dict[str, Any]:
        self.auth.authorize(token, Permission.VIEW_RULES)
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT value FROM app_config WHERE key = ?", (COVERAGE_KEY,)
            ).fetchone()
        return {
            "sigma": [
                {
                    "id": r.id,
                    "title": r.title,
                    "level": r.level,
                    "version": r.version,
                    "description": r.description,
                    "condition": r.condition_text,
                    "techniques": r.techniques,
                    "falsepositives": r.falsepositives,
                    "file": r.source_path,
                }
                for r in self.rules.rules
            ],
            "rejected": self.rules.errors,
            "correlation": {
                "TL-CR-001": "Brute force followed by success: >= "
                f"{self.config.brute_force_failures}"
                f" failures in {self.config.brute_force_window_min} min, success from"
                f" the same IP within {self.config.success_after_min} min",
                "TL-CR-002": f"Password spraying: one IP fails against >="
                f" {self.config.spray_distinct_users} accounts in"
                f" {self.config.spray_window_min} min",
                "TL-CR-003": f"Repeated failures: >= {self.config.brute_force_failures} failures"
                f" in {self.config.brute_force_window_min} min without success",
            },
            "correlation_version": self.config.version,
            "behavior": behavior.describe(self.behavior_config),
            "behavior_version": behavior.BEHAVIOR_LOGIC_VERSION,
            "behavior_config": asdict(self.behavior_config),
            "coverage": json.loads(row["value"]) if row else None,
            "attack_dataset": self.catalog.label,
        }

    def run(self, token: str) -> DetectionSummary:
        actor = self.auth.authorize(token, Permission.RUN_CORRELATION)
        started = time.perf_counter()
        with self.db.connect() as conn:
            events = [dict(r) for r in event_repo.all_events_ordered(conn)]
        correlation = brute_force(events, self.config) + password_spray(events, self.config)
        sigma = sigma_findings(self.rules.rules, events)
        analysis = behavior.analyze(events, self.behavior_config)

        new_findings = incidents_new = incidents_updated = 0
        with self.db.transaction() as conn:
            # 1. Known detections ------------------------------------------------------------
            for f in correlation:
                inc_id, created = self._persist_incident(
                    conn,
                    key=f"{f.rule_id}|{f.entity}|{f.first_seen}",
                    title=f.rule_title + f" ({f.entity.split(':', 1)[1]})",
                    description=f.rationale,
                    severity=f.severity,
                    rule_id=f.rule_id,
                    first_seen=f.first_seen,
                    last_seen=f.last_seen,
                )
                new_findings += self._persist_findings(conn, inc_id, [f])
                incidents_new += created
                incidents_updated += not created
            for cluster in cluster_host_findings(sigma):
                host = cluster[0].entity.split(":", 1)[1]
                titles = sorted({f.rule_title for f in cluster})
                inc_id, created = self._persist_incident(
                    conn,
                    key=f"SIGMA-HOST|{host}|{cluster[0].first_seen}",
                    title=f"Suspicious activity on {host}",
                    description=f"{len(cluster)} Sigma detection(s): " + "; ".join(titles),
                    severity=Severity.max(*(f.severity for f in cluster)),
                    rule_id="SIGMA-HOST-CLUSTER",
                    first_seen=min(f.first_seen for f in cluster),
                    last_seen=max(f.last_seen for f in cluster),
                )
                new_findings += self._persist_findings(conn, inc_id, cluster)
                incident_repo.link_incident_events(
                    conn, inc_id, related_alert_ids(events, host, cluster)
                )
                incidents_new += created
                incidents_updated += not created

            # 2. Behavioural indicators --------------------------------------------------------
            indicators_new, anomaly_new = self._persist_behavior(conn, analysis.indicators)
            incidents_new += anomaly_new

            # 3. Assessment, 4. links, 5. coverage ---------------------------------------------
            profiles = incident_repo.incident_profiles(conn)
            for p in profiles:
                counts = incident_repo.evidence_counts(conn, p["id"])
                ev = assessment.Evidence(
                    sigma_rules=counts["sigma"],
                    correlation_rules=counts["correlation"],
                    behavior_indicators=counts["behavior"],
                    analyst_flagged=p["detection_status"] == "suspicious_unmatched",
                )
                confidence, rationale = assessment.assess_confidence(ev)
                incident_repo.set_assessment(
                    conn,
                    p["id"],
                    confidence=confidence,
                    rationale=rationale,
                    detection_status=assessment.detection_status(ev, p["detection_status"]),
                )
            links_new = sum(
                incident_repo.upsert_link(
                    conn, link.a, link.b, link.shared, link.gap_minutes, link.rationale
                )
                for link in assessment.find_links(
                    [
                        assessment.IncidentProfile(
                            p["id"], p["first_seen"], p["last_seen"], p["entities"]
                        )
                        for p in profiles
                    ]
                )
            )
            conn.execute(
                "INSERT INTO app_config (key, value, updated_at) VALUES (?, ?, ?)"
                " ON CONFLICT(key) DO UPDATE SET value = excluded.value,"
                " updated_at = excluded.updated_at",
                (
                    COVERAGE_KEY,
                    json.dumps({"generated_at": utcnow_iso(), "gaps": analysis.coverage_gaps}),
                    utcnow_iso(),
                ),
            )
            audit_repo.append(
                conn,
                action="detection.run",
                outcome="success",
                actor_id=actor.user_id,
                actor_username=actor.username,
                details={
                    "events": len(events),
                    "new_findings": new_findings,
                    "new_incidents": incidents_new,
                    "new_indicators": indicators_new,
                    "new_links": links_new,
                    "correlation_version": self.config.version,
                    "behavior_version": behavior.BEHAVIOR_LOGIC_VERSION,
                },
            )
        summary = DetectionSummary(
            events_scanned=len(events),
            findings_total=len(correlation) + len(sigma),
            findings_new=new_findings,
            incidents_new=incidents_new,
            incidents_updated=incidents_updated,
            duration_ms=int((time.perf_counter() - started) * 1000),
            indicators_total=len(analysis.indicators),
            indicators_new=indicators_new,
            anomaly_incidents_new=anomaly_new,
            links_new=links_new,
            coverage_gaps=len(analysis.coverage_gaps),
        )
        log.info("detection run", extra=summary.__dict__)
        return summary

    def _persist_behavior(
        self,
        conn,
        indicators: list[behavior.Indicator],
    ) -> tuple[int, int]:
        new = 0
        unattached: list[behavior.Indicator] = []
        ids: dict[tuple[str, str], int] = {}
        profiles = incident_repo.incident_profiles(conn)
        for ind in indicators:
            ind_id, created = incident_repo.upsert_indicator(
                conn,
                detector_id=ind.detector_id,
                detector_version=ind.detector_version,
                entity=ind.entity,
                score=ind.score,
                fingerprint=ind.fingerprint,
                baseline=ind.baseline,
                rationale=ind.rationale,
                observed_at=ind.observed_at,
            )
            new += created
            ids[(ind.detector_id, ind.fingerprint)] = ind_id
            existing = incident_repo.indicator_incident(conn, ind.detector_id, ind.fingerprint)
            target = existing or choose_incident(ind, profiles)
            if target is None:
                unattached.append(ind)
            else:
                incident_repo.attach_indicator(conn, ind_id, target, ind.event_ids)
        anomaly_new = 0
        for cluster in cluster_indicators(unattached):
            entity = cluster[0].entity
            kind, name = entity.split(":", 1)
            peak = max(i.score for i in cluster)
            inc_id, created = self._persist_incident(
                conn,
                key=f"BEHAVIOR|{entity}|{cluster[0].observed_at}",
                title=(
                    f"Anomalous behaviour on {name}"
                    if kind == "host"
                    else f"Anomalous behaviour for user {name}"
                ),
                description=(
                    f"{len(cluster)} behavioural indicator(s), no known detection: "
                    + "; ".join(sorted({i.title for i in cluster}))
                    + ". Requires analyst review; unusual is not the same as malicious."
                ),
                severity=Severity.MEDIUM if peak >= 0.75 else Severity.LOW,
                rule_id="BEHAVIOR-CLUSTER",
                first_seen=min(i.observed_at for i in cluster),
                last_seen=max(i.observed_at for i in cluster),
                detection_status="anomalous_behavior",
            )
            anomaly_new += created
            for ind in cluster:
                incident_repo.attach_indicator(
                    conn, ids[(ind.detector_id, ind.fingerprint)], inc_id, ind.event_ids
                )
        return new, anomaly_new

    def _persist_incident(
        self,
        conn,
        *,
        key: str,
        title: str,
        description: str,
        severity: Severity,
        rule_id: str,
        first_seen: str,
        last_seen: str,
        detection_status: str = "known_detection",
    ) -> tuple[int, bool]:
        inc_id, created = incident_repo.upsert_incident(
            conn,
            correlation_key=key,
            title=title[:200],
            description=description[:2000],
            severity=severity.value,
            rule_id=rule_id,
            first_seen=first_seen,
            last_seen=last_seen,
            detection_status=detection_status,
        )
        if created:
            audit_repo.append(
                conn,
                action="incident.create",
                outcome="success",
                target_type="incident",
                target_id=inc_id,
                details={
                    "rule_id": rule_id,
                    "severity": severity.value,
                    "detection_status": detection_status,
                },
            )
        return inc_id, created

    def _persist_findings(self, conn, incident_id: int, findings: list[Finding]) -> int:
        new = 0
        for f in findings:
            finding_id, created = incident_repo.upsert_finding(
                conn,
                rule_id=f.rule_id,
                rule_title=f.rule_title,
                engine=f.engine,
                severity=f.severity.value,
                fingerprint=f.fingerprint,
                matched_fields=f.matched_fields,
                rule_version=f.rule_version,
            )
            new += created
            incident_repo.link_finding_events(conn, finding_id, f.event_ids)
            incident_repo.set_finding_incident(conn, finding_id, incident_id)
            incident_repo.link_incident_events(conn, incident_id, f.event_ids)
            for technique_id, confidence in f.techniques:
                self.catalog.get(technique_id)  # raises if a rule references an invalid ID
                incident_repo.add_mapping(
                    conn,
                    incident_id=incident_id,
                    finding_id=finding_id,
                    technique_id=technique_id,
                    source="rule",
                    confidence=confidence,
                    rationale=f.rationale,
                    evidence_ids=f.event_ids,
                    dataset_version=self.catalog.label,
                )
        return new
