"""Incidents, findings, ATT&CK mappings, notes and their evidence links."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Sequence
from typing import Any

from threatlens.timeutil import utcnow_iso

SORTABLE = {"created_at", "updated_at", "first_seen", "last_seen", "severity", "status", "id"}
_SEV_PARAM = (
    "CASE ? WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2"
    " WHEN 'low' THEN 1 ELSE 0 END"
)
SEVERITY_ORDER = (
    "CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2"
    " WHEN 'low' THEN 1 ELSE 0 END"
)


def upsert_indicator(
    conn: sqlite3.Connection,
    *,
    detector_id: str,
    detector_version: str,
    entity: str,
    score: float,
    fingerprint: str,
    baseline: dict[str, Any],
    rationale: str,
    observed_at: str,
) -> tuple[int, bool]:
    row = conn.execute(
        "SELECT id FROM behavior_indicators WHERE detector_id = ? AND fingerprint = ?",
        (detector_id, fingerprint),
    ).fetchone()
    if row:
        return int(row["id"]), False
    cur = conn.execute(
        "INSERT INTO behavior_indicators (detector_id, detector_version, entity, score,"
        " fingerprint, baseline, rationale, observed_at, created_at)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        (
            detector_id,
            detector_version,
            entity,
            score,
            fingerprint,
            json.dumps(baseline, sort_keys=True),
            rationale[:1000],
            observed_at,
            utcnow_iso(),
        ),
    )
    return int(cur.lastrowid or 0), True


def attach_indicator(
    conn: sqlite3.Connection, indicator_id: int, incident_id: int, event_ids: Sequence[str]
) -> None:
    conn.executemany(
        "INSERT OR IGNORE INTO behavior_indicator_events (indicator_id, event_id) VALUES (?, ?)",
        [(indicator_id, e) for e in event_ids],
    )
    conn.execute(
        "UPDATE behavior_indicators SET incident_id = ? WHERE id = ?", (incident_id, indicator_id)
    )
    link_incident_events(conn, incident_id, event_ids)


def indicator_incident(conn: sqlite3.Connection, detector_id: str, fingerprint: str) -> int | None:
    row = conn.execute(
        "SELECT incident_id FROM behavior_indicators WHERE detector_id = ? AND fingerprint = ?",
        (detector_id, fingerprint),
    ).fetchone()
    return row["incident_id"] if row else None


def indicators_for_incident(conn: sqlite3.Connection, incident_id: int) -> list[dict[str, Any]]:
    out = []
    for r in conn.execute(
        "SELECT * FROM behavior_indicators WHERE incident_id = ? ORDER BY observed_at, id",
        (incident_id,),
    ):
        d = dict(r)
        d["baseline"] = json.loads(d["baseline"])
        d["event_ids"] = [
            x[0]
            for x in conn.execute(
                "SELECT event_id FROM behavior_indicator_events WHERE indicator_id = ?"
                " ORDER BY event_id",
                (r["id"],),
            )
        ]
        out.append(d)
    return out


def incident_profiles(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Every incident with its time window and the entities in its evidence."""
    rows = conn.execute(
        "SELECT i.id, i.first_seen, i.last_seen, i.severity, i.detection_status,"
        " e.username, e.host, e.src_ip FROM incidents i"
        " LEFT JOIN incident_events ie ON ie.incident_id = i.id"
        " LEFT JOIN events e ON e.id = ie.event_id ORDER BY i.id"
    ).fetchall()
    profiles: dict[int, dict[str, Any]] = {}
    for r in rows:
        p = profiles.setdefault(
            r["id"],
            {
                "id": r["id"],
                "first_seen": r["first_seen"],
                "last_seen": r["last_seen"],
                "severity": r["severity"],
                "detection_status": r["detection_status"],
                "entities": set(),
                "event_ids": set(),
            },
        )
        for prefix, value in (("user", r["username"]), ("host", r["host"]), ("ip", r["src_ip"])):
            if value:
                p["entities"].add(f"{prefix}:{value}")
    for r in conn.execute("SELECT incident_id, event_id FROM incident_events"):
        if r["incident_id"] in profiles:
            profiles[r["incident_id"]]["event_ids"].add(r["event_id"])
    return list(profiles.values())


def evidence_counts(conn: sqlite3.Connection, incident_id: int) -> dict[str, int]:
    row = conn.execute(
        "SELECT"
        " (SELECT COUNT(DISTINCT rule_id) FROM findings WHERE incident_id = ?"
        "  AND engine = 'sigma'),"
        " (SELECT COUNT(DISTINCT rule_id) FROM findings WHERE incident_id = ?"
        "  AND engine = 'correlation'),"
        " (SELECT COUNT(*) FROM behavior_indicators WHERE incident_id = ?)",
        (incident_id, incident_id, incident_id),
    ).fetchone()
    return {"sigma": row[0], "correlation": row[1], "behavior": row[2]}


def set_assessment(
    conn: sqlite3.Connection,
    incident_id: int,
    *,
    confidence: str,
    rationale: str,
    detection_status: str,
) -> None:
    conn.execute(
        "UPDATE incidents SET confidence = ?, confidence_rationale = ?, detection_status = ?"
        " WHERE id = ? AND (confidence != ? OR confidence_rationale != ? OR detection_status != ?)",
        (
            confidence,
            rationale,
            detection_status,
            incident_id,
            confidence,
            rationale,
            detection_status,
        ),
    )


def upsert_link(
    conn: sqlite3.Connection,
    a: int,
    b: int,
    shared: Sequence[str],
    gap_minutes: int,
    rationale: str,
) -> bool:
    cur = conn.execute(
        "INSERT OR IGNORE INTO incident_links (incident_a, incident_b, shared_entities,"
        " gap_minutes, rationale, created_at) VALUES (?,?,?,?,?,?)",
        (a, b, json.dumps(list(shared)), gap_minutes, rationale, utcnow_iso()),
    )
    return cur.rowcount == 1


def links_for_incident(conn: sqlite3.Connection, incident_id: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT l.*, i.id AS other_id, i.title AS other_title, i.severity AS other_severity,"
        " i.status AS other_status FROM incident_links l JOIN incidents i"
        " ON i.id = CASE WHEN l.incident_a = ? THEN l.incident_b ELSE l.incident_a END"
        " WHERE l.incident_a = ? OR l.incident_b = ? ORDER BY l.gap_minutes",
        (incident_id, incident_id, incident_id),
    ).fetchall()
    return [{**dict(r), "shared_entities": json.loads(r["shared_entities"])} for r in rows]


def upsert_finding(
    conn: sqlite3.Connection,
    *,
    rule_id: str,
    rule_title: str,
    engine: str,
    severity: str,
    fingerprint: str,
    matched_fields: dict[str, Any],
    rule_version: str = "",
) -> tuple[int, bool]:
    row = conn.execute(
        "SELECT id FROM findings WHERE rule_id = ? AND fingerprint = ?", (rule_id, fingerprint)
    ).fetchone()
    if row:
        return int(row["id"]), False
    cur = conn.execute(
        "INSERT INTO findings (rule_id, rule_title, engine, severity, fingerprint, matched_fields,"
        " rule_version, created_at) VALUES (?,?,?,?,?,?,?,?)",
        (
            rule_id,
            rule_title,
            engine,
            severity,
            fingerprint,
            json.dumps(matched_fields, sort_keys=True, default=str),
            rule_version,
            utcnow_iso(),
        ),
    )
    return int(cur.lastrowid or 0), True


def link_finding_events(
    conn: sqlite3.Connection, finding_id: int, event_ids: Sequence[str]
) -> None:
    conn.executemany(
        "INSERT OR IGNORE INTO finding_events (finding_id, event_id) VALUES (?, ?)",
        [(finding_id, e) for e in event_ids],
    )


def upsert_incident(
    conn: sqlite3.Connection,
    *,
    detection_status: str = "known_detection",
    correlation_key: str,
    title: str,
    description: str,
    severity: str,
    rule_id: str,
    first_seen: str,
    last_seen: str,
) -> tuple[int, bool]:
    row = conn.execute(
        "SELECT id, severity, first_seen, last_seen FROM incidents WHERE correlation_key = ?",
        (correlation_key,),
    ).fetchone()
    now = utcnow_iso()
    if row:
        conn.execute(
            # Static SQL built from the SEVERITY_ORDER constant; all values are bound params.
            f"UPDATE incidents SET severity = CASE WHEN {_SEV_PARAM}"  # nosec B608 # noqa: S608
            f" > {SEVERITY_ORDER} THEN ? ELSE severity END,"
            " first_seen = MIN(first_seen, ?), last_seen = MAX(last_seen, ?), updated_at = ?"
            " WHERE id = ?",
            (severity, severity, first_seen, last_seen, now, row["id"]),
        )
        return int(row["id"]), False
    cur = conn.execute(
        "INSERT INTO incidents (title, description, severity, correlation_key, rule_id,"
        " first_seen, last_seen, detection_status, created_at, updated_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?)",
        (
            title,
            description,
            severity,
            correlation_key,
            rule_id,
            first_seen,
            last_seen,
            detection_status,
            now,
            now,
        ),
    )
    return int(cur.lastrowid or 0), True


def link_incident_events(
    conn: sqlite3.Connection, incident_id: int, event_ids: Sequence[str]
) -> None:
    conn.executemany(
        "INSERT OR IGNORE INTO incident_events (incident_id, event_id) VALUES (?, ?)",
        [(incident_id, e) for e in event_ids],
    )


def set_finding_incident(conn: sqlite3.Connection, finding_id: int, incident_id: int) -> None:
    conn.execute("UPDATE findings SET incident_id = ? WHERE id = ?", (incident_id, finding_id))


def add_mapping(
    conn: sqlite3.Connection,
    *,
    incident_id: int,
    finding_id: int | None,
    technique_id: str,
    source: str,
    confidence: str,
    rationale: str,
    evidence_ids: Sequence[str],
    dataset_version: str,
) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO attack_mappings (incident_id, finding_id, technique_id, source,"
        " confidence, rationale, evidence_ids, dataset_version, created_at)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        (
            incident_id,
            finding_id,
            technique_id,
            source,
            confidence,
            rationale[:1000],
            json.dumps(list(evidence_ids)),
            dataset_version,
            utcnow_iso(),
        ),
    )


def list_incidents(
    conn: sqlite3.Connection,
    *,
    statuses: Sequence[str] = (),
    severities: Sequence[str] = (),
    assigned_to: int | None = None,
    text: str | None = None,
    sort: str = "severity",
    descending: bool = True,
    limit: int = 500,
    offset: int = 0,
    detection_statuses: Sequence[str] = (),
    dispositions: Sequence[str] = (),
) -> list[sqlite3.Row]:
    clauses, params = _incident_filters(
        statuses, severities, assigned_to, text, detection_statuses, dispositions
    )
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    order = (
        SEVERITY_ORDER.replace("severity", "i.severity")
        if sort == "severity"
        else (f"i.{sort}" if sort in SORTABLE else "i.created_at")
    )
    direction = "DESC" if descending else "ASC"
    params.extend([max(1, min(limit, 5000)), max(0, offset)])
    return conn.execute(
        "SELECT i.*, u.username AS assignee,"  # nosec B608 # noqa: S608 - allow-listed clauses, bound params
        " (SELECT COUNT(*) FROM incident_events ie WHERE ie.incident_id = i.id) AS event_count"
        f" FROM incidents i LEFT JOIN users u ON u.id = i.assigned_to {where}"
        f" ORDER BY {order} {direction}, i.last_seen DESC LIMIT ? OFFSET ?",
        params,
    ).fetchall()


def count_incidents(conn: sqlite3.Connection, **filters: Any) -> int:
    clauses, params = _incident_filters(
        filters.get("statuses", ()),
        filters.get("severities", ()),
        filters.get("assigned_to"),
        filters.get("text"),
        filters.get("detection_statuses", ()),
        filters.get("dispositions", ()),
    )
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    return int(
        conn.execute(
            f"SELECT COUNT(*) FROM incidents i {where}",  # nosec B608 # noqa: S608
            params,
        ).fetchone()[0]
    )


def _incident_filters(
    statuses: Sequence[str],
    severities: Sequence[str],
    assigned_to: int | None,
    text: str | None,
    detection_statuses: Sequence[str],
    dispositions: Sequence[str],
) -> tuple[list[str], list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    for column, values in (
        ("i.detection_status", detection_statuses),
        ("i.disposition", dispositions),
    ):
        if values:
            clauses.append(f"{column} IN ({','.join('?' * len(values))})")
            params.extend(values)
    if statuses:
        clauses.append(f"i.status IN ({','.join('?' * len(statuses))})")
        params.extend(statuses)
    if severities:
        clauses.append(f"i.severity IN ({','.join('?' * len(severities))})")
        params.extend(severities)
    if assigned_to is not None:
        clauses.append("i.assigned_to = ?")
        params.append(assigned_to)
    if text:
        clauses.append("(i.title LIKE ? ESCAPE '\\' OR i.description LIKE ? ESCAPE '\\')")
        like = "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        params.extend([like, like])
    return clauses, params


def get_incident(conn: sqlite3.Connection, incident_id: int) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT i.*, u.username AS assignee FROM incidents i"
        " LEFT JOIN users u ON u.id = i.assigned_to WHERE i.id = ?",
        (incident_id,),
    ).fetchone()


def incident_event_ids(conn: sqlite3.Connection, incident_id: int) -> list[str]:
    return [
        r[0]
        for r in conn.execute(
            "SELECT ie.event_id FROM incident_events ie JOIN events e ON e.id = ie.event_id"
            " WHERE ie.incident_id = ? ORDER BY e.timestamp, e.id",
            (incident_id,),
        )
    ]


def incident_events(
    conn: sqlite3.Connection, incident_id: int, limit: int = 2000
) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT e.* FROM events e JOIN incident_events ie ON ie.event_id = e.id"
        " WHERE ie.incident_id = ? ORDER BY e.timestamp, e.id LIMIT ?",
        (incident_id, limit),
    ).fetchall()


def findings_for_incident(conn: sqlite3.Connection, incident_id: int) -> list[dict[str, Any]]:
    out = []
    for f in conn.execute(
        "SELECT * FROM findings WHERE incident_id = ? ORDER BY id", (incident_id,)
    ):
        d = dict(f)
        d["matched_fields"] = json.loads(d["matched_fields"])
        d["event_ids"] = [
            r[0]
            for r in conn.execute(
                "SELECT event_id FROM finding_events WHERE finding_id = ? ORDER BY event_id",
                (f["id"],),
            )
        ]
        out.append(d)
    return out


def mappings_for_incident(conn: sqlite3.Connection, incident_id: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT m.*, f.rule_title FROM attack_mappings m LEFT JOIN findings f"
        " ON f.id = m.finding_id WHERE m.incident_id = ? ORDER BY m.source, m.technique_id",
        (incident_id,),
    )
    return [{**dict(r), "evidence_ids": json.loads(r["evidence_ids"])} for r in rows]


def all_mappings(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT m.technique_id, m.source, m.confidence, m.incident_id, i.title, i.severity"
        " FROM attack_mappings m JOIN incidents i ON i.id = m.incident_id"
        " ORDER BY m.technique_id"
    ).fetchall()


def update_status(conn: sqlite3.Connection, incident_id: int, status: str, expected: str) -> bool:
    cur = conn.execute(
        "UPDATE incidents SET status = ?, updated_at = ? WHERE id = ? AND status = ?",
        (status, utcnow_iso(), incident_id, expected),
    )
    return cur.rowcount == 1


def assign(conn: sqlite3.Connection, incident_id: int, user_id: int | None) -> None:
    conn.execute(
        "UPDATE incidents SET assigned_to = ?, updated_at = ? WHERE id = ?",
        (user_id, utcnow_iso(), incident_id),
    )


def add_note(conn: sqlite3.Connection, incident_id: int, author_id: int, body: str) -> int:
    cur = conn.execute(
        "INSERT INTO incident_notes (incident_id, author_id, body, created_at) VALUES (?,?,?,?)",
        (incident_id, author_id, body, utcnow_iso()),
    )
    return int(cur.lastrowid or 0)


def notes(conn: sqlite3.Connection, incident_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT n.*, u.username AS author FROM incident_notes n JOIN users u"
        " ON u.id = n.author_id WHERE n.incident_id = ? ORDER BY n.id",
        (incident_id,),
    ).fetchall()
