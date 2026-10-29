"""Event and import persistence."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from threatlens.ingest.normalize import NormalizedEvent
from threatlens.timeutil import utcnow_iso

EVENT_COLUMNS = (
    "id",
    "content_hash",
    "import_id",
    "source_type",
    "timestamp",
    "event_type",
    "category",
    "severity",
    "outcome",
    "username",
    "host",
    "src_ip",
    "dest_ip",
    "process_name",
    "command_line",
    "parent_process",
    "message",
    "raw_json",
    "ingested_at",
    "original_timestamp",
    "normalization_notes",
)
SORTABLE = {"timestamp", "severity", "event_type", "username", "host"}
BATCH_SIZE = 1000


def existing_hashes(conn: sqlite3.Connection, hashes: Sequence[str]) -> set[str]:
    found: set[str] = set()
    for i in range(0, len(hashes), 500):
        chunk = list(hashes[i : i + 500])
        marks = ",".join("?" * len(chunk))
        found.update(
            r[0]
            for r in conn.execute(
                f"SELECT content_hash FROM events WHERE content_hash IN ({marks})",  # nosec B608 # noqa: S608
                chunk,
            )
        )
    return found


def file_already_imported(conn: sqlite3.Connection, file_sha256: str) -> bool:
    row = conn.execute("SELECT 1 FROM imports WHERE file_sha256 = ?", (file_sha256,)).fetchone()
    return row is not None


def create_import(conn: sqlite3.Connection, **fields: Any) -> int:
    cur = conn.execute(
        "INSERT INTO imports (file_label, file_format, source_type, file_sha256, record_count,"
        " inserted_count, duplicate_count, rejected_count, imported_by, created_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?)",
        (
            fields["file_label"],
            fields["file_format"],
            fields["source_type"],
            fields["file_sha256"],
            fields["record_count"],
            0,
            0,
            fields["rejected_count"],
            fields["imported_by"],
            utcnow_iso(),
        ),
    )
    return int(cur.lastrowid or 0)


def finalize_import(conn: sqlite3.Connection, import_id: int, inserted: int, dupes: int) -> None:
    conn.execute(
        "UPDATE imports SET inserted_count = ?, duplicate_count = ? WHERE id = ?",
        (inserted, dupes, import_id),
    )


def insert_events(
    conn: sqlite3.Connection, import_id: int, events: Sequence[NormalizedEvent]
) -> int:
    """Insert events, skipping ones already stored (by content hash). Returns rows inserted."""
    now = utcnow_iso()
    inserted = 0
    sql = (
        f"INSERT OR IGNORE INTO events ({','.join(EVENT_COLUMNS)})"  # noqa: S608
        f" VALUES ({','.join('?' * len(EVENT_COLUMNS))})"
    )
    for i in range(0, len(events), BATCH_SIZE):
        batch = events[i : i + BATCH_SIZE]
        before = conn.total_changes
        conn.executemany(
            sql,
            [
                (
                    e.id,
                    e.content_hash,
                    import_id,
                    e.source_type.value,
                    e.timestamp,
                    e.event_type,
                    e.category,
                    e.severity.value,
                    e.outcome,
                    e.username,
                    e.host,
                    e.src_ip,
                    e.dest_ip,
                    e.process_name,
                    e.command_line,
                    e.parent_process,
                    e.message,
                    e.raw_json,
                    now,
                    e.original_timestamp,
                    json.dumps(list(e.normalization_notes)),
                )
                for e in batch
            ],
        )
        inserted += conn.total_changes - before
    return inserted


@dataclass
class EventFilter:
    text: str | None = None
    usernames: Sequence[str] = ()
    hosts: Sequence[str] = ()
    event_types: Sequence[str] = ()
    severities: Sequence[str] = ()
    since: str | None = None
    until: str | None = None
    sort: str = "timestamp"
    descending: bool = True
    limit: int = 500
    offset: int = 0


def _event_where(f: EventFilter) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []

    def _in(column: str, values: Sequence[str]) -> None:
        if values:
            clauses.append(f"{column} IN ({','.join('?' * len(values))})")
            params.extend(values)

    _in("username", f.usernames)
    _in("host", f.hosts)
    _in("event_type", f.event_types)
    _in("severity", f.severities)
    if f.since:
        clauses.append("timestamp >= ?")
        params.append(f.since)
    if f.until:
        clauses.append("timestamp <= ?")
        params.append(f.until)
    if f.text:
        like = "%" + f.text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        clauses.append(
            "(message LIKE ? ESCAPE '\\' OR command_line LIKE ? ESCAPE '\\'"
            " OR process_name LIKE ? ESCAPE '\\' OR id LIKE ? ESCAPE '\\')"
        )
        params.extend([like] * 4)
    return (f"WHERE {' AND '.join(clauses)}" if clauses else ""), params


def search_events(conn: sqlite3.Connection, f: EventFilter) -> list[sqlite3.Row]:
    where, params = _event_where(f)
    sort = f.sort if f.sort in SORTABLE else "timestamp"  # allow-list, never user text in SQL
    direction = "DESC" if f.descending else "ASC"
    params.extend([max(1, min(f.limit, 5000)), max(0, f.offset)])
    return conn.execute(
        f"SELECT * FROM events {where} ORDER BY {sort} {direction}, id LIMIT ? OFFSET ?",  # nosec B608 # noqa: S608
        params,
    ).fetchall()


def count_events(conn: sqlite3.Connection, f: EventFilter) -> int:
    """Total rows matching the filter (ignores sort/limit/offset), for pagination."""
    where, params = _event_where(f)
    return int(
        conn.execute(
            f"SELECT COUNT(*) FROM events {where}",  # nosec B608 # noqa: S608
            params,
        ).fetchone()[0]
    )


def get_events(conn: sqlite3.Connection, ids: Sequence[str]) -> list[sqlite3.Row]:
    if not ids:
        return []
    marks = ",".join("?" * len(ids))
    return conn.execute(
        f"SELECT * FROM events WHERE id IN ({marks}) ORDER BY timestamp, id",  # nosec B608 # noqa: S608
        list(ids),
    ).fetchall()


def all_events_ordered(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM events ORDER BY timestamp, id").fetchall()


def list_imports(conn: sqlite3.Connection, limit: int = 100) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT i.*, u.username AS imported_by_name FROM imports i"
        " JOIN users u ON u.id = i.imported_by ORDER BY i.id DESC LIMIT ?",
        (limit,),
    ).fetchall()


def distinct_values(conn: sqlite3.Connection, column: str) -> list[str]:
    if column not in {"username", "host", "event_type", "severity", "source_type"}:
        raise ValueError("unsupported column")
    return [
        r[0]
        for r in conn.execute(
            f"SELECT DISTINCT {column} FROM events WHERE {column} IS NOT NULL"  # nosec B608 # noqa: S608
            f" ORDER BY {column} LIMIT 1000"
        )
    ]


_IMPORT_INCIDENTS = (
    "SELECT DISTINCT ie.incident_id FROM incident_events ie JOIN events e ON e.id = ie.event_id"
    " WHERE e.import_id = ?"
)


def purge_scope(conn: sqlite3.Connection, import_id: int) -> dict[str, Any]:
    incidents = [r[0] for r in conn.execute(_IMPORT_INCIDENTS, (import_id,))]
    events = conn.execute(
        "SELECT COUNT(*) FROM events WHERE import_id = ?", (import_id,)
    ).fetchone()[0]
    return {"events": events, "incident_ids": incidents}


def purge_import(conn: sqlite3.Connection, import_id: int) -> dict[str, int]:
    """Delete an import, its events and dependent evidence. Caller holds the transaction."""
    incidents = [r[0] for r in conn.execute(_IMPORT_INCIDENTS, (import_id,))]
    event_sub = "SELECT id FROM events WHERE import_id = ?"
    # Incidents built on these events go too (cascades: links, mappings, notes, reports,
    # proposals, incident_events). Findings/indicators referencing the events are removed.
    for iid in incidents:
        conn.execute("DELETE FROM incidents WHERE id = ?", (iid,))
    conn.execute(f"DELETE FROM finding_events WHERE event_id IN ({event_sub})", (import_id,))  # nosec B608 # noqa: S608
    conn.execute("DELETE FROM findings WHERE id NOT IN (SELECT finding_id FROM finding_events)")
    conn.execute(
        f"DELETE FROM behavior_indicator_events WHERE event_id IN ({event_sub})",  # nosec B608 # noqa: S608
        (import_id,),
    )
    conn.execute(
        "DELETE FROM behavior_indicators WHERE id NOT IN"
        " (SELECT indicator_id FROM behavior_indicator_events)"
    )
    conn.execute(f"DELETE FROM incident_events WHERE event_id IN ({event_sub})", (import_id,))  # nosec B608 # noqa: S608
    events = conn.execute("DELETE FROM events WHERE import_id = ?", (import_id,)).rowcount
    conn.execute("DELETE FROM imports WHERE id = ?", (import_id,))
    return {"events_deleted": events, "incidents_deleted": len(incidents)}
