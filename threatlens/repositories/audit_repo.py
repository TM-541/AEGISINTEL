"""Append-only, hash-chained audit trail.

Each row stores ``prev_hash`` and ``row_hash = sha256(prev_hash || canonical(row))``.
Edits or deletions made outside the API (triggers block them through SQLite) are detected by
``verify_chain``. This shows tampering but does not prevent it. Someone with write access to
the file can rebuild the whole chain. See THREAT_MODEL.md T15.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from typing import Any

from threatlens.logging_setup import redact
from threatlens.timeutil import utcnow_iso

GENESIS = "0" * 64


def _row_hash(prev_hash: str, fields: dict[str, Any]) -> str:
    canonical = json.dumps(fields, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()


def append(
    conn: sqlite3.Connection,
    *,
    action: str,
    outcome: str,
    actor_id: int | None = None,
    actor_username: str | None = None,
    target_type: str | None = None,
    target_id: str | int | None = None,
    details: dict[str, Any] | None = None,
) -> int:
    """Append an audit event. Caller should hold a write transaction for chain ordering."""
    row = conn.execute("SELECT row_hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
    prev_hash = row["row_hash"] if row else GENESIS
    fields = {
        "ts": utcnow_iso(),
        "actor_id": actor_id,
        "actor_username": actor_username,
        "action": action,
        "target_type": target_type,
        "target_id": None if target_id is None else str(target_id),
        "outcome": outcome,
        "details": json.dumps(redact(details or {}), sort_keys=True, default=str)[:4000],
    }
    row_hash = _row_hash(prev_hash, fields)
    cur = conn.execute(
        "INSERT INTO audit_events (ts, actor_id, actor_username, action, target_type, target_id,"
        " outcome, details, prev_hash, row_hash) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (
            fields["ts"],
            actor_id,
            actor_username,
            action,
            target_type,
            fields["target_id"],
            outcome,
            fields["details"],
            prev_hash,
            row_hash,
        ),
    )
    return int(cur.lastrowid or 0)


@dataclass(frozen=True)
class ChainStatus:
    ok: bool
    checked: int
    first_bad_id: int | None = None


def verify_chain(conn: sqlite3.Connection) -> ChainStatus:
    prev = GENESIS
    count = 0
    for row in conn.execute("SELECT * FROM audit_events ORDER BY id"):
        fields = {
            k: row[k]
            for k in (
                "ts",
                "actor_id",
                "actor_username",
                "action",
                "target_type",
                "target_id",
                "outcome",
                "details",
            )
        }
        if row["prev_hash"] != prev or _row_hash(prev, fields) != row["row_hash"]:
            return ChainStatus(False, count, row["id"])
        prev = row["row_hash"]
        count += 1
    return ChainStatus(True, count)


def list_events(
    conn: sqlite3.Connection,
    *,
    action: str | None = None,
    actor: str | None = None,
    limit: int = 500,
) -> list[sqlite3.Row]:
    clauses: list[str] = []
    params: list[Any] = []
    if action:
        clauses.append("action = ?")
        params.append(action)
    if actor:
        clauses.append("actor_username = ?")
        params.append(actor)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(max(1, min(limit, 5000)))
    return conn.execute(
        f"SELECT * FROM audit_events {where} ORDER BY id DESC LIMIT ?",  # nosec B608 # noqa: S608 - static clauses
        params,
    ).fetchall()
