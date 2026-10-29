"""Import time limits, atomicity on interruption, pagination and audited data deletion."""

from __future__ import annotations

import json

import pytest

from tests.test_investigation import FakeOllama, make_services, seed
from threatlens.errors import AuthorizationError, NotFoundError, ValidationFailedError
from threatlens.ingest.normalize import SourceType
from threatlens.models.domain import Role
from threatlens.repositories import event_repo
from threatlens.repositories.event_repo import EventFilter

GOOD = {"timestamp": "2026-10-20T10:00:00Z", "event_type": "4625", "user": "alice"}


def jsonl(n: int) -> bytes:
    return "\n".join(json.dumps({**GOOD, "n": i}) for i in range(n)).encode()


def test_import_processing_time_limit(services, analyst_token, monkeypatch):
    import threatlens.services.ingestion_service as mod

    services.settings.max_import_seconds = 1
    clock = iter([0.0, 5.0, 5.0, 5.0])  # deadline at 1.0; first check already past it
    monkeypatch.setattr(mod.time, "monotonic", lambda: next(clock))
    with pytest.raises(ValidationFailedError, match="exceeded 1 seconds"):
        services.ingestion.preview(analyst_token, "a.jsonl", jsonl(10), SourceType.AUTH)


def test_interrupted_import_leaves_no_partial_data(services, analyst_token, monkeypatch):
    data = jsonl(50)
    preview = services.ingestion.preview(analyst_token, "a.jsonl", data, SourceType.AUTH)

    def boom(conn, import_id, events):
        conn.executemany(
            "INSERT INTO events (id, content_hash, import_id, source_type,"
            " timestamp, event_type, category, severity, raw_json, ingested_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            [
                (
                    e.id,
                    e.content_hash,
                    import_id,
                    "auth",
                    e.timestamp,
                    e.event_type,
                    e.category,
                    e.severity.value,
                    e.raw_json,
                    "x",
                )
                for e in events[:10]
            ],
        )
        raise OSError("disk full")  # simulated failure halfway through the write

    monkeypatch.setattr(event_repo, "insert_events", boom)
    with pytest.raises(OSError):
        services.ingestion.commit(
            analyst_token, "a.jsonl", data, SourceType.AUTH, confirmed_sha256=preview.file_sha256
        )
    monkeypatch.undo()
    assert services.ingestion.count(analyst_token, EventFilter()) == 0
    assert services.ingestion.list_imports(analyst_token) == []
    # And the same file can be imported cleanly afterwards.
    result = services.ingestion.commit(
        analyst_token, "a.jsonl", data, SourceType.AUTH, confirmed_sha256=preview.file_sha256
    )
    assert result.inserted == 50


def test_pagination_count_matches_filters(services, analyst_token):
    data = jsonl(120)
    p = services.ingestion.preview(analyst_token, "a.jsonl", data, SourceType.AUTH)
    services.ingestion.commit(
        analyst_token, "a.jsonl", data, SourceType.AUTH, confirmed_sha256=p.file_sha256
    )
    flt = EventFilter(usernames=["alice"], limit=50)
    assert services.ingestion.count(analyst_token, flt) == 120
    pages = [
        services.ingestion.search(
            analyst_token, EventFilter(usernames=["alice"], limit=50, offset=o)
        )
        for o in (0, 50, 100)
    ]
    ids = [e["id"] for page in pages for e in page]
    assert [len(p) for p in pages] == [50, 50, 20] and len(set(ids)) == 120
    assert services.ingestion.count(analyst_token, EventFilter(text="%' OR 1=1 --")) == 0


@pytest.fixture()
def world(settings):
    services = make_services(settings, FakeOllama([]))
    admin, host_iid, _, _ = seed(services)
    services.users.create_user(
        admin, username="analyst1", password="Analyst-Strong-Pass-42", role=Role.ANALYST
    )
    return services, admin, services.auth.login("analyst1", "Analyst-Strong-Pass-42")


def test_purge_shows_impact_then_deletes_import_and_dependent_incidents(world):
    s, admin, _ = world
    endpoint = next(
        i for i in s.ingestion.list_imports(admin) if i["file_label"] == "endpoint_events.json"
    )
    impact = s.ingestion.purge_impact(admin, endpoint["id"])
    assert impact["events"] == endpoint["inserted_count"] and impact["incident_ids"]
    with pytest.raises(ValidationFailedError):
        s.ingestion.purge_import(admin, endpoint["id"], confirm_label="wrong.json")
    removed = s.ingestion.purge_import(admin, endpoint["id"], confirm_label="endpoint_events.json")
    assert removed == {
        "events_deleted": impact["events"],
        "incidents_deleted": len(impact["incident_ids"]),
    }
    remaining = {i["id"] for i in s.incidents.list_incidents(admin)}
    assert not remaining & set(impact["incident_ids"])
    with s.db.connect() as conn:
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM events WHERE import_id = ?", (endpoint["id"],)
            ).fetchone()[0]
            == 0
        )
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
    [row] = s.admin.audit_log(admin, action="data.purge_import")
    assert "events_deleted" in row["details"] and "certutil" not in row["details"]
    assert s.admin.verify_audit_chain(admin)["ok"]
    # Detection on the remaining data still works.
    s.detection.run(admin)


def test_only_admins_can_purge(world):
    s, admin, analyst = world
    imp = s.ingestion.list_imports(admin)[0]
    with pytest.raises(AuthorizationError):
        s.ingestion.purge_impact(analyst, imp["id"])
    with pytest.raises(AuthorizationError):
        s.ingestion.purge_import(analyst, imp["id"], confirm_label=imp["file_label"])
    with pytest.raises(NotFoundError):
        s.ingestion.purge_import(admin, 999_999, confirm_label="x")
