from __future__ import annotations

import json
from pathlib import Path

import pytest

from threatlens.errors import AuthorizationError, ConflictError, ValidationFailedError
from threatlens.ingest.normalize import RecordError, SourceType, normalize
from threatlens.ingest.parsers import ParseError, detect_format, sanitize_label
from threatlens.models.domain import Severity
from threatlens.repositories import audit_repo
from threatlens.repositories.event_repo import EventFilter

SAMPLES = Path(__file__).resolve().parent.parent / "sample_data"


def jsonl(*records: dict) -> bytes:
    return "\n".join(json.dumps(r) for r in records).encode()


GOOD = {
    "timestamp": "2026-10-20T10:00:00Z",
    "event_type": "4625",
    "user": "Alice",
    "host": "WS-1",
    "src_ip": "192.0.2.10",
    "severity": "low",
}


def _import(services, token, name, data, source=SourceType.AUTH):
    preview = services.ingestion.preview(token, name, data, source)
    return preview, services.ingestion.commit(
        token, name, data, source, confirmed_sha256=preview.file_sha256
    )


# --- normalisation ----------------------------------------------------------------------


def test_normalize_maps_aliases_and_vocabulary():
    e = normalize(GOOD, SourceType.AUTH)
    assert e.event_type == "auth.logon_failure"
    assert e.category == "authentication"
    assert e.username == "alice" and e.host == "ws-1"
    assert e.severity == Severity.LOW
    assert e.timestamp == "2026-10-20T10:00:00.000Z"
    assert e.id.startswith("EVT-") and len(e.id) == 20


def test_normalize_is_deterministic_and_key_order_independent():
    reordered = dict(reversed(list(GOOD.items())))
    assert normalize(GOOD, SourceType.AUTH).id == normalize(reordered, SourceType.AUTH).id


@pytest.mark.parametrize(
    "ts,expected",
    [
        (1792836000, "2026-10-24T"),
        (1792836000000, "2026-10-24T"),
        ("2026-10-20T12:00:00+02:00", "2026-10-20T10:00:00"),
        ("2026-10-20 10:00:00", "2026-10-20T10"),
    ],
)
def test_timestamp_normalisation(ts, expected):
    assert normalize({**GOOD, "timestamp": ts}, SourceType.AUTH).timestamp.startswith(expected)


@pytest.mark.parametrize(
    "patch,msg",
    [
        ({"timestamp": None}, "timestamp"),
        ({"timestamp": "yesterday"}, "timestamp"),
        ({"timestamp": 12}, "timestamp"),
        ({"timestamp": True}, "timestamp"),
        ({"event_type": None}, "event_type"),
        ({"src_ip": "999.1.1.1"}, "src_ip"),
        ({"src_ip": "127.0.0.1; rm -rf /"}, "src_ip"),
        ({"severity": "apocalyptic"}, "severity"),
    ],
)
def test_invalid_records_rejected(patch, msg):
    with pytest.raises(RecordError, match=msg):
        normalize({**GOOD, **patch}, SourceType.AUTH)


def test_control_and_bidi_characters_stripped_and_lengths_bounded():
    e = normalize({**GOOD, "message": "ok\x1b[31m\u202eevil\x00" + "A" * 5000}, SourceType.AUTH)
    assert "\x1b" not in e.message and "\u202e" not in e.message and "\x00" not in e.message
    assert len(e.message) <= 2048


def test_event_type_sanitised():
    e = normalize({**GOOD, "event_type": "Drop Table; <script>"}, SourceType.AUTH)
    assert e.event_type == "drop_table__<script>".replace("<", "_").replace(">", "_")


# --- parser hostile inputs --------------------------------------------------------------


@pytest.mark.parametrize("name", ["evil.exe", "events.json.exe", "x.yaml", "noext", "a.zip"])
def test_disallowed_extensions(name):
    with pytest.raises(ParseError):
        detect_format(name)


@pytest.mark.parametrize(
    "name,label",
    [
        ("../../etc/passwd.json", "passwd.json"),
        ("..\\..\\Windows\\win.ini.csv", "win.ini.csv"),
        ("C:\\x\\a<b>|c.jsonl", "a_b__c.jsonl"),
        ("", "upload"),
    ],
)
def test_filename_sanitised_never_a_path(name, label):
    assert sanitize_label(name) == label


@pytest.mark.parametrize(
    "name,data,expected",
    [
        ("a.json", b"", "empty"),
        ("a.json", b"\xff\xfe\x00bad", "binary"),
        ("a.json", b"\xc3\x28 invalid utf8", "UTF-8"),
        ("a.json", b"{not json", "valid JSON"),
        ("a.json", b'{"foo": 1}', "array"),
        ("a.json", b"[NaN]", "valid JSON"),
        ("a.csv", b"", "empty"),
        ("a.csv", b"timestamp,timestamp\n1,2", "duplicate"),
        ("a.csv", b"timestamp,,x\n1,2,3", "empty column"),
    ],
)
def test_malformed_files_rejected_with_safe_messages(services, analyst_token, name, data, expected):
    with pytest.raises(ValidationFailedError) as exc:
        services.ingestion.preview(analyst_token, name, data, SourceType.AUTH)
    assert expected.lower() in exc.value.public_message.lower()
    assert "Traceback" not in exc.value.public_message


def test_oversized_file_rejected_before_parsing(services, analyst_token):
    services.settings.max_upload_mb = 1
    data = b"[" + b" " * (1024 * 1024 + 10) + b"]"
    with pytest.raises(ValidationFailedError, match="limit"):
        services.ingestion.preview(analyst_token, "big.json", data, SourceType.AUTH)


def test_record_count_limit(services, analyst_token):
    services.settings.max_records = 5
    with pytest.raises(ValidationFailedError, match="more than 5"):
        services.ingestion.preview(analyst_token, "a.jsonl", jsonl(*[GOOD] * 6), SourceType.AUTH)


def test_deeply_nested_record_rejected(services, analyst_token):
    nested: dict = {"x": 1}
    for _ in range(50):
        nested = {"n": nested}
    p = services.ingestion.preview(
        analyst_token, "a.jsonl", jsonl({**GOOD, "extra": nested}), SourceType.AUTH
    )
    assert p.error_count == 1 and "nested" in p.errors[0][1]


def test_extremely_deep_json_does_not_crash(services, analyst_token):
    data = b"[" * 100_000 + b"]" * 100_000
    with pytest.raises(ValidationFailedError):
        services.ingestion.preview(analyst_token, "a.json", data, SourceType.AUTH)


def test_mixed_valid_and_invalid_jsonl(services, analyst_token):
    data = jsonl(GOOD, {**GOOD, "timestamp": "bad"}) + b"\n{broken\n[1,2]\n"
    p = services.ingestion.preview(analyst_token, "a.jsonl", data, SourceType.AUTH)
    assert len(p.valid_events) == 1 and p.error_count == 3
    assert [row for row, _ in p.errors] == [2, 3, 4]


def test_csv_ragged_rows_and_formula_payloads(services, analyst_token):
    data = (
        b"timestamp,event_type,user,message\n"
        b'2026-10-20T10:00:00Z,4625,bob,=HYPERLINK("http://x")\n'
        b"2026-10-20T10:00:01Z,4625\n"
    )
    p = services.ingestion.preview(analyst_token, "a.csv", data, SourceType.AUTH)
    assert len(p.valid_events) == 1 and p.error_count == 1
    # Stored verbatim as data; CSV-export escaping is the UI's job.
    assert p.valid_events[0].message.startswith("=HYPERLINK")


# --- import flow ------------------------------------------------------------------------


def test_preview_does_not_write(services, analyst_token):
    services.ingestion.preview(analyst_token, "a.jsonl", jsonl(GOOD), SourceType.AUTH)
    assert services.ingestion.search(analyst_token, EventFilter()) == []


def test_import_and_trace_provenance(services, analyst_token):
    _, result = _import(services, analyst_token, "a.jsonl", jsonl(GOOD))
    assert result.inserted == 1
    [event] = services.ingestion.search(analyst_token, EventFilter())
    assert event["import_id"] == result.import_id
    assert json.loads(event["raw_json"])["user"] == "Alice"  # original evidence preserved
    [imp] = services.ingestion.list_imports(analyst_token)
    assert imp["imported_by_name"] == "analyst1" and imp["file_label"] == "a.jsonl"
    with services.db.connect() as conn:
        assert audit_repo.list_events(conn, action="events.import")[0]["outcome"] == "success"


def test_duplicate_records_within_file_and_across_imports(services, analyst_token):
    _, r1 = _import(services, analyst_token, "a.jsonl", jsonl(GOOD, GOOD))
    assert r1.inserted == 1 and r1.duplicates == 1
    other = {**GOOD, "timestamp": "2026-10-20T11:00:00Z"}
    p2, r2 = _import(services, analyst_token, "b.jsonl", jsonl(GOOD, other))
    assert p2.already_stored == 1 and r2.inserted == 1 and r2.duplicates == 1


def test_same_file_cannot_be_imported_twice(services, analyst_token):
    _import(services, analyst_token, "a.jsonl", jsonl(GOOD))
    with pytest.raises(ValidationFailedError, match="already been imported"):
        _import(services, analyst_token, "renamed.jsonl", jsonl(GOOD))


def test_commit_requires_matching_confirmation(services, analyst_token):
    p = services.ingestion.preview(analyst_token, "a.jsonl", jsonl(GOOD), SourceType.AUTH)
    with pytest.raises(ConflictError):
        services.ingestion.commit(
            analyst_token,
            "a.jsonl",
            jsonl(GOOD, GOOD),
            SourceType.AUTH,
            confirmed_sha256=p.file_sha256,
        )


def test_viewer_cannot_import(services, viewer_token):
    with pytest.raises(AuthorizationError):
        services.ingestion.preview(viewer_token, "a.jsonl", jsonl(GOOD), SourceType.AUTH)
    with pytest.raises(AuthorizationError):
        services.ingestion.commit(
            viewer_token, "a.jsonl", jsonl(GOOD), SourceType.AUTH, confirmed_sha256="x"
        )


def test_search_is_injection_safe(services, analyst_token):
    _import(services, analyst_token, "a.jsonl", jsonl(GOOD))
    hostile = EventFilter(text="%' OR 1=1 --", sort="timestamp; DROP TABLE events")
    assert services.ingestion.search(analyst_token, hostile) == []
    assert len(services.ingestion.search(analyst_token, EventFilter(text="logon"))) == 0
    assert len(services.ingestion.search(analyst_token, EventFilter(usernames=["alice"]))) == 1


def test_bundled_samples_import_cleanly(services, analyst_token):
    for name, src in [
        ("auth_events.jsonl", SourceType.AUTH),
        ("endpoint_events.json", SourceType.ENDPOINT),
        ("alerts.csv", SourceType.ALERT),
    ]:
        p, r = _import(services, analyst_token, name, (SAMPLES / name).read_bytes(), src)
        assert p.error_count == 0, p.errors
        assert r.inserted > 0
