"""Normalisation of untrusted records into the canonical event model.

Field aliases (e.g. ``@timestamp``/``time``, ``user``/``username``) are mapped to one schema;
values are length-limited, control characters stripped, IPs validated, severities and event
types mapped onto fixed vocabularies. The original record is preserved as canonical JSON.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict

from threatlens.models.domain import Severity
from threatlens.timeutil import parse_timestamp, to_iso


class SourceType(StrEnum):
    AUTH = "auth"
    ENDPOINT = "endpoint"
    ALERT = "alert"


class NormalizedEvent(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    content_hash: str
    source_type: SourceType
    timestamp: str
    event_type: str
    category: str
    severity: Severity
    outcome: str | None = None
    username: str | None = None
    host: str | None = None
    src_ip: str | None = None
    dest_ip: str | None = None
    process_name: str | None = None
    command_line: str | None = None
    parent_process: str | None = None
    message: str | None = None
    raw_json: str
    original_timestamp: str | None = None
    normalization_notes: tuple[str, ...] = ()


class RecordError(ValueError):
    """A per-record validation problem; message is safe for display."""


ALIASES: dict[str, tuple[str, ...]] = {
    "timestamp": ("timestamp", "@timestamp", "time", "event_time", "ts", "TimeCreated"),
    "event_type": ("event_type", "type", "action", "event_action", "EventID", "event_id"),
    "severity": ("severity", "level", "priority"),
    "outcome": ("outcome", "result", "status"),
    "username": ("username", "user", "user_name", "account", "TargetUserName"),
    "host": ("host", "hostname", "computer", "device", "Computer"),
    "src_ip": ("src_ip", "source_ip", "client_ip", "IpAddress", "src"),
    "dest_ip": ("dest_ip", "destination_ip", "dst_ip", "dst"),
    "process_name": ("process_name", "process", "image", "Image", "NewProcessName"),
    "command_line": ("command_line", "cmdline", "CommandLine"),
    "parent_process": ("parent_process", "parent_image", "ParentImage", "ParentProcessName"),
    "message": ("message", "description", "msg", "title", "alert_name"),
}

FIELD_LIMITS = {
    "event_type": 64,
    "outcome": 32,
    "username": 128,
    "host": 255,
    "process_name": 260,
    "command_line": 4096,
    "parent_process": 260,
    "message": 2048,
}

# Windows Security / Sysmon event IDs commonly found in exports.
WINDOWS_EVENT_IDS = {
    "4624": "auth.logon_success",
    "4625": "auth.logon_failure",
    "4634": "auth.logoff",
    "4648": "auth.explicit_credentials",
    "4672": "auth.special_privileges",
    "4688": "process.create",
    "4697": "service.installed",
    "4698": "task.created",
    "4720": "account.created",
    "4732": "group.member_added",
    "1102": "log.cleared",
    "1": "process.create",
    "3": "network.connection",
    "10": "process.access",
}
EVENT_TYPE_ALIASES = {
    "login_failed": "auth.logon_failure",
    "logon_failure": "auth.logon_failure",
    "failed_login": "auth.logon_failure",
    "login_success": "auth.logon_success",
    "logon_success": "auth.logon_success",
    "login": "auth.logon_success",
    "process_start": "process.create",
    "process_creation": "process.create",
}
CATEGORY_PREFIXES = {
    "auth": "authentication",
    "process": "process",
    "account": "iam",
    "group": "iam",
    "network": "network",
    "file": "file",
    "service": "persistence",
    "task": "persistence",
    "registry": "registry",
    "log": "defense_evasion",
    "alert": "alert",
}
SEVERITY_ALIASES = {
    "info": Severity.INFORMATIONAL,
    "informational": Severity.INFORMATIONAL,
    "debug": Severity.INFORMATIONAL,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "warning": Severity.MEDIUM,
    "warn": Severity.MEDIUM,
    "high": Severity.HIGH,
    "error": Severity.HIGH,
    "critical": Severity.CRITICAL,
    "crit": Severity.CRITICAL,
    "0": Severity.INFORMATIONAL,
    "1": Severity.LOW,
    "2": Severity.MEDIUM,
    "3": Severity.HIGH,
    "4": Severity.CRITICAL,
}
# Control characters plus zero-width and bidirectional overrides (Trojan Source, CVE-2021-42574).
# Built from code points so this source file stays pure ASCII.
_INVISIBLE_RANGES = (
    (0x00, 0x08),
    (0x0B, 0x1F),
    (0x7F, 0x7F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2066, 0x2069),
)
_CONTROL = re.compile(
    "[" + "".join(f"{re.escape(chr(a))}-{re.escape(chr(b))}" for a, b in _INVISIBLE_RANGES) + "]"
)
_EVENT_TYPE_SAFE = re.compile(r"[^a-z0-9_.\-]")


def _first(record: dict[str, Any], key: str) -> Any:
    lowered = {str(k).lower(): v for k, v in record.items()}
    for alias in ALIASES[key]:
        if alias in record and record[alias] not in (None, ""):
            return record[alias]
        if alias.lower() in lowered and lowered[alias.lower()] not in (None, ""):
            return lowered[alias.lower()]
    return None


def clean_text(value: Any, limit: int) -> str | None:
    """Stringify, strip control/bidi characters, trim and bound length."""
    if value is None:
        return None
    if isinstance(value, dict | list):
        value = json.dumps(value, sort_keys=True)
    text = _CONTROL.sub("", str(value)).strip()
    if not text:
        return None
    return text[:limit]


def _ip(value: Any, field: str) -> str | None:
    text = clean_text(value, 64)
    if text is None:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError as exc:
        raise RecordError(f"Field '{field}' is not a valid IP address.") from exc


def normalize_event_type(value: Any) -> str:
    text = clean_text(value, 64)
    if text is None:
        raise RecordError("Missing required field 'event_type'.")
    if text in WINDOWS_EVENT_IDS:
        return WINDOWS_EVENT_IDS[text]
    lowered = _EVENT_TYPE_SAFE.sub("_", text.lower())
    return EVENT_TYPE_ALIASES.get(lowered, lowered)


def category_for(event_type: str, source_type: SourceType) -> str:
    if source_type == SourceType.ALERT:
        return "alert"
    return CATEGORY_PREFIXES.get(event_type.split(".", 1)[0], "other")


def normalize_severity(value: Any, default: Severity = Severity.INFORMATIONAL) -> Severity:
    text = clean_text(value, 32)
    if text is None:
        return default
    try:
        return SEVERITY_ALIASES[text.lower()]
    except KeyError as exc:
        raise RecordError("Field 'severity' has an unrecognised value.") from exc


def canonical_json(record: dict[str, Any]) -> str:
    return json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    )


def timestamp_notes(value: Any) -> list[str]:
    """Explain how a raw timestamp was interpreted (recorded as provenance)."""
    if isinstance(value, int | float) and not isinstance(value, bool):
        return [
            "timestamp given as epoch milliseconds; converted to UTC"
            if float(value) > 4_102_444_800
            else "timestamp given as epoch seconds; converted to UTC"
        ]
    text = str(value).strip()
    if text.replace(".", "", 1).isdigit():
        return ["timestamp given as a numeric epoch string; converted to UTC"]
    has_zone = text.endswith(("Z", "z")) or re.search(r"[+-]\d{2}:?\d{2}$", text[10:])
    if not has_zone:
        return ["timestamp had no time zone; interpreted as UTC"]
    if not text.endswith(("Z", "z", "+00:00", "+0000")):
        return ["timestamp had a non-UTC offset; converted to UTC"]
    return []


def _clip(field: str, value: Any, notes: list[str]) -> str | None:
    limit = FIELD_LIMITS[field]
    full = clean_text(value, 1_000_000)
    if full is not None and len(full) > limit:
        notes.append(f"{field} truncated from {len(full)} to {limit} characters")
        return full[:limit]
    return full


def normalize(
    record: dict[str, Any], source_type: SourceType, *, max_raw_chars: int = 65_536
) -> NormalizedEvent:
    raw = canonical_json(record)
    if len(raw) > max_raw_chars:
        raise RecordError("Record is too large.")
    ts_value = _first(record, "timestamp")
    if ts_value is None:
        raise RecordError("Missing required field 'timestamp'.")
    try:
        timestamp = to_iso(parse_timestamp(ts_value))
    except (ValueError, OverflowError, OSError) as exc:
        raise RecordError("Field 'timestamp' is not a valid ISO-8601 or epoch value.") from exc
    notes = timestamp_notes(ts_value)

    raw_type = clean_text(_first(record, "event_type"), 64)
    event_type = normalize_event_type(raw_type)
    if raw_type is not None and raw_type in WINDOWS_EVENT_IDS:
        notes.append(f"event type mapped from Windows event ID {raw_type}")
    default_sev = Severity.MEDIUM if source_type == SourceType.ALERT else Severity.INFORMATIONAL
    raw_sev = _first(record, "severity")
    severity = normalize_severity(raw_sev, default_sev)
    if clean_text(raw_sev, 32) is None:
        notes.append(f"severity missing; defaulted to {default_sev.value}")
    username = _clip("username", _first(record, "username"), notes)
    host = _clip("host", _first(record, "host"), notes)
    outcome = _clip("outcome", _first(record, "outcome"), notes)
    process_name = _clip("process_name", _first(record, "process_name"), notes)
    command_line = _clip("command_line", _first(record, "command_line"), notes)
    parent_process = _clip("parent_process", _first(record, "parent_process"), notes)
    message = _clip("message", _first(record, "message"), notes)

    content_hash = hashlib.sha256(f"{source_type.value}|{raw}".encode()).hexdigest()
    return NormalizedEvent(
        id=f"EVT-{content_hash[:16]}",
        content_hash=content_hash,
        source_type=source_type,
        timestamp=timestamp,
        event_type=event_type,
        category=category_for(event_type, source_type),
        severity=severity,
        outcome=outcome.lower() if outcome else None,
        username=username.lower() if username else None,
        host=host.lower() if host else None,
        src_ip=_ip(_first(record, "src_ip"), "src_ip"),
        dest_ip=_ip(_first(record, "dest_ip"), "dest_ip"),
        process_name=process_name,
        command_line=command_line,
        parent_process=parent_process,
        message=message,
        raw_json=raw,
        original_timestamp=clean_text(ts_value, 64),
        normalization_notes=tuple(notes),
    )
