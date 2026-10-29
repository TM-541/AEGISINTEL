"""Defensive parsing of uploaded event files (JSON, JSON Lines, CSV).

All input is treated as untrusted data. Files are processed in memory, never written to a
user-chosen path, and never evaluated. Limits are applied *before* expensive work.
"""

from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any

ALLOWED_EXTENSIONS = {".json": "json", ".jsonl": "jsonl", ".ndjson": "jsonl", ".csv": "csv"}
MAX_NESTING_DEPTH = 8
MAX_KEYS_PER_RECORD = 100
MAX_CSV_FIELD_BYTES = 65_536
_LABEL_SAFE = re.compile(r"[^A-Za-z0-9._ -]")


class ParseError(ValueError):
    """A whole-file problem. The message is safe to show to users."""


@dataclass
class ParsedFile:
    file_format: str
    records: list[tuple[int, dict[str, Any]]] = field(default_factory=list)  # (row number, rec)
    errors: list[tuple[int, str]] = field(default_factory=list)


def sanitize_label(filename: str) -> str:
    """Reduce an uploaded filename to a display label. It is never used as a path."""
    base = PureWindowsPath(PurePosixPath(filename or "upload").name).name
    label = _LABEL_SAFE.sub("_", base).strip(" .") or "upload"
    return label[:120]


def detect_format(filename: str) -> str:
    suffix = PurePosixPath(sanitize_label(filename).lower()).suffix
    if suffix not in ALLOWED_EXTENSIONS:
        raise ParseError("Unsupported file type. Use .json, .jsonl/.ndjson or .csv.")
    return ALLOWED_EXTENSIONS[suffix]


def decode(data: bytes, max_bytes: int) -> str:
    if not data:
        raise ParseError("The file is empty.")
    if len(data) > max_bytes:
        raise ParseError(f"The file exceeds the {max_bytes // (1024 * 1024)} MB limit.")
    if b"\x00" in data:
        raise ParseError("The file contains binary data and cannot be imported.")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ParseError("The file is not valid UTF-8 text.") from exc


def _depth(value: Any, level: int = 0) -> int:
    if level > MAX_NESTING_DEPTH:
        return level
    if isinstance(value, dict):
        return max((_depth(v, level + 1) for v in value.values()), default=level + 1)
    if isinstance(value, list):
        return max((_depth(v, level + 1) for v in value), default=level + 1)
    return level


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-standard JSON constant {name}")


def _loads(text: str) -> Any:
    return json.loads(text, parse_constant=_reject_constant)


def _check_record(obj: Any) -> str | None:
    if not isinstance(obj, dict):
        return "Record is not a JSON object."
    if len(obj) > MAX_KEYS_PER_RECORD:
        return "Record has too many fields."
    if _depth(obj) > MAX_NESTING_DEPTH:
        return "Record is nested too deeply."
    return None


def parse(filename: str, data: bytes, *, max_bytes: int, max_records: int) -> ParsedFile:
    fmt = detect_format(filename)
    text = decode(data, max_bytes)
    result = ParsedFile(file_format=fmt)
    if fmt == "json":
        _parse_json(text, result, max_records)
    elif fmt == "jsonl":
        _parse_jsonl(text, result, max_records)
    else:
        _parse_csv(text, result, max_records)
    if not result.records and not result.errors:
        raise ParseError("The file contains no records.")
    return result


def _parse_json(text: str, result: ParsedFile, max_records: int) -> None:
    try:
        doc = _loads(text)
    except (ValueError, RecursionError) as exc:
        raise ParseError("The file is not valid JSON.") from exc
    if isinstance(doc, dict) and isinstance(doc.get("events"), list):
        doc = doc["events"]
    if not isinstance(doc, list):
        raise ParseError('JSON must be an array of event objects or {"events": [...]}.')
    if len(doc) > max_records:
        raise ParseError(f"The file has more than {max_records} records.")
    for i, obj in enumerate(doc, start=1):
        problem = _check_record(obj)
        if problem:
            result.errors.append((i, problem))
        else:
            result.records.append((i, obj))


def _parse_jsonl(text: str, result: ParsedFile, max_records: int) -> None:
    count = 0
    for line_no, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        count += 1
        if count > max_records:
            raise ParseError(f"The file has more than {max_records} records.")
        try:
            obj = _loads(line)
        except (ValueError, RecursionError):
            result.errors.append((line_no, "Line is not valid JSON."))
            continue
        problem = _check_record(obj)
        if problem:
            result.errors.append((line_no, problem))
        else:
            result.records.append((line_no, obj))


def _parse_csv(text: str, result: ParsedFile, max_records: int) -> None:
    csv.field_size_limit(MAX_CSV_FIELD_BYTES)
    reader = csv.reader(io.StringIO(text, newline=""), strict=True)
    try:
        header = next(reader)
    except StopIteration as exc:
        raise ParseError("The CSV file has no header row.") from exc
    except csv.Error as exc:
        raise ParseError("The CSV header could not be parsed.") from exc
    header = [h.strip() for h in header]
    if not header or any(not h for h in header):
        raise ParseError("The CSV header contains empty column names.")
    if len(set(h.lower() for h in header)) != len(header):
        raise ParseError("The CSV header contains duplicate column names.")
    if len(header) > MAX_KEYS_PER_RECORD:
        raise ParseError("The CSV file has too many columns.")
    count = 0
    while True:
        try:
            row = next(reader)
        except StopIteration:
            break
        except csv.Error:
            result.errors.append((reader.line_num, "Row could not be parsed as CSV."))
            continue
        if not any(cell.strip() for cell in row):
            continue
        count += 1
        if count > max_records:
            raise ParseError(f"The file has more than {max_records} records.")
        if len(row) != len(header):
            result.errors.append((reader.line_num, "Row has the wrong number of columns."))
            continue
        result.records.append(
            (
                reader.line_num,
                {h: (v if v != "" else None) for h, v in zip(header, row, strict=True)},
            )
        )
