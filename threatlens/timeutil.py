"""UTC time helpers and defensive timestamp parsing."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

# Accept epochs only within a plausible window to reject garbage numeric fields.
_MIN_EPOCH = datetime(2000, 1, 1, tzinfo=UTC).timestamp()
_MAX_EPOCH = datetime(2100, 1, 1, tzinfo=UTC).timestamp()


def utcnow() -> datetime:
    return datetime.now(UTC)


def to_iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        raise ValueError("naive datetimes are not allowed")
    return dt.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def utcnow_iso() -> str:
    return to_iso(utcnow())


def from_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def iso_after(minutes: float = 0, *, hours: float = 0) -> str:
    return to_iso(utcnow() + timedelta(minutes=minutes, hours=hours))


def parse_timestamp(value: object) -> datetime:
    """Normalise ISO-8601 strings or epoch seconds/milliseconds to aware UTC.

    Naive ISO strings are interpreted as UTC (documented ingestion assumption).
    """
    if isinstance(value, bool):
        raise ValueError("boolean is not a timestamp")
    if isinstance(value, int | float):
        seconds = float(value)
        if seconds > _MAX_EPOCH:  # probably milliseconds
            seconds /= 1000.0
        if not _MIN_EPOCH <= seconds <= _MAX_EPOCH:
            raise ValueError("epoch timestamp out of supported range")
        return datetime.fromtimestamp(seconds, UTC)
    if isinstance(value, str):
        text = value.strip()
        if not text or len(text) > 64:
            raise ValueError("timestamp string empty or too long")
        if text.replace(".", "", 1).isdigit():
            return parse_timestamp(float(text))
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        dt = dt.astimezone(UTC)
        if not _MIN_EPOCH <= dt.timestamp() <= _MAX_EPOCH:
            raise ValueError("timestamp out of supported range")
        return dt
    raise ValueError("unsupported timestamp type")
