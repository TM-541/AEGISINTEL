"""Ingestion adapter interface.

File uploads are the only adapter implemented. A future SIEM/EDR integration would implement
``IngestionAdapter`` and yield raw dict records. Those records go through the same
``normalize`` → dedup → insert pipeline, so validation is never bypassed.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any, Protocol

from threatlens.ingest.normalize import SourceType
from threatlens.ingest.parsers import ParsedFile, parse


class IngestionAdapter(Protocol):
    name: str
    source_type: SourceType

    def records(self) -> Iterator[tuple[int, dict[str, Any]]]: ...


class FileUploadAdapter:
    name = "file_upload"

    def __init__(
        self,
        filename: str,
        data: bytes,
        source_type: SourceType,
        *,
        max_bytes: int,
        max_records: int,
    ) -> None:
        self.source_type = source_type
        self.parsed: ParsedFile = parse(
            filename, data, max_bytes=max_bytes, max_records=max_records
        )

    def records(self) -> Iterator[tuple[int, dict[str, Any]]]:
        yield from self.parsed.records
