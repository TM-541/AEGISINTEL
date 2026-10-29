"""Two-step ingestion: ``preview`` (no writes) then ``commit`` (explicit confirmation).

``commit`` re-parses and re-validates the bytes. It only proceeds if their SHA-256 matches
the hash the analyst confirmed, so the data written is exactly the data that was previewed.
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field

from threatlens.config import Settings
from threatlens.db.database import Database
from threatlens.errors import ConflictError, NotFoundError, ValidationFailedError
from threatlens.ingest.adapters import FileUploadAdapter
from threatlens.ingest.normalize import NormalizedEvent, RecordError, SourceType, normalize
from threatlens.ingest.parsers import ParseError, sanitize_label
from threatlens.repositories import audit_repo, event_repo
from threatlens.security.rbac import Permission
from threatlens.services.auth_service import AuthService

log = logging.getLogger(__name__)
MAX_REPORTED_ERRORS = 50


@dataclass
class ImportPreview:
    file_label: str
    file_format: str
    source_type: SourceType
    file_sha256: str
    total_records: int
    valid_events: list[NormalizedEvent]
    errors: list[tuple[int, str]] = field(default_factory=list)
    error_count: int = 0
    duplicates_in_file: int = 0
    already_stored: int = 0
    file_already_imported: bool = False

    @property
    def new_events(self) -> int:
        return len(self.valid_events) - self.already_stored


@dataclass(frozen=True)
class ImportResult:
    import_id: int
    inserted: int
    duplicates: int
    rejected: int
    duration_ms: int


class IngestionService:
    def __init__(self, db: Database, auth: AuthService, settings: Settings) -> None:
        self.db = db
        self.auth = auth
        self.settings = settings

    def _build_preview(self, filename: str, data: bytes, source_type: SourceType) -> ImportPreview:
        source_type = SourceType(source_type)
        deadline = time.monotonic() + self.settings.max_import_seconds
        try:
            adapter = FileUploadAdapter(
                filename,
                data,
                source_type,
                max_bytes=self.settings.max_upload_bytes,
                max_records=self.settings.max_records,
            )
        except ParseError as exc:
            raise ValidationFailedError(str(exc)) from exc

        parsed = adapter.parsed
        errors = list(parsed.errors)
        seen: set[str] = set()
        events: list[NormalizedEvent] = []
        dupes_in_file = 0
        for n, (row_no, record) in enumerate(adapter.records()):
            if n % 256 == 0 and time.monotonic() > deadline:
                raise ValidationFailedError(
                    f"Import processing exceeded {self.settings.max_import_seconds} seconds. "
                    "Split the file into smaller parts."
                )
            try:
                event = normalize(record, source_type)
            except RecordError as exc:
                errors.append((row_no, str(exc)))
                continue
            if event.content_hash in seen:
                dupes_in_file += 1
                continue
            seen.add(event.content_hash)
            events.append(event)

        file_sha = hashlib.sha256(data).hexdigest()
        with self.db.connect() as conn:
            stored = event_repo.existing_hashes(conn, [e.content_hash for e in events])
            imported = event_repo.file_already_imported(conn, file_sha)
        errors.sort()
        return ImportPreview(
            file_label=sanitize_label(filename),
            file_format=parsed.file_format,
            source_type=source_type,
            file_sha256=file_sha,
            total_records=len(parsed.records) + len(parsed.errors),
            valid_events=events,
            errors=errors[:MAX_REPORTED_ERRORS],
            error_count=len(errors),
            duplicates_in_file=dupes_in_file,
            already_stored=len(stored),
            file_already_imported=imported,
        )

    def preview(
        self, token: str, filename: str, data: bytes, source_type: SourceType
    ) -> ImportPreview:
        self.auth.authorize(token, Permission.IMPORT_EVENTS)
        return self._build_preview(filename, data, source_type)

    def commit(
        self,
        token: str,
        filename: str,
        data: bytes,
        source_type: SourceType,
        *,
        confirmed_sha256: str,
    ) -> ImportResult:
        actor = self.auth.authorize(token, Permission.IMPORT_EVENTS)
        started = time.perf_counter()
        preview = self._build_preview(filename, data, source_type)
        if preview.file_sha256 != confirmed_sha256:
            raise ConflictError("The file changed after preview. Preview it again.")
        if preview.file_already_imported:
            raise ValidationFailedError("This exact file has already been imported.")
        if not preview.valid_events:
            raise ValidationFailedError("No valid records to import.")
        with self.db.transaction() as conn:
            import_id = event_repo.create_import(
                conn,
                file_label=preview.file_label,
                file_format=preview.file_format,
                source_type=preview.source_type.value,
                file_sha256=preview.file_sha256,
                record_count=preview.total_records,
                rejected_count=preview.error_count,
                imported_by=actor.user_id,
            )
            inserted = event_repo.insert_events(conn, import_id, preview.valid_events)
            dupes = preview.duplicates_in_file + (len(preview.valid_events) - inserted)
            event_repo.finalize_import(conn, import_id, inserted, dupes)
            audit_repo.append(
                conn,
                action="events.import",
                outcome="success",
                actor_id=actor.user_id,
                actor_username=actor.username,
                target_type="import",
                target_id=import_id,
                details={
                    "file": preview.file_label,
                    "inserted": inserted,
                    "duplicates": dupes,
                    "rejected": preview.error_count,
                },
            )
        duration_ms = int((time.perf_counter() - started) * 1000)
        log.info(
            "import committed",
            extra={"import_id": import_id, "inserted": inserted, "duration_ms": duration_ms},
        )
        return ImportResult(import_id, inserted, dupes, preview.error_count, duration_ms)

    def search(self, token: str, flt: event_repo.EventFilter) -> list[dict]:
        self.auth.authorize(token, Permission.VIEW_EVENTS)
        with self.db.connect() as conn:
            return [dict(r) for r in event_repo.search_events(conn, flt)]

    def facets(self, token: str) -> dict[str, list[str]]:
        self.auth.authorize(token, Permission.VIEW_EVENTS)
        with self.db.connect() as conn:
            return {
                c: event_repo.distinct_values(conn, c)
                for c in ("username", "host", "event_type", "severity")
            }

    def list_imports(self, token: str) -> list[dict]:
        self.auth.authorize(token, Permission.VIEW_EVENTS)
        with self.db.connect() as conn:
            return [dict(r) for r in event_repo.list_imports(conn)]

    def count(self, token: str, flt: event_repo.EventFilter) -> int:
        self.auth.authorize(token, Permission.VIEW_EVENTS)
        with self.db.connect() as conn:
            return event_repo.count_events(conn, flt)

    # --- data retention ----------------------------------------------------------------------

    def purge_impact(self, token: str, import_id: int) -> dict:
        """What deleting an import would remove (shown to the admin before confirming)."""
        self.auth.authorize(token, Permission.MANAGE_SYSTEM)
        with self.db.connect() as conn:
            imp = conn.execute("SELECT * FROM imports WHERE id = ?", (import_id,)).fetchone()
            if imp is None:
                raise NotFoundError()
            return {"import": dict(imp), **event_repo.purge_scope(conn, import_id)}

    def purge_import(self, token: str, import_id: int, *, confirm_label: str) -> dict:
        """Permanently delete an import's events and every incident built on them.

        Requires the admin to type the file label. The audit trail keeps counts only, never
        the deleted content. The similarity index should be rebuilt afterwards (stale vectors
        are never shown, because results are re-checked against the database).
        """
        actor = self.auth.authorize(token, Permission.MANAGE_SYSTEM)
        with self.db.transaction() as conn:
            imp = conn.execute("SELECT * FROM imports WHERE id = ?", (import_id,)).fetchone()
            if imp is None:
                raise NotFoundError()
            if confirm_label.strip() != imp["file_label"]:
                raise ValidationFailedError("Type the exact file name to confirm deletion.")
            removed = event_repo.purge_import(conn, import_id)
            audit_repo.append(
                conn,
                action="data.purge_import",
                outcome="success",
                actor_id=actor.user_id,
                actor_username=actor.username,
                target_type="import",
                target_id=import_id,
                details=removed,
            )
        log.info("import purged", extra={"import_id": import_id, **removed})
        return removed
