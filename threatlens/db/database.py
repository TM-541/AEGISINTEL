"""SQLite connection management and migrations.

Each unit of work opens its own short-lived connection. This is safe with Streamlit's
threaded script runs. ``transaction()`` uses ``BEGIN IMMEDIATE`` so writers serialize.
"""

from __future__ import annotations

import hashlib
import logging
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

from threatlens.errors import DatabaseUnavailableError
from threatlens.timeutil import utcnow_iso

log = logging.getLogger(__name__)

MIGRATIONS_PACKAGE = "threatlens.db.migrations"


class MigrationIntegrityError(RuntimeError):
    """An applied migration file was modified after it ran."""


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    sql: str

    @property
    def checksum(self) -> str:
        return hashlib.sha256(self.sql.encode("utf-8")).hexdigest()


def load_migrations() -> list[Migration]:
    migrations = []
    for entry in resources.files(MIGRATIONS_PACKAGE).iterdir():
        if entry.name.endswith(".sql"):
            version_str, _, rest = entry.name.partition("_")
            migrations.append(
                Migration(int(version_str), rest.removesuffix(".sql"), entry.read_text("utf-8"))
            )
    return sorted(migrations, key=lambda m: m.version)


class Database:
    def __init__(self, path: Path, *, busy_timeout_ms: int = 5000) -> None:
        self.path = path
        self.busy_timeout_ms = busy_timeout_ms

    def _open(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path, isolation_level=None, timeout=self.busy_timeout_ms / 1000)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute(f"PRAGMA busy_timeout = {int(self.busy_timeout_ms)}")
        conn.execute("PRAGMA journal_mode = WAL")
        return conn

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        try:
            conn = self._open()
        except sqlite3.Error as exc:
            log.error("database open failed", extra={"error": type(exc).__name__})
            raise DatabaseUnavailableError(detail=str(exc)) from exc
        try:
            yield conn
        except sqlite3.OperationalError as exc:
            # Locks, disk I/O, corrupt pages: surface a safe, generic error.
            log.error("database operation failed", extra={"error": str(exc)})
            raise DatabaseUnavailableError(detail=str(exc)) from exc
        except sqlite3.DatabaseError as exc:
            if isinstance(exc, sqlite3.IntegrityError):
                raise
            log.error("database error", extra={"error": str(exc)})
            raise DatabaseUnavailableError(detail=str(exc)) from exc
        finally:
            conn.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            else:
                conn.execute("COMMIT")

    def migrate(self) -> list[int]:
        """Apply pending migrations; verify checksums of applied ones. Returns new versions."""
        applied_now: list[int] = []
        with self.connect() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations ("
                " version INTEGER PRIMARY KEY, name TEXT NOT NULL,"
                " checksum TEXT NOT NULL, applied_at TEXT NOT NULL)"
            )
            applied = {
                row["version"]: row["checksum"]
                for row in conn.execute("SELECT version, checksum FROM schema_migrations")
            }
            pending = []
            for migration in load_migrations():
                if migration.version in applied:
                    if applied[migration.version] != migration.checksum:
                        raise MigrationIntegrityError(
                            f"migration {migration.version} changed after being applied"
                        )
                    continue
                pending.append(migration)
            if pending and applied:
                # Existing database about to change shape: take a verified backup first.
                from threatlens.maintenance import backup_database

                info = backup_database(self.path, label=f"pre-migration-{pending[0].version}")
                log.info("pre-migration backup", extra={"backup": info.path.name})
            for migration in pending:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    # executescript would COMMIT implicitly; run statements individually.
                    for statement in _split_sql(migration.sql):
                        conn.execute(statement)
                    conn.execute(
                        "INSERT INTO schema_migrations (version, name, checksum, applied_at)"
                        " VALUES (?, ?, ?, ?)",
                        (migration.version, migration.name, migration.checksum, utcnow_iso()),
                    )
                    conn.execute("COMMIT")
                except BaseException:
                    conn.execute("ROLLBACK")
                    raise
                applied_now.append(migration.version)
                log.info("migration applied", extra={"version": migration.version})
        return applied_now

    def integrity_check(self) -> str:
        with self.connect() as conn:
            return str(conn.execute("PRAGMA quick_check").fetchone()[0])


def _split_sql(script: str) -> list[str]:
    """Split a migration script into complete statements (trigger-aware)."""
    statements: list[str] = []
    buffer = ""
    for line in script.splitlines(keepends=True):
        if line.strip().startswith("--") and not buffer.strip():
            continue
        buffer += line
        if sqlite3.complete_statement(buffer):
            if buffer.strip():
                statements.append(buffer.strip())
            buffer = ""
    if buffer.strip():
        raise ValueError("migration ends with an incomplete statement")
    return statements
