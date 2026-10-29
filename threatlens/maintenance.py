"""Database backup, verification, restore and local administrator recovery.

These operations are for a terminal on the host only (see ``scripts/``); the web UI never
exposes them. Backups use SQLite's online backup API, which produces a consistent snapshot even
while the application is running (including WAL content).

A SHA-256 fingerprint is recorded for every backup. It lets you detect later changes to the
backup file; it cannot by itself prove that the data was authentic when the backup was taken.
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from threatlens.repositories import audit_repo, user_repo
from threatlens.security.passwords import hash_password, validate_password_policy
from threatlens.timeutil import utcnow

SQLITE_MAGIC = b"SQLite format 3\x00"
_LABEL_RE = re.compile(r"[^a-z0-9-]+")


class BackupError(RuntimeError):
    """A safe, user-presentable backup/restore failure."""


@dataclass(frozen=True)
class BackupInfo:
    path: Path
    sha256: str
    size_bytes: int
    schema_versions: tuple[int, ...]


def backups_dir_for(db_path: Path) -> Path:
    return db_path.parent / "backups"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_backup(path: Path) -> BackupInfo:
    """Check the file is an intact SQLite database with this application's schema."""
    if not path.is_file():
        raise BackupError("Backup file not found.")
    with path.open("rb") as fh:
        if fh.read(16) != SQLITE_MAGIC:
            raise BackupError("File is not a SQLite database.")
    try:
        conn = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
        try:
            if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise BackupError("Backup failed the SQLite integrity check.")
            versions = tuple(
                r[0] for r in conn.execute("SELECT version FROM schema_migrations ORDER BY version")
            )
        finally:
            conn.close()
    except sqlite3.DatabaseError as exc:
        raise BackupError("Backup is not a valid application database.") from exc
    if not versions:
        raise BackupError("Backup has no schema history.")
    return BackupInfo(path, _sha256(path), path.stat().st_size, versions)


def backup_database(
    db_path: Path, dest_dir: Path | None = None, *, label: str = "manual"
) -> BackupInfo:
    if not db_path.is_file():
        raise BackupError("Database file not found; nothing to back up.")
    dest_dir = dest_dir or backups_dir_for(db_path)
    dest_dir.mkdir(parents=True, exist_ok=True)
    safe_label = _LABEL_RE.sub("-", label.lower()).strip("-")[:40] or "manual"
    stamp = utcnow().strftime("%Y%m%dT%H%M%S%fZ")
    target = dest_dir / f"{db_path.stem}-{stamp}-{safe_label}.db"
    if target.exists():  # never overwrite an existing backup
        raise BackupError("A backup with this name already exists.")
    src = sqlite3.connect(db_path)
    dst = sqlite3.connect(target)
    try:
        src.backup(dst)
    finally:
        dst.close()
        src.close()
    info = verify_backup(target)
    target.with_suffix(".db.sha256").write_text(f"{info.sha256}  {target.name}\n", "utf-8")
    return info


def list_backups(db_path: Path) -> list[Path]:
    d = backups_dir_for(db_path)
    return sorted(d.glob("*.db"), reverse=True) if d.is_dir() else []


def restore_database(backup_path: Path, db_path: Path) -> tuple[BackupInfo, BackupInfo | None]:
    """Replace the live database with a verified backup.

    The current database (if any) is first saved as a ``pre-restore`` backup, so a restore can
    itself be undone. Returns (restored backup info, safety backup info or None).
    """
    info = verify_backup(backup_path)
    recorded = backup_path.with_suffix(".db.sha256")
    if recorded.is_file() and recorded.read_text("utf-8").split()[0] != info.sha256:
        raise BackupError("Backup fingerprint does not match its .sha256 record.")
    safety = backup_database(db_path, label="pre-restore") if db_path.is_file() else None
    db_path.parent.mkdir(parents=True, exist_ok=True)
    src = sqlite3.connect(f"file:{backup_path.as_posix()}?mode=ro", uri=True)
    dst = sqlite3.connect(db_path)
    try:
        src.backup(dst)
    finally:
        dst.close()
        src.close()
    return info, safety


def recover_admin(db_path: Path, username: str, new_password: str) -> None:
    """Local break-glass recovery: reset an administrator's password and re-enable the account.

    Only works for accounts that already have the admin role. All existing sessions for the
    account are revoked and the recovery is written to the audit trail.
    """
    validate_password_policy(new_password, username=username)
    conn = sqlite3.connect(db_path, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = user_repo.get_auth_row(conn, username)
        if row is None or row["role"] != "admin":
            conn.execute("ROLLBACK")
            raise BackupError("No administrator account with that username.")
        user_repo.update_password_hash(conn, row["id"], hash_password(new_password))
        user_repo.set_active(conn, row["id"], True)
        conn.execute(
            "UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?", (row["id"],)
        )
        conn.execute("DELETE FROM login_attempts WHERE username = ? COLLATE NOCASE", (username,))
        user_repo.revoke_user_sessions(conn, row["id"])
        audit_repo.append(
            conn,
            action="admin.recovery_cli",
            outcome="success",
            actor_username="local-terminal",
            target_type="user",
            target_id=row["id"],
            details={"username": row["username"]},
        )
        conn.execute("COMMIT")
    except BackupError:
        raise
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()
