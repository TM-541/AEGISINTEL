from __future__ import annotations

import sqlite3

import pytest

from tests.conftest import ADMIN_PW
from threatlens.db import database as dbmod
from threatlens.db.database import Database, Migration
from threatlens.errors import AuthenticationError, RateLimitedError, ValidationFailedError
from threatlens.maintenance import (
    BackupError,
    backup_database,
    list_backups,
    recover_admin,
    restore_database,
    verify_backup,
)
from threatlens.repositories import audit_repo

NEW_PW = "Break-Glass-Reset-Pass-88"


def test_backup_is_consistent_verified_and_fingerprinted(services, admin_token):
    info = backup_database(services.settings.db_path)
    assert info.path.parent.name == "backups" and info.schema_versions
    assert info.path.with_suffix(".db.sha256").read_text().startswith(info.sha256)
    conn = sqlite3.connect(info.path)
    assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1
    conn.close()
    assert list_backups(services.settings.db_path)[0] == info.path


def test_backup_label_cannot_traverse_paths(services, admin_token):
    info = backup_database(services.settings.db_path, label="..\\..\\evil/../x")
    assert info.path.parent.name == "backups" and ".." not in info.path.name


def test_restore_round_trip_and_safety_copy(services, admin_token):
    from threatlens.models.domain import Role

    db_path = services.settings.db_path
    snapshot = backup_database(db_path, label="before-change")
    services.users.create_user(
        admin_token, username="later", password=ADMIN_PW + "x", role=Role.VIEWER
    )
    _, safety = restore_database(snapshot.path, db_path)
    with services.db.connect() as conn:
        names = [r[0] for r in conn.execute("SELECT username FROM users")]
    assert names == ["admin"]
    assert safety is not None and "pre-restore" in safety.path.name
    conn = sqlite3.connect(safety.path)  # the undo point still has the newer user
    assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 2
    conn.close()


@pytest.mark.parametrize(
    "content", [b"", b"not a database at all" * 50, b"SQLite format 3\x00" + b"\x00" * 200]
)
def test_restore_rejects_invalid_files(tmp_path, services, content):
    bad = tmp_path / "bad.db"
    bad.write_bytes(content)
    with pytest.raises(BackupError):
        restore_database(bad, services.settings.db_path)


def test_restore_rejects_foreign_sqlite_database(tmp_path, services):
    foreign = tmp_path / "foreign.db"
    conn = sqlite3.connect(foreign)
    conn.execute("CREATE TABLE x (a)")
    conn.commit()
    conn.close()
    with pytest.raises(BackupError, match="not a valid application database|schema"):
        verify_backup(foreign)


def test_restore_detects_tampered_fingerprint(services, admin_token):
    info = backup_database(services.settings.db_path)
    info.path.with_suffix(".db.sha256").write_text("0" * 64 + "  x\n")
    with pytest.raises(BackupError, match="fingerprint"):
        restore_database(info.path, services.settings.db_path)


def test_pending_migration_on_existing_db_takes_backup_first(db, monkeypatch):
    original = dbmod.load_migrations()
    extra = Migration(999, "test_extra", "CREATE TABLE t_extra (a INTEGER);")
    monkeypatch.setattr(dbmod, "load_migrations", lambda: [*original, extra])
    assert db.migrate() == [999]
    backups = list_backups(db.path)
    assert len(backups) == 1 and "pre-migration-999" in backups[0].name
    assert 999 not in verify_backup(backups[0]).schema_versions  # backup = state before


def test_fresh_database_needs_no_backup(tmp_path):
    db = Database(tmp_path / "fresh.db")
    db.migrate()
    assert list_backups(db.path) == []


def test_admin_recovery_resets_unlocks_and_audits(services, admin_token):
    for _ in range(services.settings.login_max_failures):
        with pytest.raises(AuthenticationError):
            services.auth.login("admin", "Wrong-Password-123")
    with pytest.raises(RateLimitedError):
        services.auth.login("admin", ADMIN_PW)
    recover_admin(services.settings.db_path, "admin", NEW_PW)
    with pytest.raises(Exception):  # noqa: B017 - SessionExpiredError
        services.auth.resolve(admin_token)
    services.auth.login("admin", NEW_PW)
    with services.db.connect() as conn:
        row = audit_repo.list_events(conn, action="admin.recovery_cli")[0]
        assert row["actor_username"] == "local-terminal" and NEW_PW not in row["details"]
        assert audit_repo.verify_chain(conn).ok


def test_admin_recovery_refuses_non_admins_and_weak_passwords(services, admin_token, analyst_token):
    with pytest.raises(BackupError):
        recover_admin(services.settings.db_path, "analyst1", NEW_PW)
    with pytest.raises(BackupError):
        recover_admin(services.settings.db_path, "nobody", NEW_PW)
    with pytest.raises(ValidationFailedError):
        recover_admin(services.settings.db_path, "admin", "short")
