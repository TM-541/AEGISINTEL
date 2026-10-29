from __future__ import annotations

import sqlite3

import pytest

from threatlens.db import database as dbmod
from threatlens.db.database import Database, Migration, MigrationIntegrityError
from threatlens.errors import DatabaseUnavailableError
from threatlens.models.domain import Role
from threatlens.repositories import audit_repo, user_repo


def test_migrate_is_idempotent(db):
    assert db.migrate() == []
    with db.connect() as conn:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"users", "events", "incidents", "audit_events", "response_proposals"} <= tables


def test_foreign_keys_enforced(db):
    with pytest.raises(sqlite3.IntegrityError), db.transaction() as conn:
        conn.execute(
            "INSERT INTO sessions (token_hash, user_id, created_at, last_seen_at, expires_at)"
            " VALUES ('h', 999, 'x', 'x', 'x')"
        )


def test_username_unique_case_insensitive(db):
    with db.transaction() as conn:
        user_repo.create_user(
            conn, username="alice", display_name="", password_hash="h", role=Role.ANALYST
        )
    with pytest.raises(sqlite3.IntegrityError), db.transaction() as conn:
        user_repo.create_user(
            conn, username="ALICE", display_name="", password_hash="h", role=Role.ANALYST
        )


def test_role_check_constraint(db):
    with pytest.raises(sqlite3.IntegrityError), db.transaction() as conn:
        conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at, updated_at)"
            " VALUES ('bob', 'h', 'superuser', 'x', 'x')"
        )


def test_transaction_rolls_back_on_error(db):
    with pytest.raises(RuntimeError), db.transaction() as conn:
        user_repo.create_user(
            conn, username="carol", display_name="", password_hash="h", role=Role.VIEWER
        )
        raise RuntimeError("boom")
    with db.connect() as conn:
        assert user_repo.count_users(conn) == 0


def test_sql_injection_payload_is_inert(db):
    payload = "x'; DROP TABLE users; --"
    with db.transaction() as conn:
        user_repo.create_user(
            conn, username=payload[:60], display_name=payload, password_hash="h", role=Role.VIEWER
        )
    with db.connect() as conn:
        assert user_repo.get_auth_row(conn, payload[:60]) is not None
        assert user_repo.count_users(conn) == 1


def test_modified_migration_detected(db, monkeypatch):
    original = dbmod.load_migrations()
    tampered = [Migration(m.version, m.name, m.sql + "\n-- edited") for m in original]
    monkeypatch.setattr(dbmod, "load_migrations", lambda: tampered)
    with pytest.raises(MigrationIntegrityError):
        db.migrate()


def test_corrupt_database_fails_safely(tmp_path):
    path = tmp_path / "corrupt.db"
    path.write_bytes(b"this is not a sqlite database" * 100)
    with pytest.raises(DatabaseUnavailableError) as exc_info:
        Database(path).migrate()
    assert "sqlite" not in exc_info.value.public_message.lower()


def test_audit_chain_verifies_and_is_append_only(db):
    with db.transaction() as conn:
        for i in range(3):
            audit_repo.append(
                conn, action="test.event", outcome="success", details={"i": i, "password": "p"}
            )
    with db.connect() as conn:
        status = audit_repo.verify_chain(conn)
        assert status.ok and status.checked == 3
        assert '"p"' not in conn.execute("SELECT details FROM audit_events").fetchone()[0]
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE audit_events SET outcome='failure' WHERE id=1")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("DELETE FROM audit_events WHERE id=1")


def test_audit_chain_detects_tampering(db):
    with db.transaction() as conn:
        for i in range(3):
            audit_repo.append(conn, action="test.event", outcome="success", details={"i": i})
    with db.connect() as conn:
        # Simulate an attacker with raw file access who bypasses the triggers.
        conn.execute("DROP TRIGGER audit_no_update")
        conn.execute("UPDATE audit_events SET outcome='failure' WHERE id=2")
        status = audit_repo.verify_chain(conn)
    assert not status.ok and status.first_bad_id == 2
