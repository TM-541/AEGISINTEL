"""User, session and login-attempt persistence."""

from __future__ import annotations

import sqlite3

from threatlens.models.domain import Role, User
from threatlens.timeutil import utcnow_iso


def _to_user(row: sqlite3.Row) -> User:
    return User(
        id=row["id"],
        username=row["username"],
        display_name=row["display_name"],
        role=Role(row["role"]),
        is_active=bool(row["is_active"]),
        last_login_at=row["last_login_at"],
        created_at=row["created_at"],
    )


def count_users(conn: sqlite3.Connection) -> int:
    return int(conn.execute("SELECT COUNT(*) FROM users").fetchone()[0])


def count_active_admins(conn: sqlite3.Connection) -> int:
    return int(
        conn.execute(
            "SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active = 1"
        ).fetchone()[0]
    )


def create_user(
    conn: sqlite3.Connection, *, username: str, display_name: str, password_hash: str, role: Role
) -> int:
    now = utcnow_iso()
    cur = conn.execute(
        "INSERT INTO users (username, display_name, password_hash, role, created_at, updated_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (username, display_name, password_hash, role.value, now, now),
    )
    return int(cur.lastrowid or 0)


def get_auth_row(conn: sqlite3.Connection, username: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def get_user(conn: sqlite3.Connection, user_id: int) -> User | None:
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return _to_user(row) if row else None


def list_users(conn: sqlite3.Connection) -> list[User]:
    return [_to_user(r) for r in conn.execute("SELECT * FROM users ORDER BY username")]


def record_login_failure(conn: sqlite3.Connection, user_id: int, locked_until: str | None) -> None:
    conn.execute(
        "UPDATE users SET failed_logins = failed_logins + 1,"
        " locked_until = COALESCE(?, locked_until), updated_at = ? WHERE id = ?",
        (locked_until, utcnow_iso(), user_id),
    )


def record_login_success(conn: sqlite3.Connection, user_id: int) -> None:
    now = utcnow_iso()
    conn.execute(
        "UPDATE users SET failed_logins = 0, locked_until = NULL, last_login_at = ?, updated_at = ?"
        " WHERE id = ?",
        (now, now, user_id),
    )


def update_password_hash(conn: sqlite3.Connection, user_id: int, password_hash: str) -> None:
    conn.execute(
        "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
        (password_hash, utcnow_iso(), user_id),
    )


def set_role(conn: sqlite3.Connection, user_id: int, role: Role) -> None:
    conn.execute(
        "UPDATE users SET role = ?, updated_at = ? WHERE id = ?",
        (role.value, utcnow_iso(), user_id),
    )


def set_active(conn: sqlite3.Connection, user_id: int, active: bool) -> None:
    conn.execute(
        "UPDATE users SET is_active = ?, updated_at = ? WHERE id = ?",
        (int(active), utcnow_iso(), user_id),
    )


# --- sessions -------------------------------------------------------------------------------


def create_session(
    conn: sqlite3.Connection, *, token_hash: str, user_id: int, expires_at: str
) -> None:
    now = utcnow_iso()
    conn.execute(
        "INSERT INTO sessions (token_hash, user_id, created_at, last_seen_at, expires_at)"
        " VALUES (?, ?, ?, ?, ?)",
        (token_hash, user_id, now, now, expires_at),
    )


def get_session(conn: sqlite3.Connection, token_hash: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT s.*, u.username, u.role, u.is_active FROM sessions s"
        " JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?",
        (token_hash,),
    ).fetchone()


def touch_session(conn: sqlite3.Connection, token_hash: str) -> None:
    conn.execute(
        "UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?", (utcnow_iso(), token_hash)
    )


def revoke_session(conn: sqlite3.Connection, token_hash: str) -> None:
    conn.execute(
        "UPDATE sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
        (utcnow_iso(), token_hash),
    )


def revoke_user_sessions(conn: sqlite3.Connection, user_id: int) -> None:
    conn.execute(
        "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
        (utcnow_iso(), user_id),
    )


# --- global throttling ----------------------------------------------------------------------


def add_login_attempt(conn: sqlite3.Connection, username: str, success: bool) -> None:
    conn.execute(
        "INSERT INTO login_attempts (username, success, created_at) VALUES (?, ?, ?)",
        (username[:64], int(success), utcnow_iso()),
    )


def count_failures_since(conn: sqlite3.Connection, since_iso: str) -> int:
    return int(
        conn.execute(
            "SELECT COUNT(*) FROM login_attempts WHERE success = 0 AND created_at >= ?",
            (since_iso,),
        ).fetchone()[0]
    )
