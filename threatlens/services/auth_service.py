"""Authentication, sessions, first-run setup and authorization.

Security properties (see THREAT_MODEL.md T1-T4):
* Setup works only while zero users exist. It needs a one-time code issued out-of-band
  by ``scripts/init_db.py``. The user check runs inside a write transaction.
* Login throttling is keyed by username, whether or not the user exists, plus a global
  failure ceiling. The response is generic, so it does not reveal which accounts exist.
* Session tokens are 256-bit random values. Only their SHA-256 is stored. Every call
  re-resolves token → user → role from the database.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import secrets
from datetime import timedelta

from threatlens.config import Settings
from threatlens.db.database import Database
from threatlens.errors import (
    AuthenticationError,
    AuthorizationError,
    RateLimitedError,
    SessionExpiredError,
    SetupError,
    ValidationFailedError,
)
from threatlens.models.domain import Principal, Role
from threatlens.repositories import audit_repo, user_repo
from threatlens.security.passwords import (
    hash_password,
    needs_rehash,
    validate_password_policy,
    verify_password,
)
from threatlens.security.rbac import Permission, has_permission
from threatlens.timeutil import from_iso, iso_after, to_iso, utcnow, utcnow_iso

log = logging.getLogger(__name__)

USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,64}$")
SETUP_CODE_KEY = "setup_code"
SETUP_CODE_TTL_MINUTES = 30


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def validate_username(username: str) -> str:
    username = username.strip()
    if not USERNAME_RE.fullmatch(username):
        raise ValidationFailedError(
            "Username must be 3-64 characters: letters, digits, dot, underscore or hyphen."
        )
    return username


class AuthService:
    def __init__(self, db: Database, settings: Settings) -> None:
        self.db = db
        self.settings = settings

    # --- first-run setup ------------------------------------------------------------------

    def setup_required(self) -> bool:
        with self.db.connect() as conn:
            return user_repo.count_users(conn) == 0

    def issue_setup_code(self) -> str:
        """Create a one-time setup code (only while no users exist). Returns the plaintext once."""
        code = secrets.token_urlsafe(18)
        value = f"{_sha256(code)}|{iso_after(SETUP_CODE_TTL_MINUTES)}"
        with self.db.transaction() as conn:
            if user_repo.count_users(conn) > 0:
                raise SetupError()
            conn.execute(
                "INSERT INTO app_config (key, value, updated_at) VALUES (?, ?, ?)"
                " ON CONFLICT(key) DO UPDATE SET value = excluded.value,"
                " updated_at = excluded.updated_at",
                (SETUP_CODE_KEY, value, utcnow_iso()),
            )
            audit_repo.append(conn, action="setup.code_issued", outcome="success")
        return code

    def create_initial_admin(
        self, *, setup_code: str, username: str, password: str, display_name: str = ""
    ) -> int:
        username = validate_username(username)
        validate_password_policy(password, username=username)
        password_hash = hash_password(password)
        denied: SetupError | None = None
        with self.db.transaction() as conn:
            row = conn.execute(
                "SELECT value FROM app_config WHERE key = ?", (SETUP_CODE_KEY,)
            ).fetchone()
            if user_repo.count_users(conn) > 0:
                denied, reason = SetupError(), "already_initialised"
            elif not row or not self._setup_code_valid(row["value"], setup_code):
                denied = SetupError("The setup code is invalid or expired.")
                reason = "invalid_setup_code"
        if denied is not None:
            self.audit_denied("setup.create_admin", None, reason=reason)
            raise denied
        with self.db.transaction() as conn:
            # Re-check inside the write transaction: closes the race between two setups.
            if user_repo.count_users(conn) > 0:
                raise SetupError()
            user_id = user_repo.create_user(
                conn,
                username=username,
                display_name=display_name[:128],
                password_hash=password_hash,
                role=Role.ADMIN,
            )
            conn.execute("DELETE FROM app_config WHERE key = ?", (SETUP_CODE_KEY,))
            audit_repo.append(
                conn,
                action="setup.create_admin",
                outcome="success",
                actor_id=user_id,
                actor_username=username,
                target_type="user",
                target_id=user_id,
            )
        log.info("initial administrator created", extra={"user_id": user_id})
        return user_id

    @staticmethod
    def _setup_code_valid(stored: str, supplied: str) -> bool:
        digest, _, expires = stored.partition("|")
        if not expires or from_iso(expires) < utcnow():
            return False
        return hmac.compare_digest(digest, _sha256(supplied.strip()))

    # --- login / logout -------------------------------------------------------------------

    def _check_throttle(self, conn, username: str) -> None:
        window_start = to_iso(utcnow() - timedelta(minutes=self.settings.login_lockout_minutes))
        user_failures = conn.execute(
            "SELECT COUNT(*) FROM login_attempts WHERE username = ? COLLATE NOCASE"
            " AND success = 0 AND created_at >= ?",
            (username, window_start),
        ).fetchone()[0]
        global_failures = user_repo.count_failures_since(
            conn, to_iso(utcnow() - timedelta(minutes=1))
        )
        if (
            user_failures >= self.settings.login_max_failures
            or global_failures >= self.settings.global_login_failures_per_minute
        ):
            audit_repo.append(
                conn,
                action="auth.login",
                outcome="denied",
                actor_username=username[:64],
                details={"reason": "throttled"},
            )
            raise RateLimitedError()

    def login(self, username: str, password: str) -> str:
        username = (username or "").strip()[:64]
        password = (password or "")[:256]
        with self.db.transaction() as conn:
            self._check_throttle(conn, username)
            row = user_repo.get_auth_row(conn, username) if username else None
            # Always run a hash verification to keep timing uniform.
            ok = verify_password(row["password_hash"] if row else None, password)
            if not row or not ok or not row["is_active"]:
                user_repo.add_login_attempt(conn, username, False)
                if row:
                    user_repo.record_login_failure(conn, row["id"], None)
                reason = "inactive" if row and ok else "bad_credentials"
                audit_repo.append(
                    conn,
                    action="auth.login",
                    outcome="failure",
                    actor_username=username,
                    details={"reason": reason},
                )
                failed = True
            else:
                failed = False
                user_repo.add_login_attempt(conn, username, True)
                user_repo.record_login_success(conn, row["id"])
                if needs_rehash(row["password_hash"]):
                    user_repo.update_password_hash(conn, row["id"], hash_password(password))
                token = secrets.token_urlsafe(32)
                user_repo.create_session(
                    conn,
                    token_hash=_sha256(token),
                    user_id=row["id"],
                    expires_at=iso_after(hours=self.settings.session_absolute_hours),
                )
                audit_repo.append(
                    conn,
                    action="auth.login",
                    outcome="success",
                    actor_id=row["id"],
                    actor_username=row["username"],
                )
        if failed:
            # Raised after commit so the failed attempt is recorded for throttling.
            raise AuthenticationError()
        return token

    def logout(self, token: str) -> None:
        with self.db.transaction() as conn:
            row = user_repo.get_session(conn, _sha256(token))
            user_repo.revoke_session(conn, _sha256(token))
            if row:
                audit_repo.append(
                    conn,
                    action="auth.logout",
                    outcome="success",
                    actor_id=row["user_id"],
                    actor_username=row["username"],
                )

    # --- session resolution & authorization -----------------------------------------------

    def resolve(self, token: str | None) -> Principal:
        if not token or len(token) > 128:
            raise SessionExpiredError()
        token_hash = _sha256(token)
        with self.db.transaction() as conn:
            row = user_repo.get_session(conn, token_hash)
            now = utcnow()
            if (
                not row
                or row["revoked_at"] is not None
                or from_iso(row["expires_at"]) <= now
                or from_iso(row["last_seen_at"])
                + timedelta(minutes=self.settings.session_idle_minutes)
                <= now
                or not row["is_active"]
            ):
                if row and row["revoked_at"] is None:
                    user_repo.revoke_session(conn, token_hash)
                raise SessionExpiredError()
            user_repo.touch_session(conn, token_hash)
            return Principal(
                user_id=row["user_id"], username=row["username"], role=Role(row["role"])
            )

    def authorize(self, token: str | None, permission: Permission) -> Principal:
        principal = self.resolve(token)
        if not has_permission(principal.role, permission):
            self.audit_denied("authz.denied", principal, permission=permission.value)
            raise AuthorizationError()
        return principal

    def audit_denied(
        self,
        action: str,
        principal: Principal | None,
        *,
        target_type: str | None = None,
        target_id: str | int | None = None,
        **details: object,
    ) -> None:
        """Record a denial in its own transaction (the caller's transaction will roll back)."""
        with self.db.transaction() as conn:
            audit_repo.append(
                conn,
                action=action,
                outcome="denied",
                actor_id=principal.user_id if principal else None,
                actor_username=principal.username if principal else None,
                target_type=target_type,
                target_id=target_id,
                details=dict(details),
            )

    def change_own_password(self, token: str, current: str, new: str) -> bool:
        principal = self.resolve(token)
        validate_password_policy(new, username=principal.username)
        with self.db.transaction() as conn:
            row = user_repo.get_auth_row(conn, principal.username)
            if not row or not verify_password(row["password_hash"], current):
                audit_repo.append(
                    conn,
                    action="user.change_password",
                    outcome="failure",
                    actor_id=principal.user_id,
                    actor_username=principal.username,
                )
                failed = True
            else:
                failed = False
                user_repo.update_password_hash(conn, principal.user_id, hash_password(new))
                user_repo.revoke_user_sessions(conn, principal.user_id)
                audit_repo.append(
                    conn,
                    action="user.change_password",
                    outcome="success",
                    actor_id=principal.user_id,
                    actor_username=principal.username,
                )
        if failed:
            raise AuthenticationError("Current password is incorrect.")
        return True
