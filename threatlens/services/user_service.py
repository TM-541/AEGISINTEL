"""Administrator user management with escalation safeguards."""

from __future__ import annotations

import sqlite3

from threatlens.db.database import Database
from threatlens.errors import (
    AuthorizationError,
    ConflictError,
    NotFoundError,
    ValidationFailedError,
)
from threatlens.models.domain import Role, User
from threatlens.repositories import audit_repo, user_repo
from threatlens.security.passwords import hash_password, validate_password_policy
from threatlens.security.rbac import Permission
from threatlens.services.auth_service import AuthService, validate_username


class UserService:
    def __init__(self, db: Database, auth: AuthService) -> None:
        self.db = db
        self.auth = auth

    def list_users(self, token: str) -> list[User]:
        self.auth.authorize(token, Permission.MANAGE_USERS)
        with self.db.connect() as conn:
            return user_repo.list_users(conn)

    def list_assignable(self, token: str) -> list[User]:
        """Active analysts/admins for incident assignment (no sensitive fields)."""
        self.auth.authorize(token, Permission.VIEW_INCIDENTS)
        with self.db.connect() as conn:
            return [
                u
                for u in user_repo.list_users(conn)
                if u.is_active and u.role in (Role.ANALYST, Role.ADMIN)
            ]

    def create_user(
        self, token: str, *, username: str, password: str, role: Role, display_name: str = ""
    ) -> int:
        actor = self.auth.authorize(token, Permission.MANAGE_USERS)
        username = validate_username(username)
        role = Role(role)
        validate_password_policy(password, username=username)
        password_hash = hash_password(password)
        with self.db.transaction() as conn:
            try:
                user_id = user_repo.create_user(
                    conn,
                    username=username,
                    display_name=display_name[:128],
                    password_hash=password_hash,
                    role=role,
                )
            except sqlite3.IntegrityError as exc:
                raise ValidationFailedError("That username is not available.") from exc
            audit_repo.append(
                conn,
                action="user.create",
                outcome="success",
                actor_id=actor.user_id,
                actor_username=actor.username,
                target_type="user",
                target_id=user_id,
                details={"role": role.value},
            )
        return user_id

    def change_role(self, token: str, user_id: int, role: Role) -> bool:
        actor = self.auth.authorize(token, Permission.MANAGE_USERS)
        role = Role(role)
        with self.db.transaction() as conn:
            target = user_repo.get_user(conn, user_id)
            if target is None:
                raise NotFoundError()
            self_change = target.id == actor.user_id
            if self_change:
                pass
            elif (
                target.role == Role.ADMIN
                and role != Role.ADMIN
                and target.is_active
                and user_repo.count_active_admins(conn) <= 1
            ):
                raise ConflictError("At least one active administrator must remain.")
            else:
                user_repo.set_role(conn, user_id, role)
                user_repo.revoke_user_sessions(conn, user_id)
                audit_repo.append(
                    conn,
                    action="user.change_role",
                    outcome="success",
                    actor_id=actor.user_id,
                    actor_username=actor.username,
                    target_type="user",
                    target_id=user_id,
                    details={"from": target.role.value, "to": role.value},
                )
        if self_change:
            self.auth.audit_denied(
                "user.change_role",
                actor,
                target_type="user",
                target_id=user_id,
                reason="self_change",
            )
            raise AuthorizationError("You cannot change your own role.")
        return True

    def set_active(self, token: str, user_id: int, active: bool) -> bool:
        actor = self.auth.authorize(token, Permission.MANAGE_USERS)
        with self.db.transaction() as conn:
            target = user_repo.get_user(conn, user_id)
            if target is None:
                raise NotFoundError()
            if target.id == actor.user_id and not active:
                raise AuthorizationError("You cannot disable your own account.")
            if (
                not active
                and target.role == Role.ADMIN
                and target.is_active
                and user_repo.count_active_admins(conn) <= 1
            ):
                raise ConflictError("At least one active administrator must remain.")
            user_repo.set_active(conn, user_id, active)
            if not active:
                user_repo.revoke_user_sessions(conn, user_id)
            audit_repo.append(
                conn,
                action="user.enable" if active else "user.disable",
                outcome="success",
                actor_id=actor.user_id,
                actor_username=actor.username,
                target_type="user",
                target_id=user_id,
            )
        return True

    def reset_password(self, token: str, user_id: int, new_password: str) -> bool:
        actor = self.auth.authorize(token, Permission.MANAGE_USERS)
        with self.db.transaction() as conn:
            target = user_repo.get_user(conn, user_id)
            if target is None:
                raise NotFoundError()
            validate_password_policy(new_password, username=target.username)
            user_repo.update_password_hash(conn, user_id, hash_password(new_password))
            user_repo.revoke_user_sessions(conn, user_id)
            audit_repo.append(
                conn,
                action="user.reset_password",
                outcome="success",
                actor_id=actor.user_id,
                actor_username=actor.username,
                target_type="user",
                target_id=user_id,
            )
        return True
