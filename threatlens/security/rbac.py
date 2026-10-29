"""Role-based access control: explicit role → permission mapping."""

from __future__ import annotations

from enum import StrEnum

from threatlens.models.domain import Role


class Permission(StrEnum):
    VIEW_DASHBOARD = "view_dashboard"
    VIEW_EVENTS = "view_events"
    VIEW_INCIDENTS = "view_incidents"
    VIEW_REPORTS = "view_reports"
    VIEW_RULES = "view_rules"
    IMPORT_EVENTS = "import_events"
    RUN_CORRELATION = "run_correlation"
    UPDATE_INCIDENT = "update_incident"
    RUN_AI_INVESTIGATION = "run_ai_investigation"
    SEARCH_SIMILAR = "search_similar"
    PROPOSE_RESPONSE = "propose_response"
    DECIDE_RESPONSE = "decide_response"
    VIEW_AUDIT = "view_audit"
    MANAGE_USERS = "manage_users"
    VIEW_HEALTH = "view_health"
    MANAGE_SYSTEM = "manage_system"


_VIEWER = {
    Permission.VIEW_DASHBOARD,
    Permission.VIEW_EVENTS,
    Permission.VIEW_INCIDENTS,
    Permission.VIEW_REPORTS,
    Permission.VIEW_RULES,
    Permission.VIEW_HEALTH,
}
_ANALYST = _VIEWER | {
    Permission.IMPORT_EVENTS,
    Permission.RUN_CORRELATION,
    Permission.UPDATE_INCIDENT,
    Permission.RUN_AI_INVESTIGATION,
    Permission.SEARCH_SIMILAR,
    Permission.PROPOSE_RESPONSE,
    Permission.DECIDE_RESPONSE,
}
_ADMIN = _ANALYST | {Permission.VIEW_AUDIT, Permission.MANAGE_USERS, Permission.MANAGE_SYSTEM}

ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.VIEWER: frozenset(_VIEWER),
    Role.ANALYST: frozenset(_ANALYST),
    Role.ADMIN: frozenset(_ADMIN),
}


def has_permission(role: Role, permission: Permission) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, frozenset())
