"""Audit log access and application health/configuration status."""

from __future__ import annotations

import time
from typing import Any

from threatlens.config import Settings
from threatlens.db.database import Database
from threatlens.errors import ThreatLensError
from threatlens.repositories import audit_repo
from threatlens.security.rbac import Permission, has_permission
from threatlens.services.auth_service import AuthService
from threatlens.services.detection_service import DetectionService
from threatlens.services.investigation import InvestigationService
from threatlens.services.retrieval_service import RetrievalService


class AdminService:
    def __init__(
        self,
        db: Database,
        auth: AuthService,
        settings: Settings,
        detection: DetectionService,
        investigation: InvestigationService,
        retrieval: RetrievalService,
    ) -> None:
        self.db = db
        self.auth = auth
        self.settings = settings
        self.detection = detection
        self.investigation = investigation
        self.retrieval = retrieval

    def audit_log(
        self, token: str, *, action: str | None = None, actor: str | None = None, limit: int = 500
    ) -> list[dict[str, Any]]:
        self.auth.authorize(token, Permission.VIEW_AUDIT)
        with self.db.connect() as conn:
            return [
                dict(r)
                for r in audit_repo.list_events(conn, action=action, actor=actor, limit=limit)
            ]

    def verify_audit_chain(self, token: str) -> dict[str, Any]:
        self.auth.authorize(token, Permission.VIEW_AUDIT)
        with self.db.connect() as conn:
            status = audit_repo.verify_chain(conn)
        return {"ok": status.ok, "checked": status.checked, "first_bad_id": status.first_bad_id}

    def health(self, token: str) -> dict[str, Any]:
        principal = self.auth.authorize(token, Permission.VIEW_HEALTH)
        is_admin = has_permission(principal.role, Permission.MANAGE_SYSTEM)
        checks: dict[str, Any] = {}

        started = time.perf_counter()
        try:
            integrity = self.db.integrity_check()
            with self.db.connect() as conn:
                versions = [
                    r[0]
                    for r in conn.execute("SELECT version FROM schema_migrations ORDER BY version")
                ]
                chain = audit_repo.verify_chain(conn)
            checks["database"] = {
                "ok": integrity == "ok",
                "integrity": integrity,
                "schema_versions": versions,
                "latency_ms": round((time.perf_counter() - started) * 1000, 1),
            }
            checks["audit_chain"] = {"ok": chain.ok, "rows_verified": chain.checked}
        except ThreatLensError as exc:
            checks["database"] = {"ok": False, "error": exc.public_message}

        rules = self.detection.rules
        checks["detection_rules"] = {
            "ok": not rules.errors,
            "loaded": len(rules.rules),
            "rejected": [name for name, _ in rules.errors],
        }
        checks["attack_dataset"] = {
            "ok": True,
            "label": self.detection.catalog.label,
            "techniques": len(self.detection.catalog.techniques),
        }
        ollama = self.investigation.status()
        checks["ollama"] = {
            "ok": bool(ollama.get("available") and ollama.get("model_installed")),
            **ollama,
            "model": self.settings.ollama_model,
        }
        checks["vector_search"] = {
            "ok": self.retrieval.status().get("available", False)
            or not self.settings.enable_vector_search,
            **self.retrieval.status(),
        }

        config = {
            "environment": self.settings.env,
            "ollama_model": self.settings.ollama_model,
            "embed_model": self.settings.ollama_embed_model,
            "ollama_timeout_s": self.settings.ollama_timeout_seconds,
            "ai_max_events": self.settings.ai_max_events,
            "session_idle_minutes": self.settings.session_idle_minutes,
            "login_max_failures": self.settings.login_max_failures,
            "max_upload_mb": self.settings.max_upload_mb,
            "two_person_approval": self.settings.response_require_two_person,
        }
        if is_admin:  # internal locations are shown to administrators only
            config["ollama_host"] = self.settings.ollama_host
            config["data_dir"] = str(self.settings.data_dir)
        return {"checks": checks, "config": config}
