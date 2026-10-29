"""Composition root: builds the service graph once per process."""

from __future__ import annotations

from dataclasses import dataclass

from threatlens.config import Settings, get_settings
from threatlens.db.database import Database
from threatlens.integrations.ollama import OllamaClient
from threatlens.integrations.vector_store import Embedder, OllamaEmbedder, VectorStore
from threatlens.logging_setup import configure_logging
from threatlens.services.admin_service import AdminService
from threatlens.services.auth_service import AuthService
from threatlens.services.detection_service import DetectionService
from threatlens.services.incident_service import IncidentService
from threatlens.services.ingestion_service import IngestionService
from threatlens.services.investigation import InvestigationService
from threatlens.services.response_service import ResponseService
from threatlens.services.retrieval_service import RetrievalService
from threatlens.services.user_service import UserService


@dataclass
class Services:
    settings: Settings
    db: Database
    auth: AuthService
    users: UserService
    ingestion: IngestionService
    detection: DetectionService
    incidents: IncidentService
    investigation: InvestigationService
    retrieval: RetrievalService
    response: ResponseService
    admin: AdminService


def build_services(
    settings: Settings | None = None,
    *,
    ollama_client: OllamaClient | None = None,
    embedder: Embedder | None = None,
) -> Services:
    settings = settings or get_settings()
    configure_logging(settings.log_level)
    db = Database(settings.db_path)
    db.migrate()
    auth = AuthService(db, settings)
    client = ollama_client or OllamaClient(
        settings.ollama_host, timeout=settings.ollama_timeout_seconds
    )
    chosen_embedder = embedder or OllamaEmbedder(client, settings.ollama_embed_model)

    def store_factory() -> VectorStore:
        return VectorStore(settings.chroma_dir, chosen_embedder)

    detection = DetectionService(db, auth)
    investigation = InvestigationService(db, auth, settings, client=client)
    retrieval = RetrievalService(db, auth, store_factory, enabled=settings.enable_vector_search)
    return Services(
        settings=settings,
        db=db,
        auth=auth,
        users=UserService(db, auth),
        ingestion=IngestionService(db, auth, settings),
        detection=detection,
        incidents=IncidentService(db, auth),
        investigation=investigation,
        retrieval=retrieval,
        response=ResponseService(db, auth, settings),
        admin=AdminService(db, auth, settings, detection, investigation, retrieval),
    )
