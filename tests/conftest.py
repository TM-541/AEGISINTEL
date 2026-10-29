from __future__ import annotations

import os

import pytest

from threatlens.config import Settings

ADMIN_PW = "Correct-Horse-Battery-9"
ANALYST_PW = "Analyst-Strong-Pass-42"
VIEWER_PW = "Viewer-Strong-Pass-77"


@pytest.fixture()
def settings(tmp_path, monkeypatch) -> Settings:
    # Isolate from any developer .env file or environment overrides.
    monkeypatch.chdir(tmp_path)
    for key in list(os.environ):
        if key.startswith("THREATLENS_"):
            monkeypatch.delenv(key, raising=False)
    return Settings(
        env="test", data_dir=tmp_path / "data", enable_vector_search=False, _env_file=None
    )


@pytest.fixture()
def db(settings):
    from threatlens.db.database import Database

    database = Database(settings.db_path)
    database.migrate()
    return database


@pytest.fixture()
def services(settings):
    from threatlens.services.container import build_services

    return build_services(settings)


@pytest.fixture()
def admin_token(services):
    code = services.auth.issue_setup_code()
    services.auth.create_initial_admin(setup_code=code, username="admin", password=ADMIN_PW)
    return services.auth.login("admin", ADMIN_PW)


@pytest.fixture()
def analyst_token(services, admin_token):
    from threatlens.models.domain import Role

    services.users.create_user(
        admin_token, username="analyst1", password=ANALYST_PW, role=Role.ANALYST
    )
    return services.auth.login("analyst1", ANALYST_PW)


@pytest.fixture()
def viewer_token(services, admin_token):
    from threatlens.models.domain import Role

    services.users.create_user(
        admin_token, username="viewer1", password=VIEWER_PW, role=Role.VIEWER
    )
    return services.auth.login("viewer1", VIEWER_PW)
