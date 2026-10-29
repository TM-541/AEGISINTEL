"""Optional live tests against a local Ollama (and Chroma). Run: pytest -m integration

Model names come from THREATLENS_OLLAMA_MODEL / THREATLENS_OLLAMA_EMBED_MODEL if set.
"""

from __future__ import annotations

import os

import pytest

from tests.test_investigation import seed
from threatlens.config import Settings
from threatlens.services.container import build_services

pytestmark = pytest.mark.integration


@pytest.fixture()
def live_services(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "data",
        _env_file=None,
        enable_vector_search=True,
        ollama_model=os.environ.get("THREATLENS_OLLAMA_MODEL", "llama3.2:3b"),
        ollama_embed_model=os.environ.get("THREATLENS_OLLAMA_EMBED_MODEL", "nomic-embed-text"),
        ollama_timeout_seconds=600,
    )
    services = build_services(settings)
    if not services.investigation.status().get("available"):
        pytest.skip("Ollama is not running")
    return services


def test_live_investigation_produces_validated_traceable_report(live_services):
    token, iid, ids, detail = seed(live_services)
    out = live_services.investigation.investigate(token, iid)
    print("\nstatus:", out["status"], "attempts:", out["attempts"], "ms:", out["duration_ms"])
    print("notes:", out["validation_notes"])
    print("summary:", out["report"]["summary"][:400])
    assert out["status"] in {"validated", "fallback"}
    report = out["report"]
    valid_ids = set(ids)
    for entry in report["timeline"]:
        assert set(entry["event_ids"]) <= valid_ids
    for t in report["attack_techniques"]:
        assert live_services.investigation.catalog.is_valid(t["technique_id"])
    # Deterministic state untouched by whatever the model wrote.
    assert live_services.incidents.detail(token, iid)["incident"]["severity"] == "critical"
    assert report["injection_warnings"], "the sample injection alert should be flagged"


def test_live_embedding_retrieval_relevance(live_services):
    token, host_id, _, _ = seed(live_services)
    assert live_services.retrieval.reindex(token) == len(
        live_services.incidents.list_incidents(token)
    )
    incidents = live_services.incidents.list_incidents(token)
    brute = next(i for i in incidents if i["rule_id"] == "TL-CR-001")
    results = live_services.retrieval.similar(token, brute["id"], k=2)
    print("\nsimilar to brute force:", [(r["title"], r["similarity"]) for r in results])
    assert results[0]["title"].startswith("Password spraying")
    assert results[0]["similarity"] > results[1]["similarity"]
