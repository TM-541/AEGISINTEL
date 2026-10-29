"""MITRE ATT&CK technique catalogue with identifier validation.

Prefers the full catalogue built by ``scripts/fetch_attack.py`` (git-ignored) and falls back
to the bundled curated subset. A technique ID is only accepted if it exists in the loaded
dataset. Revoked IDs are reported along with their replacement.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
DATA_PACKAGE = "threatlens.integrations.data"


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]
    url: str


class UnknownTechniqueError(ValueError):
    pass


class AttackCatalog:
    def __init__(self, data: dict, *, dataset_name: str) -> None:
        self.dataset_name = dataset_name
        self.version: str = data.get("version") or "unknown"
        self.retrieved_at: str = data.get("retrieved_at", "unknown")
        self.source: str = data.get("source", "")
        self.revoked: dict[str, str | None] = data.get("revoked", {})
        self.techniques: dict[str, Technique] = {
            tid: Technique(tid, t["name"], tuple(t["tactics"]), t.get("url", ""))
            for tid, t in data["techniques"].items()
            if TECHNIQUE_RE.fullmatch(tid)
        }

    @property
    def label(self) -> str:
        return f"{self.dataset_name} | {self.version} | retrieved {self.retrieved_at[:10]}"

    def get(self, technique_id: str) -> Technique:
        tid = technique_id.strip().upper()
        if not TECHNIQUE_RE.fullmatch(tid):
            raise UnknownTechniqueError(f"'{technique_id[:20]}' is not a technique identifier")
        if tid in self.techniques:
            return self.techniques[tid]
        if tid in self.revoked:
            replacement = self.revoked[tid]
            raise UnknownTechniqueError(
                f"{tid} is revoked in ATT&CK" + (f"; use {replacement}" if replacement else "")
            )
        raise UnknownTechniqueError(f"{tid} is not in the loaded ATT&CK dataset")

    def is_valid(self, technique_id: str) -> bool:
        try:
            self.get(technique_id)
            return True
        except UnknownTechniqueError:
            return False


@lru_cache(maxsize=1)
def load_catalog() -> AttackCatalog:
    files = resources.files(DATA_PACKAGE)
    full = files / "attack_catalog.json"
    if full.is_file():
        return AttackCatalog(json.loads(full.read_text("utf-8")), dataset_name="full catalogue")
    subset = files / "attack_subset.json"
    return AttackCatalog(json.loads(subset.read_text("utf-8")), dataset_name="bundled subset")
