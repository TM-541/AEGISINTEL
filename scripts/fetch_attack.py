"""Build a local ATT&CK technique catalogue from the official MITRE CTI STIX bundle.

Usage:
  .venv\\Scripts\\python.exe scripts\\fetch_attack.py            # download + build catalogue
  .venv\\Scripts\\python.exe scripts\\fetch_attack.py --verify   # also verify bundled subset

The bundle is parsed as JSON data only. Output: threatlens/integrations/data/attack_catalog.json
(git-ignored). When that file is present, the app uses it in place of the bundled subset.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import httpx

SOURCE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)
DATA_DIR = Path(__file__).resolve().parent.parent / "threatlens" / "integrations" / "data"
MAX_BYTES = 200 * 1024 * 1024


def _attack_id(obj: dict) -> str | None:
    ref = next(
        (r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"),
        None,
    )
    return ref.get("external_id") if ref else None


def build_catalog(bundle: dict) -> dict:
    """Active techniques plus a map of revoked IDs to their replacements."""
    techniques: dict[str, dict] = {}
    stix_to_id: dict[str, str] = {}
    revoked_stix: dict[str, str] = {}
    latest_modified = ""
    objects = bundle.get("objects", [])
    for obj in objects:
        if obj.get("type") == "attack-pattern" and _attack_id(obj):
            stix_to_id[obj["id"]] = _attack_id(obj)  # type: ignore[assignment]
            latest_modified = max(latest_modified, obj.get("modified", ""))
    for obj in objects:
        if obj.get("type") == "relationship" and obj.get("relationship_type") == "revoked-by":
            revoked_stix[obj["source_ref"]] = obj["target_ref"]
    revoked = {
        stix_to_id[src]: stix_to_id.get(dst)
        for src, dst in revoked_stix.items()
        if src in stix_to_id
    }
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ref = next(
            (
                r
                for r in obj.get("external_references", [])
                if r.get("source_name") == "mitre-attack"
            ),
            None,
        )
        if not ref or not ref.get("external_id"):
            continue
        techniques[ref["external_id"]] = {
            "name": obj.get("name", ""),
            "tactics": sorted(
                p["phase_name"]
                for p in obj.get("kill_chain_phases", [])
                if p.get("kill_chain_name") == "mitre-attack"
            ),
            "url": ref.get("url", ""),
        }
    return {
        "version": f"enterprise-attack (latest object modified {latest_modified[:10]})",
        "techniques": techniques,
        "revoked": revoked,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify", action="store_true", help="check the bundled subset IDs")
    args = parser.parse_args()

    print(f"Downloading {SOURCE_URL}")
    with httpx.Client(timeout=120, follow_redirects=True) as client:
        resp = client.get(SOURCE_URL)
        resp.raise_for_status()
    if len(resp.content) > MAX_BYTES:
        print("Refusing unexpectedly large bundle", file=sys.stderr)
        return 1
    sha = hashlib.sha256(resp.content).hexdigest()
    catalog = build_catalog(resp.json())
    catalog.update(
        {
            "source": SOURCE_URL,
            "sha256": sha,
            "retrieved_at": datetime.now(UTC).isoformat(timespec="seconds"),
        }
    )
    out = DATA_DIR / "attack_catalog.json"
    out.write_text(json.dumps(catalog, indent=1, sort_keys=True), encoding="utf-8")
    print(f"ATT&CK {catalog['version']}: {len(catalog['techniques'])} techniques -> {out}")

    if args.verify:
        subset = json.loads((DATA_DIR / "attack_subset.json").read_text(encoding="utf-8"))
        bad = 0
        for tid, info in subset["techniques"].items():
            official = catalog["techniques"].get(tid)
            if official is None:
                print(f"  MISSING/REVOKED: {tid} {info['name']}")
                bad += 1
            elif official["name"] != info["name"] or official["tactics"] != info["tactics"]:
                print(
                    f"  DIFFERS: {tid} subset={info['name']}/{info['tactics']} "
                    f"official={official['name']}/{official['tactics']}"
                )
                bad += 1
        print("Subset verification:", "OK" if not bad else f"{bad} problem(s)")
        return 1 if bad else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
