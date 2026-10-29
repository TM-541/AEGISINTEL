"""Reproducible performance measurements on synthetic data.

Usage: .venv\\Scripts\\python.exe scripts\\benchmark.py [--scales 1 10 50]

For each scale, generates datasets (scale x background noise, same attack scenario) into a
temporary directory, then measures:
  * ingestion preview + commit time and events/second
  * full detection run (Sigma subset + correlation) time
  * event search latency (p50/p95 over 50 filtered queries)
  * incident list + detail latency
Prints a Markdown table. Uses a throwaway database; nothing in data/ is touched.
"""

from __future__ import annotations

import argparse
import platform
import statistics
import subprocess  # nosec B404 - runs our own generator script only
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

from threatlens.config import Settings
from threatlens.ingest.normalize import SourceType
from threatlens.repositories.event_repo import EventFilter
from threatlens.services.container import build_services

ROOT = Path(__file__).resolve().parent.parent
PW = "Perf-Measure-Pass-2026!"


def pct(values: list[float], p: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(round(p / 100 * (len(ordered) - 1))))]


def run(scale: int, *, trace_memory: bool = False) -> dict:
    tmp = Path(tempfile.mkdtemp(prefix="tl-bench-"))
    subprocess.run(  # noqa: S603 # nosec B603 - fixed argv, our own script
        [
            sys.executable,
            str(ROOT / "scripts" / "generate_samples.py"),
            "--scale",
            str(scale),
            "--out",
            str(tmp / "samples"),
        ],
        check=True,
        capture_output=True,
    )
    s = build_services(
        Settings(
            data_dir=tmp / "data",
            log_level="ERROR",
            enable_vector_search=False,
            max_upload_mb=200,
            _env_file=None,
        )
    )
    code = s.auth.issue_setup_code()
    s.auth.create_initial_admin(setup_code=code, username="bench", password=PW)
    token = s.auth.login("bench", PW)

    suffix = "" if scale == 1 else f"_x{scale}"
    files = [
        (f"auth_events{suffix}.jsonl", SourceType.AUTH),
        (f"endpoint_events{suffix}.json", SourceType.ENDPOINT),
    ]
    if trace_memory:
        tracemalloc.start()
    total, t0 = 0, time.perf_counter()
    for name, src in files:
        data = (tmp / "samples" / name).read_bytes()
        preview = s.ingestion.preview(token, name, data, src)
        result = s.ingestion.commit(token, name, data, src, confirmed_sha256=preview.file_sha256)
        total += result.inserted
    ingest_s = time.perf_counter() - t0

    t0 = time.perf_counter()
    summary = s.detection.run(token)
    detect_s = time.perf_counter() - t0
    peak_bytes = tracemalloc.get_traced_memory()[1] if trace_memory else 0
    if trace_memory:
        tracemalloc.stop()

    facets = s.ingestion.facets(token)
    lat = []
    for i in range(50):
        flt = EventFilter(
            usernames=[facets["username"][i % len(facets["username"])]],
            text="exe" if i % 2 else None,
            limit=500,
        )
        t0 = time.perf_counter()
        s.ingestion.search(token, flt)
        lat.append((time.perf_counter() - t0) * 1000)

    inc_lat = []
    for _ in range(20):
        t0 = time.perf_counter()
        for inc in s.incidents.list_incidents(token):
            s.incidents.detail(token, inc["id"])
        inc_lat.append((time.perf_counter() - t0) * 1000)

    return {
        "scale": scale,
        "events": total,
        "ingest_s": ingest_s,
        "eps": total / ingest_s,
        "detect_s": detect_s,
        "incidents": summary.incidents_new,
        "findings": summary.findings_total,
        "search_p50": pct(lat, 50),
        "search_p95": pct(lat, 95),
        "incident_p50": statistics.median(inc_lat),
        "indicators": summary.indicators_total,
        "peak_mb": peak_bytes / 1_048_576,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scales", type=int, nargs="+", default=[1, 10, 50])
    args = parser.parse_args()
    print(
        f"Python {platform.python_version()} · {platform.platform()} · "
        f"{platform.processor() or 'unknown CPU'}\n"
    )
    print(
        "| scale | events | ingest (s) | events/s | detection (s) | incidents | findings "
        "| indicators | search p50 / p95 (ms) | list+detail all incidents p50 (ms) "
        "| peak Python heap, ingest+detect (MB) |"
    )
    print("|---|---|---|---|---|---|---|---|---|---|---|")
    for scale in args.scales:
        r = run(scale)  # timings measured without tracing overhead
        r["peak_mb"] = run(scale, trace_memory=True)["peak_mb"]
        print(
            f"| x{r['scale']} | {r['events']:,} | {r['ingest_s']:.2f} | {r['eps']:,.0f} "
            f"| {r['detect_s']:.2f} | {r['incidents']} | {r['findings']} "
            f"| {r['indicators']} | {r['search_p50']:.1f} / {r['search_p95']:.1f} "
            f"| {r['incident_p50']:.1f} | {r['peak_mb']:.1f} |"
        )


if __name__ == "__main__":
    main()
