"""Transparent behavioural analytics: detection beyond known rules.

Each detector compares an event with a baseline built from the *same entity's own history*
and explains the result. Design rules:

* **No invented baselines.** If an entity lacks enough history, the detector records a
  coverage gap ("insufficient baseline") and emits nothing for it.
* **Past-only baselines** for logon detectors: an event is compared only with what happened
  before it, so the event under evaluation cannot make itself look normal.
* **Scores are anomaly strength, not probability of compromise.** A score near 1 means
  "strongly unusual for this entity given the history we have". It never means "malicious".
* **Untrusted baselines.** Baselines come from imported data, which may already contain
  attacker activity. That limitation is documented and shown with every indicator.

Pure functions with no I/O, deterministic for a given input, unit-testable in isolation.
"""

from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import PureWindowsPath
from typing import Any

from threatlens.timeutil import from_iso

BEHAVIOR_LOGIC_VERSION = "1.0"

DETECTORS = {
    "BH-001": "New logon source network for user",
    "BH-002": "Rare process on host",
    "BH-003": "Logon outside the user's observed active hours",
}


@dataclass(frozen=True)
class BehaviorConfig:
    min_baseline_logons: int = 5  # BH-001: prior successful logons required
    min_host_process_events: int = 12  # BH-002: process events on host required
    rare_process_max_count: int = 1  # BH-002: "rare" = seen at most this many times
    min_hour_baseline: int = 8  # BH-003: prior successful logons required
    hour_tolerance: int = 2  # BH-003: slack around observed hours (1 gave 2 FPs on samples)
    max_coverage_gaps: int = 200  # bound on reported gaps


@dataclass
class Indicator:
    detector_id: str
    entity: str  # "user:<name>" or "host:<name>"
    score: float  # 0..1 anomaly strength (not a probability of compromise)
    fingerprint: str
    event_ids: list[str]
    observed_at: str
    baseline: dict[str, Any]
    rationale: str
    detector_version: str = BEHAVIOR_LOGIC_VERSION

    @property
    def title(self) -> str:
        return DETECTORS[self.detector_id]


@dataclass
class BehaviorResult:
    indicators: list[Indicator] = field(default_factory=list)
    coverage_gaps: list[dict[str, str]] = field(default_factory=list)


def network_of(ip: str) -> str | None:
    """Collapse an address to its /24 (IPv4) or /64 (IPv6) network."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    prefix = 24 if addr.version == 4 else 64
    return str(ipaddress.ip_network(f"{addr}/{prefix}", strict=False))


def _strength(baseline_size: int, scale: float) -> float:
    """Grows with the amount of history: more evidence of 'normal' = stronger anomaly."""
    return round(min(0.95, 1 - 1 / (1 + baseline_size / scale)), 3)


def _successful_logons(events: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    by_user: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in events:
        if e["event_type"] == "auth.logon_success" and e.get("username"):
            by_user[e["username"]].append(e)
    for items in by_user.values():
        items.sort(key=lambda e: (e["timestamp"], e["id"]))
    return by_user


def new_logon_network(
    events: list[dict[str, Any]], cfg: BehaviorConfig, out: BehaviorResult
) -> None:
    """BH-001: successful logon from a network never seen in the user's prior logons.

    Single pass per user (O(n)): the baseline is the running set of networks seen so far.
    """
    for user, logons in _successful_logons(events).items():
        evaluated = False
        known: set[str] = set()
        for prior_count, e in enumerate(logons):
            net = network_of(e.get("src_ip") or "")
            if net is not None and prior_count >= cfg.min_baseline_logons:
                evaluated = True
                if net not in known:
                    out.indicators.append(
                        Indicator(
                            detector_id="BH-001",
                            entity=f"user:{user}",
                            score=_strength(prior_count, 10),
                            fingerprint=e["id"],
                            event_ids=[e["id"]],
                            observed_at=e["timestamp"],
                            baseline={
                                "prior_successful_logons": prior_count,
                                "known_networks": sorted(known)[:10],
                            },
                            rationale=(
                                f"'{user}' logged on successfully from {e.get('src_ip')} "
                                f"({net}); none of their {prior_count} earlier successful "
                                "logons came from this network."
                            ),
                        )
                    )
            if net is not None:
                known.add(net)  # this logon becomes history for the next one
        if not evaluated and logons:
            _gap(
                out,
                cfg,
                "BH-001",
                f"user:{user}",
                f"{len(logons)} successful logon(s); {cfg.min_baseline_logons + 1}+ needed "
                "to judge a new source network",
            )


def off_hours_logon(events: list[dict[str, Any]], cfg: BehaviorConfig, out: BehaviorResult) -> None:
    """BH-003: successful logon outside the user's previously observed UTC hours.

    Single pass per user (O(n)): the baseline is the running min/max hour seen so far.
    """
    for user, logons in _successful_logons(events).items():
        evaluated = False
        lo_seen, hi_seen = 24, -1
        for prior_count, e in enumerate(logons):
            hour = from_iso(e["timestamp"]).hour
            if prior_count >= cfg.min_hour_baseline:
                evaluated = True
                lo, hi = lo_seen - cfg.hour_tolerance, hi_seen + cfg.hour_tolerance
                if not lo <= hour <= hi:
                    out.indicators.append(
                        Indicator(
                            detector_id="BH-003",
                            entity=f"user:{user}",
                            score=_strength(prior_count, 15),
                            fingerprint=e["id"],
                            event_ids=[e["id"]],
                            observed_at=e["timestamp"],
                            baseline={
                                "prior_successful_logons": prior_count,
                                "observed_hours_utc": [lo_seen, hi_seen],
                            },
                            rationale=(
                                f"'{user}' logged on at {hour:02d}:00 UTC; their {prior_count} "
                                f"earlier logons were between {lo_seen:02d}:00 and "
                                f"{hi_seen:02d}:59 UTC. Time zones, travel and shift work "
                                "can explain this."
                            ),
                        )
                    )
            lo_seen, hi_seen = min(lo_seen, hour), max(hi_seen, hour)
        if not evaluated and logons:
            _gap(
                out,
                cfg,
                "BH-003",
                f"user:{user}",
                f"{len(logons)} successful logon(s); {cfg.min_hour_baseline + 1}+ needed to "
                "learn active hours",
            )


def rare_process(events: list[dict[str, Any]], cfg: BehaviorConfig, out: BehaviorResult) -> None:
    """BH-002: process image seen at most N times on a host with a meaningful history."""
    by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in events:
        if e["event_type"] == "process.create" and e.get("host") and e.get("process_name"):
            by_host[e["host"]].append(e)
    for host, procs in by_host.items():
        if len(procs) < cfg.min_host_process_events:
            _gap(
                out,
                cfg,
                "BH-002",
                f"host:{host}",
                f"{len(procs)} process event(s); {cfg.min_host_process_events} needed for a "
                "process baseline",
            )
            continue
        names = [PureWindowsPath(p["process_name"]).name.lower() for p in procs]
        counts = Counter(names)
        for p, name in zip(procs, names, strict=True):
            if counts[name] > cfg.rare_process_max_count:
                continue
            out.indicators.append(
                Indicator(
                    detector_id="BH-002",
                    entity=f"host:{host}",
                    score=_strength(len(procs), 30),
                    fingerprint=p["id"],
                    event_ids=[p["id"]],
                    observed_at=p["timestamp"],
                    baseline={
                        "process_events_on_host": len(procs),
                        "times_seen": counts[name],
                        "distinct_processes": len(counts),
                    },
                    rationale=(
                        f"'{name}' ran {counts[name]} time(s) among {len(procs)} process "
                        f"events on {host} ({len(counts)} distinct programs). Rare is not "
                        "the same as malicious."
                    ),
                )
            )


def _gap(out: BehaviorResult, cfg: BehaviorConfig, detector: str, entity: str, reason: str) -> None:
    if len(out.coverage_gaps) < cfg.max_coverage_gaps:
        out.coverage_gaps.append({"detector": detector, "entity": entity, "reason": reason})


def analyze(events: list[dict[str, Any]], cfg: BehaviorConfig | None = None) -> BehaviorResult:
    cfg = cfg or BehaviorConfig()
    out = BehaviorResult()
    new_logon_network(events, cfg, out)
    rare_process(events, cfg, out)
    off_hours_logon(events, cfg, out)
    out.indicators.sort(key=lambda i: (i.observed_at, i.detector_id, i.fingerprint))
    return out


def describe(cfg: BehaviorConfig) -> dict[str, str]:
    return {
        "BH-001": f"{DETECTORS['BH-001']}: logon from a /24 (IPv6 /64) not seen in the user's "
        f"earlier successful logons; needs >= {cfg.min_baseline_logons} earlier logons.",
        "BH-002": f"{DETECTORS['BH-002']}: program seen <= {cfg.rare_process_max_count} time(s) "
        f"on a host with >= {cfg.min_host_process_events} process events.",
        "BH-003": f"{DETECTORS['BH-003']}: logon more than {cfg.hour_tolerance}h outside the "
        f"user's earlier UTC logon hours; needs >= {cfg.min_hour_baseline} earlier "
        "logons.",
    }


def strength_label(score: float) -> str:
    return "strong" if score >= 0.75 else "moderate" if score >= 0.5 else "weak"


__all__ = ["BehaviorConfig", "BehaviorResult", "Indicator", "analyze", "describe"]
