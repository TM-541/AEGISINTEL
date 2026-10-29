"""Deterministic incident assessment and linking (pure functions, no I/O).

Severity, confidence, detection status and disposition are deliberately separate:

* **Severity**: the potential impact if the activity is malicious. Taken from rules; never
  changed by AI or by this module.
* **Confidence**: how strongly the evidence supports the incident. Computed here from how
  many *independent* signal types agree.
* **Detection status**: how the incident was found (rule, behaviour only, analyst flag).
* **Disposition**: the analyst's verdict. Only a human sets it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta

from threatlens.timeutil import from_iso

LINK_MAX_GAP = timedelta(hours=2)


@dataclass(frozen=True)
class Evidence:
    sigma_rules: int = 0
    correlation_rules: int = 0
    behavior_indicators: int = 0
    analyst_flagged: bool = False


def detection_status(ev: Evidence, current: str) -> str:
    if ev.sigma_rules or ev.correlation_rules:
        return "known_detection"
    if current == "suspicious_unmatched":  # analyst-raised: keep that provenance
        return current
    return "anomalous_behavior" if ev.behavior_indicators else current


def assess_confidence(ev: Evidence) -> tuple[str, str]:
    """Return (confidence, plain-English rationale)."""
    kinds = [
        name
        for name, present in (
            ("Sigma rule match", ev.sigma_rules),
            ("correlation rule", ev.correlation_rules),
            ("behavioural anomaly", ev.behavior_indicators),
        )
        if present
    ]
    distinct_rules = ev.sigma_rules + ev.correlation_rules
    if len(kinds) >= 2:
        return "high", f"Independent signal types agree: {', '.join(kinds)}."
    if distinct_rules >= 3:
        return "high", f"{distinct_rules} distinct detection rules matched."
    if distinct_rules >= 1:
        return "medium", (
            f"{distinct_rules} detection rule(s) matched; no independent corroborating signal type."
        )
    if ev.behavior_indicators:
        return "low", (
            f"{ev.behavior_indicators} behavioural anomaly indicator(s) only; no "
            "known detection matched. Unusual is not the same as malicious."
        )
    if ev.analyst_flagged:
        return "low", "Raised by an analyst for review; no automated signal attached yet."
    return "low", "No supporting automated signal."


@dataclass
class IncidentProfile:
    id: int
    first_seen: str
    last_seen: str
    entities: set[str] = field(default_factory=set)  # "user:x", "host:y", "ip:z"


@dataclass(frozen=True)
class Link:
    a: int
    b: int
    shared: tuple[str, ...]
    gap_minutes: int
    rationale: str


def find_links(profiles: list[IncidentProfile], max_gap: timedelta = LINK_MAX_GAP) -> list[Link]:
    """Pairs of incidents that share an entity and lie within ``max_gap`` of each other.

    A link is a lead for the analyst. Two incidents touching the same user or host close in
    time are not proof of the same actor, so the rationale says so explicitly.
    """
    ordered = sorted(profiles, key=lambda p: (p.first_seen, p.id))
    links: list[Link] = []
    for i, a in enumerate(ordered):
        a_end = from_iso(a.last_seen)
        for b in ordered[i + 1 :]:
            gap = from_iso(b.first_seen) - a_end
            if gap > max_gap:
                break  # sorted by start time: later ones are further away
            shared = sorted(a.entities & b.entities)
            if not shared:
                continue
            minutes = max(0, int(gap.total_seconds() // 60))
            lo, hi = sorted((a.id, b.id))
            links.append(
                Link(
                    lo,
                    hi,
                    tuple(shared),
                    minutes,
                    f"Share {', '.join(shared)}; {minutes} min apart. Possible relationship for "
                    "analyst review, not evidence of a common actor.",
                )
            )
    return links
