"""Deterministic, configurable correlation rules over normalized events.

These are plain functions over time-ordered event dicts. The same input always produces the
same findings, with the same fingerprints, so re-running detection is idempotent.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import timedelta
from typing import Any

from threatlens.models.domain import Severity
from threatlens.timeutil import from_iso

CORRELATION_LOGIC_VERSION = "1.1"


@dataclass(frozen=True)
class CorrelationConfig:
    brute_force_failures: int = 8
    brute_force_window_min: int = 10
    success_after_min: int = 15
    spray_distinct_users: int = 5
    spray_window_min: int = 15

    @property
    def version(self) -> str:
        """Rule logic version plus a fingerprint of the thresholds in effect."""
        cfg = json.dumps(asdict(self), sort_keys=True).encode()
        return f"{CORRELATION_LOGIC_VERSION}+cfg:{hashlib.sha256(cfg).hexdigest()[:8]}"


@dataclass
class Finding:
    rule_id: str
    rule_title: str
    engine: str  # 'sigma' | 'correlation'
    severity: Severity
    fingerprint: str
    event_ids: list[str]
    matched_fields: dict[str, Any]
    techniques: list[tuple[str, str]]  # (technique_id, confidence)
    rationale: str
    entity: str  # grouping key: user or host
    first_seen: str
    last_seen: str
    extra: dict[str, Any] = field(default_factory=dict)
    rule_version: str = ""


CORRELATION_RULES = {
    "TL-CR-001": "Brute force followed by successful logon",
    "TL-CR-002": "Password spraying from a single source",
    "TL-CR-003": "Repeated failed logons for one account",
}


def _failures(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [e for e in events if e["event_type"] == "auth.logon_failure"]


def brute_force(events: list[dict[str, Any]], cfg: CorrelationConfig) -> list[Finding]:
    """TL-CR-001 / TL-CR-003: >= N failures for a user within W minutes.

    If a success for that user from one of the failing source IPs follows within S minutes,
    emit CR-001 (likely compromise); otherwise CR-003.
    """
    by_user: dict[str, list[dict[str, Any]]] = defaultdict(list)
    successes: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in events:
        if not e.get("username"):
            continue
        if e["event_type"] == "auth.logon_failure":
            by_user[e["username"]].append(e)
        elif e["event_type"] == "auth.logon_success":
            successes[e["username"]].append(e)

    findings: list[Finding] = []
    window = timedelta(minutes=cfg.brute_force_window_min)
    for user, fails in by_user.items():
        i = 0
        while i < len(fails):
            start = from_iso(fails[i]["timestamp"])
            j = i
            while j + 1 < len(fails) and from_iso(fails[j + 1]["timestamp"]) - start <= window:
                j += 1
            burst = fails[i : j + 1]
            if len(burst) < cfg.brute_force_failures:
                i += 1
                continue
            last_fail = from_iso(burst[-1]["timestamp"])
            ips = {e.get("src_ip") for e in burst}
            success = next(
                (
                    s
                    for s in successes.get(user, [])
                    if last_fail
                    <= from_iso(s["timestamp"])
                    <= last_fail + timedelta(minutes=cfg.success_after_min)
                    and s.get("src_ip") in ips
                ),
                None,
            )
            ids = [e["id"] for e in burst] + ([success["id"]] if success else [])
            src = sorted(ip for ip in ips if ip)
            if success:
                findings.append(
                    Finding(
                        rule_id="TL-CR-001",
                        rule_title=CORRELATION_RULES["TL-CR-001"],
                        engine="correlation",
                        severity=Severity.HIGH,
                        fingerprint=f"{user}|{burst[0]['timestamp']}",
                        event_ids=ids,
                        matched_fields={
                            "username": user,
                            "failures": len(burst),
                            "src_ip": src,
                            "success_event": success["id"],
                        },
                        techniques=[("T1110.001", "medium"), ("T1078", "medium")],
                        rationale=(
                            f"{len(burst)} failed logons for '{user}' within "
                            f"{cfg.brute_force_window_min} min, then a successful logon "
                            f"from the same source ({', '.join(src)})."
                        ),
                        rule_version=cfg.version,
                        entity=f"user:{user}",
                        first_seen=burst[0]["timestamp"],
                        last_seen=success["timestamp"],
                    )
                )
            else:
                findings.append(
                    Finding(
                        rule_id="TL-CR-003",
                        rule_title=CORRELATION_RULES["TL-CR-003"],
                        engine="correlation",
                        severity=Severity.MEDIUM,
                        fingerprint=f"{user}|{burst[0]['timestamp']}",
                        event_ids=ids,
                        matched_fields={"username": user, "failures": len(burst), "src_ip": src},
                        techniques=[("T1110.001", "low")],
                        rationale=(
                            f"{len(burst)} failed logons for '{user}' within "
                            f"{cfg.brute_force_window_min} min; no subsequent success seen."
                        ),
                        rule_version=cfg.version,
                        entity=f"user:{user}",
                        first_seen=burst[0]["timestamp"],
                        last_seen=burst[-1]["timestamp"],
                    )
                )
            i = j + 1
    return findings


def password_spray(events: list[dict[str, Any]], cfg: CorrelationConfig) -> list[Finding]:
    """TL-CR-002: one source IP fails against >= N distinct accounts within W minutes."""
    by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in _failures(events):
        if e.get("src_ip") and e.get("username"):
            by_ip[e["src_ip"]].append(e)
    findings: list[Finding] = []
    window = timedelta(minutes=cfg.spray_window_min)
    for ip, fails in by_ip.items():
        i = 0
        while i < len(fails):
            start = from_iso(fails[i]["timestamp"])
            burst = [e for e in fails[i:] if from_iso(e["timestamp"]) - start <= window]
            users = sorted({e["username"] for e in burst})
            if len(users) >= cfg.spray_distinct_users:
                findings.append(
                    Finding(
                        rule_id="TL-CR-002",
                        rule_title=CORRELATION_RULES["TL-CR-002"],
                        engine="correlation",
                        severity=Severity.MEDIUM,
                        fingerprint=f"{ip}|{burst[0]['timestamp']}",
                        event_ids=[e["id"] for e in burst],
                        matched_fields={
                            "src_ip": ip,
                            "distinct_users": len(users),
                            "usernames": users,
                        },
                        techniques=[("T1110.003", "medium")],
                        rationale=(
                            f"Source {ip} failed to log on as {len(users)} different "
                            f"accounts within {cfg.spray_window_min} min."
                        ),
                        rule_version=cfg.version,
                        entity=f"ip:{ip}",
                        first_seen=burst[0]["timestamp"],
                        last_seen=burst[-1]["timestamp"],
                    )
                )
                i += len(burst)
            else:
                i += 1
    return findings
