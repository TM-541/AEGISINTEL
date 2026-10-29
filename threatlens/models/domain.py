"""Core domain enums and models."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class Role(StrEnum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)

    @classmethod
    def max(cls, *values: Severity) -> Severity:
        return max(values, key=lambda s: s.rank)


class IncidentStatus(StrEnum):
    NEW = "new"
    TRIAGE = "triage"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class Disposition(StrEnum):
    """The analyst's verdict. Separate from workflow status and never set automatically."""

    UNDETERMINED = "undetermined"
    TRUE_POSITIVE = "true_positive"
    BENIGN_CONFIRMED = "benign_confirmed"
    FALSE_POSITIVE = "false_positive"
    INCONCLUSIVE = "inconclusive"
    INSUFFICIENT_TELEMETRY = "insufficient_telemetry"


class DetectionStatus(StrEnum):
    KNOWN_DETECTION = "known_detection"
    ANOMALOUS_BEHAVIOR = "anomalous_behavior"
    SUSPICIOUS_UNMATCHED = "suspicious_unmatched"


class ProposalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    FAILED = "failed"


class User(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: int
    username: str
    display_name: str
    role: Role
    is_active: bool
    last_login_at: str | None = None
    created_at: str


class Principal(BaseModel):
    """The authenticated actor for one service call, always resolved from the DB."""

    model_config = ConfigDict(frozen=True)

    user_id: int
    username: str
    role: Role
