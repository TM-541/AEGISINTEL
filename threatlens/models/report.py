"""Schema for AI-generated investigation reports.

The model must return JSON matching ``InvestigationReport`` exactly (``extra='forbid'``).
Field length and list caps bound the output size. Semantic checks (that evidence IDs exist,
that ATT&CK IDs are valid) are done in code by ``services.investigation.validate``.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

EventIds = Annotated[list[Annotated[str, Field(max_length=40)]], Field(min_length=1, max_length=20)]
Short = Annotated[str, Field(min_length=1, max_length=400)]


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Sufficiency(StrEnum):
    SUFFICIENT = "sufficient"
    PARTIAL = "partial"
    INSUFFICIENT = "insufficient"


class SimulatedAction(StrEnum):
    """The only response actions that may be proposed. All are simulated in this version."""

    ESCALATE_INCIDENT = "escalate_incident"
    PREPARE_CHECKLIST = "prepare_investigation_checklist"
    CONTAINMENT_PLAN = "generate_containment_plan"
    SIMULATE_ACCOUNT_DISABLE = "simulate_account_disable"
    SIMULATE_HOST_ISOLATION = "simulate_host_isolation"
    SIMULATE_PASSWORD_RESET = "simulate_password_reset"  # nosec B105 # noqa: S105 - action name


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class TimelineEntry(_Strict):
    description: Short
    event_ids: EventIds


class Observation(_Strict):
    statement: Short
    event_ids: EventIds


class Hypothesis(_Strict):
    statement: Short
    confidence: Confidence
    supporting_event_ids: EventIds


class Recommendation(_Strict):
    action_type: SimulatedAction
    target: Annotated[str, Field(min_length=1, max_length=128)]
    rationale: Short
    event_ids: EventIds


class SuggestedTechnique(_Strict):
    technique_id: Annotated[str, Field(max_length=12)]
    rationale: Short
    confidence: Confidence
    event_ids: EventIds


class InvestigationReport(_Strict):
    summary: Annotated[str, Field(min_length=1, max_length=1500)]
    evidence_sufficiency: Sufficiency
    timeline: Annotated[list[TimelineEntry], Field(max_length=30)]
    observations: Annotated[list[Observation], Field(max_length=15)]
    hypotheses: Annotated[list[Hypothesis], Field(max_length=10)]
    alternative_explanations: Annotated[list[Short], Field(max_length=8)]
    missing_evidence: Annotated[list[Short], Field(max_length=10)]
    next_steps: Annotated[list[Short], Field(max_length=10)]
    containment_recommendations: Annotated[list[Recommendation], Field(max_length=6)]
    attack_techniques: Annotated[list[SuggestedTechnique], Field(max_length=8)]
