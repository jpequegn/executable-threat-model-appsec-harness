"""Typed inputs and outputs for durable assurance reporting."""

from __future__ import annotations

from datetime import date

from pydantic import BaseModel, ConfigDict, Field

from appsec_harness.eval.models import EvaluationRun
from appsec_harness.remediation.models import RemediationRun


class ClosedModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RunMetadata(ClosedModel):
    config_id: str
    harness_version: str
    evidence_date: date
    as_of_date: date
    reviewer_minutes: float | None = Field(default=None, ge=0)
    cost_micros: int | None = Field(default=None, ge=0)
    duration_ms: int | None = Field(default=None, ge=0)
    notes: str = ""


class TrialBundle(ClosedModel):
    evaluation: EvaluationRun
    remediation: RemediationRun
    metadata: RunMetadata


class MetricRecord(ClosedModel):
    name: str
    numerator: float | None
    denominator: float | None
    value: float | None
    unit: str
    measurement_status: str


class AttributionRecord(ClosedModel):
    category: str
    code: str
    count: int
    explanation: str


class ComparisonRecord(ClosedModel):
    config_id: str
    metric_name: str
    samples: int
    mean: float
    minimum: float
    maximum: float


class AssurancePacket(ClosedModel):
    schema_version: str = "appsec-harness.dev/assurance/v1"
    run_id: str
    trial_id: str
    config_id: str
    evidence_date: date
    evidence_age_days: int
    manifest_digest: str
    metrics: list[MetricRecord]
    attributions: list[AttributionRecord]
    comparisons: list[ComparisonRecord]
    promotion_action: str
    evidence_complete: bool
    limitations: list[str]
