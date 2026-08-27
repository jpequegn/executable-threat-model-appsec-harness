"""Typed contracts for deterministic evaluation adapters."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "appsec-harness.dev/v1"
VerificationStatus = Literal["confirmed", "rejected", "flaky"]


class ClosedModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EvidenceRef(ClosedModel):
    id: str
    kind: str
    uri: str
    digest: str | None = None


class Finding(ClosedModel):
    schema_version: str = SCHEMA_VERSION
    id: str
    trial_id: str
    component: str
    location: str
    hypothesis: str
    attack_preconditions: list[str]
    claimed_impact: str
    asset_id: str
    evidence: list[EvidenceRef]
    discovery_adapter: str
    confidence: float = Field(ge=0, le=1)


class DiscoveryRun(ClosedModel):
    adapter: str
    input_digest: str
    allowed_paths: list[str]
    denied_paths: list[str]
    findings: list[Finding]


class PartialGrade(ClosedModel):
    correct_asset_role_hypothesis: bool
    valid_local_evidence_request: bool
    reproduced_invariant_failure: bool
    regression_preserved: bool

    @property
    def score(self) -> int:
        return sum(
            [
                self.correct_asset_role_hypothesis,
                self.valid_local_evidence_request,
                self.reproduced_invariant_failure,
                self.regression_preserved,
            ]
        )


class VerificationProof(ClosedModel):
    schema_version: str = SCHEMA_VERSION
    id: str
    finding_id: str
    environment_id: str
    verifier_adapter: str
    verifier_input_digest: str
    discovery_input_digest: str
    status: VerificationStatus
    reason_code: str
    observed: str
    expected: str
    artifact_digest: str | None = None
    checks: list[EvidenceRef]


class VerificationResult(ClosedModel):
    proof: VerificationProof
    partial_grade: PartialGrade | None = None


class EvaluationMetrics(ClosedModel):
    seeded_cases: int
    discovered_true_cases: int
    total_candidates: int
    confirmed_cases: int
    rejected_cases: int
    flaky_cases: int
    discovery_recall: float
    precision_before_verification: float
    precision_after_verification: float


class EvaluationRun(ClosedModel):
    schema_version: str = SCHEMA_VERSION
    trial_id: str
    discovery: DiscoveryRun
    verification: list[VerificationResult]
    metrics: EvaluationMetrics
