"""Typed remediation decisions and release-gate evidence."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

PatchProfile = Literal["fixed-sql", "bad-sql"]
Severity = Literal["low", "medium", "high", "critical", "unknown"]


class ClosedModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TriageDecision(ClosedModel):
    finding_id: str
    proof_id: str
    asset_sensitivity: str
    reachability: str
    tenant_scope: str
    preconditions: list[str]
    control_evidence: list[str]
    unknowns: list[str]
    severity: Severity
    priority: int
    reviewer_status: Literal["unreviewed", "approved", "rejected", "disputed"]


class ContainmentEvidence(ClosedModel):
    finding_id: str
    capability: str
    active: bool
    forensic_state_digest: str
    reversible: bool


class PatchCandidate(ClosedModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: str
    proof_id: str
    profile: PatchProfile
    finding_digest: str
    proof_digest: str
    policy_digest: str
    environment_digest: str
    patch_digest: str


class StageGateResults(ClosedModel):
    exploit_blocked: bool
    functional_tests: bool
    negative_tests: bool
    authorized_behavior: bool
    health_gate: bool
    latency_gate: bool
    evidence_complete: bool

    @property
    def passed(self) -> bool:
        return all(self.model_dump().values())


class RemediationPolicy(ClosedModel):
    mode: Literal["advisory", "shadow", "promote"] = "advisory"
    human_approved: bool = False
    github_writes_enabled: bool = False
    latency_budget_ms: int = 500


class PromotionDecision(ClosedModel):
    action: Literal["advisory", "staged", "promoted", "rolled_back"]
    reason_code: str
    rollback_preserved_evidence: bool


class RemediationRun(ClosedModel):
    triage: TriageDecision
    containment: ContainmentEvidence
    patch: PatchCandidate
    gates: StageGateResults
    promotion: PromotionDecision
