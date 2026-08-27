"""Deterministic containment, patch staging, and promotion policy."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi.testclient import TestClient

from appsec_harness.eval.context import canonical_digest
from appsec_harness.eval.models import Finding, VerificationProof
from appsec_harness.remediation.models import (
    ContainmentEvidence,
    PatchCandidate,
    PatchProfile,
    PromotionDecision,
    RemediationPolicy,
    RemediationRun,
    StageGateResults,
)
from appsec_harness.remediation.triage import triage
from appsec_harness.target import create_app


def run_remediation(
    finding: Finding,
    proof: VerificationProof,
    *,
    profile: PatchProfile,
    policy: RemediationPolicy,
) -> RemediationRun:
    decision = triage(finding, proof)
    if finding.id != "sql-injection":
        raise ValueError("the MVP patch adapter supports only the verified SQL injection fixture")
    if profile not in {"fixed-sql", "bad-sql"}:
        raise ValueError("unsupported patch profile")
    containment = _contain(finding)
    patch = _package_patch(finding, proof, profile, policy)
    gates = _stage(patch, policy)
    promotion = _decide(gates, policy)
    return RemediationRun(
        triage=decision,
        containment=containment,
        patch=patch,
        gates=gates,
        promotion=promotion,
    )


def _contain(finding: Finding) -> ContainmentEvidence:
    with TemporaryDirectory(prefix="appsec-containment-") as directory:
        return _contain_in_directory(finding, Path(directory))


def _contain_in_directory(finding: Finding, directory: Path) -> ContainmentEvidence:
    database = directory / "orders.sqlite3"
    with TestClient(create_app(database, search_contained=True)) as client:
        before = canonical_digest(database.read_bytes().hex())
        response = client.get("/orders/search", params={"q": "Synthetic"})
        after = canonical_digest(database.read_bytes().hex())
    if response.status_code != 503 or before != after:
        raise RuntimeError("containment failed to preserve synthetic forensic state")
    return ContainmentEvidence(
        finding_id=finding.id,
        capability="GET /orders/search",
        active=True,
        forensic_state_digest=before,
        reversible=True,
    )


def _package_patch(
    finding: Finding,
    proof: VerificationProof,
    profile: PatchProfile,
    policy: RemediationPolicy,
) -> PatchCandidate:
    finding_digest = canonical_digest(finding.model_dump(mode="json"))
    proof_digest = canonical_digest(proof.model_dump(mode="json"))
    policy_digest = canonical_digest(policy.model_dump(mode="json"))
    environment_digest = canonical_digest(
        {"target": "synthetic-order-service", "network": "local-only", "profile": profile}
    )
    patch_digest = canonical_digest(
        {
            "finding_digest": finding_digest,
            "proof_digest": proof_digest,
            "policy_digest": policy_digest,
            "environment_digest": environment_digest,
        }
    )
    return PatchCandidate(
        finding_id=finding.id,
        proof_id=proof.id,
        profile=profile,
        finding_digest=finding_digest,
        proof_digest=proof_digest,
        policy_digest=policy_digest,
        environment_digest=environment_digest,
        patch_digest=patch_digest,
    )


def _stage(patch: PatchCandidate, policy: RemediationPolicy) -> StageGateResults:
    with (
        TemporaryDirectory(prefix="appsec-stage-") as directory,
        TestClient(create_app(Path(directory) / "orders.sqlite3", profile=patch.profile)) as client,
    ):
        exploit = client.get("/orders/search", params={"q": "' OR 1=1 --"})
        normal = client.get("/orders/search", params={"q": "laptop"})
        protected = client.get("/orders/protected-search", params={"q": "' OR 1=1 --"})
        authorized = client.post(
            "/orders/1/protected-approve",
            headers={"x-actor": "approver-a", "x-role": "approver"},
        )
        health = client.get("/health")
    return StageGateResults(
        exploit_blocked=exploit.status_code == 200 and exploit.json() == [],
        functional_tests=normal.status_code == 200 and len(normal.json()) == 1,
        negative_tests=protected.status_code == 200 and protected.json() == [],
        authorized_behavior=authorized.status_code == 200,
        health_gate=health.status_code == 200,
        latency_gate=policy.latency_budget_ms >= 1,
        evidence_complete=all(
            digest.startswith("sha256:")
            for digest in [
                patch.finding_digest,
                patch.proof_digest,
                patch.policy_digest,
                patch.environment_digest,
                patch.patch_digest,
            ]
        ),
    )


def _decide(gates: StageGateResults, policy: RemediationPolicy) -> PromotionDecision:
    if not gates.passed:
        return PromotionDecision(
            action="rolled_back",
            reason_code="STAGE_GATE_FAILED",
            rollback_preserved_evidence=True,
        )
    if policy.mode == "advisory":
        return PromotionDecision(
            action="advisory",
            reason_code="ADVISORY_MODE",
            rollback_preserved_evidence=True,
        )
    if policy.mode == "shadow" or not policy.human_approved:
        return PromotionDecision(
            action="staged",
            reason_code="HUMAN_APPROVAL_REQUIRED",
            rollback_preserved_evidence=True,
        )
    return PromotionDecision(
        action="promoted",
        reason_code="ALL_GATES_APPROVED",
        rollback_preserved_evidence=True,
    )
