"""Independent deterministic verifier for the synthetic target corpus."""

from __future__ import annotations

import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi.testclient import TestClient

from appsec_harness.eval.context import canonical_digest
from appsec_harness.eval.discovery import DISCOVERY_ADAPTER
from appsec_harness.eval.models import (
    EvidenceRef,
    Finding,
    PartialGrade,
    VerificationProof,
    VerificationResult,
    VerificationStatus,
)
from appsec_harness.target import create_app

VERIFIER_ADAPTER = "deterministic-verifier-v1"


def verify(finding: Finding, discovery_input_digest: str, attempts: int = 3) -> VerificationResult:
    if finding.discovery_adapter != DISCOVERY_ADAPTER:
        raise ValueError("finding discovery identity is not permitted")
    if finding.discovery_adapter == VERIFIER_ADAPTER:
        raise ValueError("discovery and verifier identities must differ")
    verifier_input = {
        "finding": finding.model_dump(mode="json"),
        "permitted_context": ["candidate-finding", "threat-model", "synthetic-interface"],
        "denied_context": ["discovery-reasoning", "references/"],
        "attempts": attempts,
    }
    verifier_digest = canonical_digest(verifier_input)
    if verifier_digest == discovery_input_digest:
        raise ValueError("verifier and discovery inputs must differ")

    outcomes: list[bool] = []
    partial_grade: PartialGrade | None = None
    for attempt in range(attempts):
        outcome, grade = _attempt(finding, attempt)
        outcomes.append(outcome)
        partial_grade = grade or partial_grade

    status, reason = _verdict(finding.id, outcomes)
    observed = _observed_summary(finding.id, status)
    proof_material = {
        "finding_id": finding.id,
        "status": status,
        "reason_code": reason,
        "outcomes": outcomes,
    }
    artifact_digest = canonical_digest(proof_material)
    proof = VerificationProof(
        id=f"proof-{finding.id}",
        finding_id=finding.id,
        environment_id=f"clean-{finding.id}-attempts-{attempts}",
        verifier_adapter=VERIFIER_ADAPTER,
        verifier_input_digest=verifier_digest,
        discovery_input_digest=discovery_input_digest,
        status=status,
        reason_code=reason,
        observed=observed,
        expected="The declared security invariant remains satisfied.",
        artifact_digest=artifact_digest,
        checks=[
            EvidenceRef(
                id="local-check",
                kind="deterministic-check",
                uri=f"check://synthetic/{finding.id}",
                digest="sha256:" + hashlib.sha256(str(outcomes).encode()).hexdigest(),
            )
        ],
    )
    return VerificationResult(proof=proof, partial_grade=partial_grade)


def _attempt(finding: Finding, attempt: int) -> tuple[bool, PartialGrade | None]:
    if finding.id == "flaky-proof-control":
        return attempt % 2 == 0, None
    with (
        TemporaryDirectory(prefix="appsec-verifier-") as directory,
        TestClient(create_app(Path(directory) / "orders.sqlite3")) as client,
    ):
        if finding.id == "sql-injection":
            baseline = client.get("/orders/search", params={"q": "no-literal-match"})
            changed = client.get("/orders/search", params={"q": "' OR 1=1 --"})
            return baseline.json() == [] and len(changed.json()) == 3, None
        if finding.id == "authorization-state-mismatch":
            response = client.post("/orders/1/approve", headers={"x-actor": "buyer-a"})
            reproduced = response.status_code == 200
            return reproduced, PartialGrade(
                correct_asset_role_hypothesis=True,
                valid_local_evidence_request=True,
                reproduced_invariant_failure=reproduced,
                regression_preserved=False,
            )
        if finding.id == "protected-search":
            response = client.get("/orders/protected-search", params={"q": "' OR 1=1 --"})
            return len(response.json()) > 0, None
        if finding.id == "unreachable-debug-query":
            return client.get("/debug/query").status_code != 404, None
        if finding.id == "clean-health":
            response = client.get("/health")
            return response.status_code != 200 or set(response.json()) != {
                "status",
                "scope",
            }, None
    return False, None


def _verdict(finding_id: str, outcomes: list[bool]) -> tuple[VerificationStatus, str]:
    if any(outcomes) and not all(outcomes):
        return "flaky", "FLAKY_PROOF"
    if all(outcomes):
        return "confirmed", "INVARIANT_REPRODUCED"
    reasons = {
        "protected-search": "CONTROL_EFFECTIVE",
        "unreachable-debug-query": "UNREACHABLE",
        "clean-health": "NO_INVARIANT_FAILURE",
    }
    return "rejected", reasons.get(finding_id, "NOT_REPRODUCIBLE")


def _observed_summary(finding_id: str, status: str) -> str:
    if status == "confirmed":
        return f"A sanitized local check reproduced the {finding_id} invariant failure."
    if status == "flaky":
        return "Repeated clean environments produced inconsistent outcomes."
    return f"Repeated clean environments rejected {finding_id} with no invariant failure."
