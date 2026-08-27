from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from appsec_harness.eval.runner import run_evaluation
from appsec_harness.remediation.models import RemediationPolicy
from appsec_harness.remediation.runner import run_remediation
from appsec_harness.remediation.triage import triage, triage_queue


@pytest.fixture(scope="module")
def evaluation():  # type: ignore[no-untyped-def]
    return run_evaluation(Path.cwd())


def finding_and_proof(evaluation, finding_id: str):  # type: ignore[no-untyped-def]
    finding = next(item for item in evaluation.discovery.findings if item.id == finding_id)
    proof = next(
        item.proof for item in evaluation.verification if item.proof.finding_id == finding_id
    )
    return finding, proof


def test_triage_refuses_unverified_findings(evaluation) -> None:  # type: ignore[no-untyped-def]
    finding, proof = finding_and_proof(evaluation, "protected-search")
    with pytest.raises(ValueError, match="confirmed"):
        triage(finding, proof)


def test_triage_queue_prioritizes_verified_risk(evaluation) -> None:  # type: ignore[no-untyped-def]
    pairs = [
        finding_and_proof(evaluation, "authorization-state-mismatch"),
        finding_and_proof(evaluation, "protected-search"),
        finding_and_proof(evaluation, "sql-injection"),
    ]
    queue = triage_queue(pairs)
    assert [decision.finding_id for decision in queue] == [
        "sql-injection",
        "authorization-state-mismatch",
    ]
    assert all(decision.severity == "medium" for decision in queue)


def test_unknown_business_context_does_not_inflate_severity(evaluation) -> None:  # type: ignore[no-untyped-def]
    finding, proof = finding_and_proof(evaluation, "sql-injection")
    unknown = finding.model_copy(update={"asset_id": "unknown-asset"})
    decision = triage(unknown, proof)
    assert decision.severity == "unknown"
    assert decision.priority == 0
    assert decision.unknowns == ["asset sensitivity", "tenant scope"]


def test_good_patch_is_contained_staged_and_promoted_with_approval(evaluation) -> None:  # type: ignore[no-untyped-def]
    finding, proof = finding_and_proof(evaluation, "sql-injection")
    result = run_remediation(
        finding,
        proof,
        profile="fixed-sql",
        policy=RemediationPolicy(mode="promote", human_approved=True),
    )
    assert result.containment.active is True
    assert result.containment.reversible is True
    assert result.gates.passed is True
    assert result.gates.authorized_behavior is True
    assert result.promotion.action == "promoted"
    assert result.promotion.reason_code == "ALL_GATES_APPROVED"


def test_human_approval_is_required(evaluation) -> None:  # type: ignore[no-untyped-def]
    finding, proof = finding_and_proof(evaluation, "sql-injection")
    result = run_remediation(
        finding,
        proof,
        profile="fixed-sql",
        policy=RemediationPolicy(mode="promote", human_approved=False),
    )
    assert result.gates.passed is True
    assert result.promotion.action == "staged"
    assert result.promotion.reason_code == "HUMAN_APPROVAL_REQUIRED"


def test_bad_patch_rolls_back_and_preserves_evidence(evaluation) -> None:  # type: ignore[no-untyped-def]
    finding, proof = finding_and_proof(evaluation, "sql-injection")
    result = run_remediation(
        finding,
        proof,
        profile="bad-sql",
        policy=RemediationPolicy(mode="promote", human_approved=True),
    )
    assert result.gates.exploit_blocked is True
    assert result.gates.functional_tests is False
    assert result.promotion.action == "rolled_back"
    assert result.promotion.rollback_preserved_evidence is True


def test_advisory_mode_and_github_writes_default_off(evaluation) -> None:  # type: ignore[no-untyped-def]
    finding, proof = finding_and_proof(evaluation, "sql-injection")
    policy = RemediationPolicy()
    result = run_remediation(finding, proof, profile="fixed-sql", policy=policy)
    assert policy.github_writes_enabled is False
    assert result.promotion.action == "advisory"


def test_patch_candidate_is_immutable(evaluation) -> None:  # type: ignore[no-untyped-def]
    finding, proof = finding_and_proof(evaluation, "sql-injection")
    result = run_remediation(
        finding,
        proof,
        profile="fixed-sql",
        policy=RemediationPolicy(),
    )
    with pytest.raises(ValidationError):
        result.patch.profile = "bad-sql"
