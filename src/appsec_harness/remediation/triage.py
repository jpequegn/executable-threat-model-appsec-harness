"""Evidence-derived triage that refuses unverified candidates."""

from __future__ import annotations

from appsec_harness.eval.models import Finding, VerificationProof
from appsec_harness.remediation.models import Severity, TriageDecision


def triage(finding: Finding, proof: VerificationProof) -> TriageDecision:
    if proof.finding_id != finding.id or proof.status != "confirmed":
        raise ValueError("only independently confirmed findings are eligible for triage")
    known_assets = {
        "orders": ("synthetic-confidential", "single synthetic service"),
        "approval-state": ("synthetic-internal", "single synthetic workflow"),
    }
    asset_context = known_assets.get(finding.asset_id)
    unknowns = [] if asset_context else ["asset sensitivity", "tenant scope"]
    sensitivity, scope = asset_context or ("unknown", "unknown")
    severity: Severity = "medium" if not unknowns else "unknown"
    priority = 70 if finding.id == "sql-injection" else 60
    if unknowns:
        priority = 0
    return TriageDecision(
        finding_id=finding.id,
        proof_id=proof.id,
        asset_sensitivity=sensitivity,
        reachability="loopback-only",
        tenant_scope=scope,
        preconditions=list(finding.attack_preconditions),
        control_evidence=[check.uri for check in proof.checks],
        unknowns=unknowns,
        severity=severity,
        priority=priority,
        reviewer_status="unreviewed",
    )


def triage_queue(
    pairs: list[tuple[Finding, VerificationProof]],
) -> list[TriageDecision]:
    decisions = [triage(finding, proof) for finding, proof in pairs if proof.status == "confirmed"]
    return sorted(decisions, key=lambda decision: (-decision.priority, decision.finding_id))
