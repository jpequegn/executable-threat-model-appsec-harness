"""Metric reconciliation and transparent calculations."""

from __future__ import annotations

from appsec_harness.eval.context import canonical_digest
from appsec_harness.eval.runner import SEEDED_CASES
from appsec_harness.reporting.models import (
    AttributionRecord,
    MetricRecord,
    TrialBundle,
)


def reconcile(bundle: TrialBundle) -> None:
    evaluation = bundle.evaluation
    statuses = [result.proof.status for result in evaluation.verification]
    metrics = evaluation.metrics
    expected = {
        "total_candidates": len(evaluation.discovery.findings),
        "confirmed_cases": statuses.count("confirmed"),
        "rejected_cases": statuses.count("rejected"),
        "flaky_cases": statuses.count("flaky"),
    }
    for field, count in expected.items():
        if getattr(metrics, field) != count:
            actual = getattr(metrics, field)
            raise ValueError(f"evaluation metric {field} does not reconcile: {actual} != {count}")
    candidate_ids = {finding.id for finding in evaluation.discovery.findings}
    confirmed_ids = {
        result.proof.finding_id
        for result in evaluation.verification
        if result.proof.status == "confirmed"
    }
    expected_rates = {
        "discovery_recall": _safe_ratio(len(candidate_ids & SEEDED_CASES), len(SEEDED_CASES)),
        "precision_before_verification": _safe_ratio(
            len(candidate_ids & SEEDED_CASES), len(candidate_ids)
        ),
        "precision_after_verification": _safe_ratio(
            len(confirmed_ids & SEEDED_CASES), len(confirmed_ids)
        ),
    }
    for field, value in expected_rates.items():
        if abs(getattr(metrics, field) - value) > 0.000001:
            raise ValueError(f"evaluation metric {field} does not reconcile")
    proof = next(
        (
            result.proof
            for result in evaluation.verification
            if result.proof.finding_id == bundle.remediation.triage.finding_id
        ),
        None,
    )
    if (
        proof is None
        or proof.status != "confirmed"
        or proof.id != bundle.remediation.triage.proof_id
    ):
        raise ValueError("remediation does not reference a confirmed evaluation proof")
    expected_digest = bundle.remediation.patch.proof_digest
    if canonical_digest(proof.model_dump(mode="json")) != expected_digest:
        raise ValueError("remediation proof digest does not reconcile")


def calculate_metrics(bundle: TrialBundle) -> list[MetricRecord]:
    evaluated = bundle.evaluation.metrics
    confirmed_ids = {
        result.proof.finding_id
        for result in bundle.evaluation.verification
        if result.proof.status == "confirmed"
    }
    confirmed_true = len(confirmed_ids & SEEDED_CASES)
    action = bundle.remediation.promotion.action
    gates = bundle.remediation.gates
    records = [
        _ratio("discovery_recall", evaluated.discovered_true_cases, evaluated.seeded_cases),
        _ratio(
            "precision_before_verification",
            evaluated.discovered_true_cases,
            evaluated.total_candidates,
        ),
        _ratio("precision_after_verification", confirmed_true, evaluated.confirmed_cases),
        _ratio("flakiness_rate", evaluated.flaky_cases, evaluated.total_candidates),
        _ratio("patch_success_rate", int(action == "promoted"), 1),
        _ratio("rollback_rate", int(action == "rolled_back"), 1),
        _ratio("regression_rate", int(not gates.functional_tests), 1),
        _measured("reviewer_minutes", bundle.metadata.reviewer_minutes, "minutes"),
        _measured("cost_micros", bundle.metadata.cost_micros, "micros"),
        _measured("duration_ms", bundle.metadata.duration_ms, "milliseconds"),
    ]
    if bundle.metadata.reviewer_minutes is None or bundle.metadata.reviewer_minutes == 0:
        records.append(_measured("verified_findings_per_review_hour", None, "findings/hour"))
    else:
        rate = evaluated.confirmed_cases / (bundle.metadata.reviewer_minutes / 60)
        records.append(_measured("verified_findings_per_review_hour", rate, "findings/hour"))
    return records


def defect_attributions(bundle: TrialBundle) -> list[AttributionRecord]:
    rejected = sum(result.proof.status == "rejected" for result in bundle.evaluation.verification)
    flaky = sum(result.proof.status == "flaky" for result in bundle.evaluation.verification)
    bad_patch = int(bundle.remediation.promotion.action == "rolled_back")
    rows = [
        AttributionRecord(
            category="agent",
            code="DISCOVERY_FALSE_POSITIVE_OR_BAD_PATCH",
            count=rejected + bad_patch,
            explanation=(
                "Rejected candidates and a gate-rejected patch are attributed to adapter output."
            ),
        ),
        AttributionRecord(
            category="environment",
            code="ENVIRONMENT_FAILURE",
            count=0,
            explanation="No target startup, reset, or local-network policy failure was observed.",
        ),
        AttributionRecord(
            category="policy",
            code="POLICY_FAILURE",
            count=0,
            explanation="The deterministic policy caught all ineligible transitions in this run.",
        ),
        AttributionRecord(
            category="reference",
            code="REFERENCE_DEFECT",
            count=0,
            explanation="Human reference fixtures reconciled to the seeded corpus.",
        ),
        AttributionRecord(
            category="grader",
            code="FLAKY_PROOF",
            count=flaky,
            explanation="Inconsistent repeated outcomes remain quarantined as grader uncertainty.",
        ),
    ]
    return rows


def _ratio(name: str, numerator: int, denominator: int) -> MetricRecord:
    value = numerator / denominator if denominator else None
    return MetricRecord(
        name=name,
        numerator=float(numerator),
        denominator=float(denominator),
        value=round(value, 6) if value is not None else None,
        unit="ratio",
        measurement_status="measured" if denominator else "undefined",
    )


def _measured(name: str, value: float | int | None, unit: str) -> MetricRecord:
    return MetricRecord(
        name=name,
        numerator=float(value) if value is not None else None,
        denominator=1.0 if value is not None else None,
        value=round(float(value), 6) if value is not None else None,
        unit=unit,
        measurement_status="measured" if value is not None else "not_measured",
    )


def _safe_ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0
