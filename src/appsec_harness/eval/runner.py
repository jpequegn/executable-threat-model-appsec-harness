"""End-to-end deterministic discovery and independent verification runner."""

from __future__ import annotations

from pathlib import Path

from appsec_harness.eval.context import build_discovery_context
from appsec_harness.eval.discovery import discover
from appsec_harness.eval.models import EvaluationMetrics, EvaluationRun
from appsec_harness.eval.verifier import verify

SEEDED_CASES = {"sql-injection", "authorization-state-mismatch"}


def run_evaluation(root: Path, trial_id: str = "deterministic-baseline") -> EvaluationRun:
    context = build_discovery_context(root)
    discovery = discover(context, trial_id)
    verification = [verify(finding, discovery.input_digest) for finding in discovery.findings]
    candidate_ids = {finding.id for finding in discovery.findings}
    confirmed_ids = {
        result.proof.finding_id for result in verification if result.proof.status == "confirmed"
    }
    true_candidates = candidate_ids & SEEDED_CASES
    true_confirmed = confirmed_ids & SEEDED_CASES
    metrics = EvaluationMetrics(
        seeded_cases=len(SEEDED_CASES),
        discovered_true_cases=len(true_candidates),
        total_candidates=len(candidate_ids),
        confirmed_cases=len(confirmed_ids),
        rejected_cases=sum(result.proof.status == "rejected" for result in verification),
        flaky_cases=sum(result.proof.status == "flaky" for result in verification),
        discovery_recall=_ratio(len(true_candidates), len(SEEDED_CASES)),
        precision_before_verification=_ratio(len(true_candidates), len(candidate_ids)),
        precision_after_verification=_ratio(len(true_confirmed), len(confirmed_ids)),
    )
    return EvaluationRun(
        trial_id=trial_id,
        discovery=discovery,
        verification=verification,
        metrics=metrics,
    )


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0
