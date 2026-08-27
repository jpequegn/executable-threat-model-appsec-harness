"""High-recall deterministic discovery baseline."""

from __future__ import annotations

from appsec_harness.eval.context import DiscoveryContext
from appsec_harness.eval.models import DiscoveryRun, EvidenceRef, Finding

DISCOVERY_ADAPTER = "deterministic-discovery-v1"


def discover(context: DiscoveryContext, trial_id: str) -> DiscoveryRun:
    findings = [
        _finding(
            trial_id,
            "sql-injection",
            "OrderStore.search_vulnerable",
            "src/appsec_harness/target/store.py",
            "A search term may alter query structure and broaden returned synthetic orders.",
            "orders",
            0.97,
        ),
        _finding(
            trial_id,
            "authorization-state-mismatch",
            "POST /orders/{order_id}/approve",
            "src/appsec_harness/target/app.py",
            "A buyer may transition their own synthetic order to approved.",
            "approval-state",
            0.93,
        ),
        _finding(
            trial_id,
            "protected-search",
            "OrderStore.search_protected",
            "src/appsec_harness/target/store.py",
            "The protected search may still allow query-structure changes.",
            "orders",
            0.42,
        ),
        _finding(
            trial_id,
            "unreachable-debug-query",
            "unreachable_debug_query",
            "src/appsec_harness/target/dead_code.py",
            "An apparent raw query may be externally reachable.",
            "orders",
            0.36,
        ),
        _finding(
            trial_id,
            "clean-health",
            "GET /health",
            "src/appsec_harness/target/app.py",
            "The health response may expose protected state.",
            "orders",
            0.18,
        ),
        _finding(
            trial_id,
            "flaky-proof-control",
            "synthetic flaky verifier fixture",
            "fixtures/corpus/cases.json",
            "An unstable observation may indicate an invariant failure.",
            "orders",
            0.51,
        ),
    ]
    return DiscoveryRun(
        adapter=DISCOVERY_ADAPTER,
        input_digest=context.input_digest,
        allowed_paths=list(context.allowed_paths),
        denied_paths=list(context.denied_paths),
        findings=findings,
    )


def _finding(
    trial_id: str,
    finding_id: str,
    component: str,
    location: str,
    hypothesis: str,
    asset_id: str,
    confidence: float,
) -> Finding:
    return Finding(
        id=finding_id,
        trial_id=trial_id,
        component=component,
        location=location,
        hypothesis=hypothesis,
        attack_preconditions=["local synthetic target is running"],
        claimed_impact="synthetic invariant may be violated",
        asset_id=asset_id,
        evidence=[EvidenceRef(id="source", kind="source-location", uri=f"repo://{location}")],
        discovery_adapter=DISCOVERY_ADAPTER,
        confidence=confidence,
    )
