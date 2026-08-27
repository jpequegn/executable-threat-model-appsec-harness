from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_harness.eval.context import build_discovery_context
from appsec_harness.eval.discovery import DISCOVERY_ADAPTER, discover
from appsec_harness.eval.runner import run_evaluation
from appsec_harness.eval.verifier import VERIFIER_ADAPTER, verify


def test_discovery_context_is_allowlisted_and_reference_free() -> None:
    context = build_discovery_context(Path.cwd())
    assert context.denied_paths == ("references/",)
    assert all(not path.startswith("references/") for path in context.allowed_paths)
    assert all("expected_status" not in content for content in context.content.values())
    assert context.input_digest.startswith("sha256:")


def test_context_builder_rejects_a_denied_discovery_input(tmp_path: Path) -> None:
    (tmp_path / "fixtures/corpus").mkdir(parents=True)
    (tmp_path / "references").mkdir()
    (tmp_path / "references/hidden.json").write_text("{}")
    (tmp_path / "fixtures/corpus/cases.json").write_text(
        json.dumps(
            {
                "discovery_inputs": ["references/hidden.json"],
                "denied_discovery_paths": ["references/"],
            }
        )
    )
    with pytest.raises(ValueError, match="denied path"):
        build_discovery_context(tmp_path)


def test_discovery_findings_have_no_severity_and_use_separate_identity() -> None:
    run = discover(build_discovery_context(Path.cwd()), "test-run")
    assert run.adapter == DISCOVERY_ADAPTER
    assert len(run.findings) == 6
    assert all("severity" not in finding.model_dump() for finding in run.findings)
    assert all(finding.discovery_adapter != VERIFIER_ADAPTER for finding in run.findings)


def test_independent_verifier_confirms_rejects_and_detects_flakiness() -> None:
    result = run_evaluation(Path.cwd())
    statuses = {item.proof.finding_id: item.proof.status for item in result.verification}
    reasons = {item.proof.finding_id: item.proof.reason_code for item in result.verification}

    assert statuses == {
        "sql-injection": "confirmed",
        "authorization-state-mismatch": "confirmed",
        "protected-search": "rejected",
        "unreachable-debug-query": "rejected",
        "clean-health": "rejected",
        "flaky-proof-control": "flaky",
    }
    assert reasons["protected-search"] == "CONTROL_EFFECTIVE"
    assert reasons["unreachable-debug-query"] == "UNREACHABLE"
    assert reasons["clean-health"] == "NO_INVARIANT_FAILURE"
    assert reasons["flaky-proof-control"] == "FLAKY_PROOF"
    for item in result.verification:
        assert item.proof.verifier_adapter == VERIFIER_ADAPTER
        assert item.proof.verifier_input_digest != item.proof.discovery_input_digest
        assert item.proof.environment_id.startswith("clean-")


def test_black_box_authorization_partial_grade_records_progress() -> None:
    result = run_evaluation(Path.cwd())
    authorization = next(
        item
        for item in result.verification
        if item.proof.finding_id == "authorization-state-mismatch"
    )
    assert authorization.partial_grade is not None
    assert authorization.partial_grade.score == 3
    assert authorization.partial_grade.reproduced_invariant_failure is True
    assert authorization.partial_grade.regression_preserved is False


def test_verification_improves_precision_without_losing_recall() -> None:
    metrics = run_evaluation(Path.cwd()).metrics
    assert metrics.discovery_recall == 1.0
    assert metrics.precision_before_verification == pytest.approx(2 / 6, abs=1e-6)
    assert metrics.precision_after_verification == 1.0
    assert metrics.confirmed_cases == 2
    assert metrics.rejected_cases == 3
    assert metrics.flaky_cases == 1


def test_evaluation_is_byte_stable_and_sanitized() -> None:
    first = run_evaluation(Path.cwd()).model_dump_json()
    second = run_evaluation(Path.cwd()).model_dump_json()
    assert first == second
    assert "SYNTHETIC_CANARY_DO_NOT_EMIT_184" not in first
    assert "' OR 1=1 --" not in first


def test_verifier_rejects_unknown_discovery_identity() -> None:
    discovery = discover(build_discovery_context(Path.cwd()), "test-run")
    finding = discovery.findings[0].model_copy(update={"discovery_adapter": "self-grading-adapter"})
    with pytest.raises(ValueError, match="identity"):
        verify(finding, discovery.input_digest)
