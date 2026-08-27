from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import duckdb
import pytest

from appsec_harness.eval.models import EvaluationRun
from appsec_harness.eval.runner import run_evaluation
from appsec_harness.remediation.models import RemediationPolicy
from appsec_harness.remediation.runner import run_remediation
from appsec_harness.reporting.models import RunMetadata, TrialBundle
from appsec_harness.reporting.store import EvidenceStore


def make_bundle(*, duration_ms: int | None = 250, notes: str = "") -> TrialBundle:
    evaluation = run_evaluation(Path.cwd())
    finding = next(item for item in evaluation.discovery.findings if item.id == "sql-injection")
    proof = next(
        result.proof for result in evaluation.verification if result.proof.finding_id == finding.id
    )
    remediation = run_remediation(
        finding,
        proof,
        profile="fixed-sql",
        policy=RemediationPolicy(mode="promote", human_approved=True),
    )
    return TrialBundle(
        evaluation=evaluation,
        remediation=remediation,
        metadata=RunMetadata(
            config_id="deterministic-baseline-v1",
            harness_version="0.1.0",
            evidence_date=date(2026, 8, 27),
            as_of_date=date(2026, 8, 27),
            reviewer_minutes=8,
            cost_micros=0,
            duration_ms=duration_ms,
            notes=notes,
        ),
    )


def test_import_is_idempotent_and_metrics_reconcile(tmp_path: Path) -> None:
    with EvidenceStore(tmp_path / "evidence.duckdb") as store:
        first = store.import_bundle(make_bundle())
        second = store.import_bundle(make_bundle())
        assert first.run_id == second.run_id
        assert store.table_count("runs") == 1
        assert store.table_count("findings") == 6
        metrics = {metric.name: metric for metric in first.metrics}
        assert metrics["discovery_recall"].numerator == 2
        assert metrics["discovery_recall"].denominator == 2
        assert metrics["precision_before_verification"].value == pytest.approx(2 / 6, abs=1e-6)
        assert metrics["precision_after_verification"].value == 1
        assert metrics["verified_findings_per_review_hour"].value == 15


def test_inconsistent_source_metrics_are_rejected(tmp_path: Path) -> None:
    bundle = make_bundle()
    tampered_evaluation = EvaluationRun.model_validate(bundle.evaluation.model_dump())
    tampered_evaluation.metrics.confirmed_cases = 99
    tampered = bundle.model_copy(update={"evaluation": tampered_evaluation})
    with EvidenceStore(tmp_path / "evidence.duckdb") as store:
        with pytest.raises(ValueError, match="does not reconcile"):
            store.import_bundle(tampered)
        assert store.table_count("runs") == 0


def test_unmeasured_values_remain_explicit(tmp_path: Path) -> None:
    with EvidenceStore(tmp_path / "evidence.duckdb") as store:
        packet = store.import_bundle(make_bundle(duration_ms=None))
    duration = next(metric for metric in packet.metrics if metric.name == "duration_ms")
    assert duration.value is None
    assert duration.measurement_status == "not_measured"
    assert any("duration_ms" in limitation for limitation in packet.limitations)


def test_reports_are_redacted_and_byte_stable(tmp_path: Path) -> None:
    bundle = make_bundle(notes="token=secret-value SYNTHETIC_CANARY_DO_NOT_EMIT_184")
    with EvidenceStore(tmp_path / "evidence.duckdb") as store:
        packet = store.import_bundle(bundle)
        first = tmp_path / "first"
        second = tmp_path / "second"
        store.write_packet(packet, first)
        store.write_packet(packet, second)
        stored_json = store.connection.execute("SELECT bundle_json FROM runs").fetchone()[0]
    assert (first / "assurance.json").read_bytes() == (second / "assurance.json").read_bytes()
    assert (first / "assurance.md").read_bytes() == (second / "assurance.md").read_bytes()
    assert "secret-value" not in stored_json
    assert "SYNTHETIC_CANARY_DO_NOT_EMIT_184" not in stored_json


def test_run_measurement_notes_are_disclosed(tmp_path: Path) -> None:
    with EvidenceStore(tmp_path / "evidence.duckdb") as store:
        packet = store.import_bundle(make_bundle(notes="Duration is a deterministic fixture."))
    assert "Run metadata: Duration is a deterministic fixture." in packet.limitations


def test_parquet_exports_are_queryable(tmp_path: Path) -> None:
    with EvidenceStore(tmp_path / "evidence.duckdb") as store:
        store.import_bundle(make_bundle())
        paths = store.export_parquet(tmp_path / "parquet")
    assert {path.name for path in paths} == {
        "runs.parquet",
        "metrics.parquet",
        "findings.parquet",
        "attributions.parquet",
        "patches.parquet",
    }
    connection = duckdb.connect()
    try:
        count = connection.execute(
            "SELECT COUNT(*) FROM read_parquet(?)", [str(tmp_path / "parquet/findings.parquet")]
        ).fetchone()[0]
    finally:
        connection.close()
    assert count == 6


def test_comparisons_disclose_sample_count_and_range(tmp_path: Path) -> None:
    with EvidenceStore(tmp_path / "evidence.duckdb") as store:
        first = store.import_bundle(make_bundle(duration_ms=200))
        second = store.import_bundle(make_bundle(duration_ms=300))
        packet = store.packet(second.run_id)
    duration = next(
        row
        for row in packet.comparisons
        if row.config_id == "deterministic-baseline-v1" and row.metric_name == "duration_ms"
    )
    assert first.run_id != second.run_id
    assert duration.samples == 2
    assert duration.mean == 250
    assert duration.minimum == 200
    assert duration.maximum == 300


def test_all_defect_categories_are_present(tmp_path: Path) -> None:
    with EvidenceStore(tmp_path / "evidence.duckdb") as store:
        packet = store.import_bundle(make_bundle())
    assert {row.category for row in packet.attributions} == {
        "agent",
        "environment",
        "policy",
        "reference",
        "grader",
    }
    flaky = next(row for row in packet.attributions if row.category == "grader")
    assert flaky.count == 1


def test_fixture_metadata_is_valid() -> None:
    metadata = RunMetadata.model_validate_json(
        Path("fixtures/reporting/demo-metadata.json").read_text()
    )
    assert json.loads(metadata.model_dump_json())["config_id"] == "deterministic-baseline-v1"
