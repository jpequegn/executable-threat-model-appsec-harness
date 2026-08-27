"""Idempotent DuckDB evidence store with Parquet and assurance exports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import duckdb

from appsec_harness.eval.context import canonical_digest
from appsec_harness.reporting.metrics import calculate_metrics, defect_attributions, reconcile
from appsec_harness.reporting.models import (
    AssurancePacket,
    AttributionRecord,
    ComparisonRecord,
    MetricRecord,
    TrialBundle,
)
from appsec_harness.target.redaction import redact


class EvidenceStore:
    def __init__(self, database_path: Path) -> None:
        database_path.parent.mkdir(parents=True, exist_ok=True)
        self.database_path = database_path
        self.connection = duckdb.connect(str(database_path))
        self._create_schema()

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> EvidenceStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def import_bundle(self, bundle: TrialBundle) -> AssurancePacket:
        reconcile(bundle)
        sanitized = redact(bundle.model_dump(mode="json"))
        if not isinstance(sanitized, dict):
            raise TypeError("sanitized bundle must be an object")
        run_id = canonical_digest(sanitized)
        manifest_digest = canonical_digest(
            {
                "evaluation": sanitized["evaluation"],
                "remediation": sanitized["remediation"],
                "config_id": bundle.metadata.config_id,
            }
        )
        metrics = calculate_metrics(bundle)
        attributions = defect_attributions(bundle)
        self.connection.execute("BEGIN TRANSACTION")
        try:
            self.connection.execute(
                """
                INSERT OR REPLACE INTO runs
                (run_id, trial_id, config_id, evidence_date, as_of_date, manifest_digest,
                 harness_version, bundle_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    run_id,
                    bundle.evaluation.trial_id,
                    bundle.metadata.config_id,
                    bundle.metadata.evidence_date,
                    bundle.metadata.as_of_date,
                    manifest_digest,
                    bundle.metadata.harness_version,
                    json.dumps(sanitized, sort_keys=True, separators=(",", ":")),
                ],
            )
            for table in ["metrics", "findings", "attributions", "patches"]:
                self.connection.execute(f"DELETE FROM {table} WHERE run_id = ?", [run_id])
            self._insert_metrics(run_id, metrics)
            self._insert_findings(run_id, bundle)
            self._insert_attributions(run_id, attributions)
            self._insert_patch(run_id, bundle)
        except Exception:
            self.connection.execute("ROLLBACK")
            raise
        else:
            self.connection.execute("COMMIT")
        return self.packet(run_id)

    def packet(self, run_id: str) -> AssurancePacket:
        run = self.connection.execute(
            """
            SELECT trial_id, config_id, evidence_date, as_of_date, manifest_digest, bundle_json
            FROM runs WHERE run_id = ?
            """,
            [run_id],
        ).fetchone()
        if run is None:
            raise KeyError(run_id)
        metrics = [
            MetricRecord(
                name=row[0],
                numerator=row[1],
                denominator=row[2],
                value=row[3],
                unit=row[4],
                measurement_status=row[5],
            )
            for row in self.connection.execute(
                """
                SELECT metric_name, numerator, denominator, value, unit, measurement_status
                FROM metrics WHERE run_id = ? ORDER BY metric_name
                """,
                [run_id],
            ).fetchall()
        ]
        attributions = [
            AttributionRecord(category=row[0], code=row[1], count=row[2], explanation=row[3])
            for row in self.connection.execute(
                """
                SELECT category, code, count, explanation
                FROM attributions WHERE run_id = ? ORDER BY category, code
                """,
                [run_id],
            ).fetchall()
        ]
        comparisons = [
            ComparisonRecord(
                config_id=row[0],
                metric_name=row[1],
                samples=row[2],
                mean=row[3],
                minimum=row[4],
                maximum=row[5],
            )
            for row in self.connection.execute(
                """
                SELECT r.config_id, m.metric_name, COUNT(*), AVG(m.value),
                       MIN(m.value), MAX(m.value)
                FROM metrics m JOIN runs r USING (run_id)
                WHERE m.value IS NOT NULL
                GROUP BY r.config_id, m.metric_name
                ORDER BY r.config_id, m.metric_name
                """
            ).fetchall()
        ]
        bundle = json.loads(run[5])
        evidence_age = (run[3] - run[2]).days
        not_measured = [
            metric.name for metric in metrics if metric.measurement_status != "measured"
        ]
        limitations = [
            "All targets, identities, data, and effects are synthetic and loopback-only.",
            (
                "Configuration comparisons disclose sample count and observed range; "
                "they are not causal estimates."
            ),
        ]
        if not_measured:
            limitations.append("Not measured in this run: " + ", ".join(not_measured) + ".")
        notes = bundle["metadata"].get("notes", "")
        if notes:
            limitations.append("Run metadata: " + notes)
        return AssurancePacket(
            run_id=run_id,
            trial_id=run[0],
            config_id=run[1],
            evidence_date=run[2],
            evidence_age_days=evidence_age,
            manifest_digest=run[4],
            metrics=metrics,
            attributions=attributions,
            comparisons=comparisons,
            promotion_action=bundle["remediation"]["promotion"]["action"],
            evidence_complete=bundle["remediation"]["gates"]["evidence_complete"],
            limitations=limitations,
        )

    def write_packet(self, packet: AssurancePacket, output_directory: Path) -> None:
        output_directory.mkdir(parents=True, exist_ok=True)
        json_path = output_directory / "assurance.json"
        markdown_path = output_directory / "assurance.md"
        json_path.write_text(packet.model_dump_json(indent=2) + "\n")
        markdown_path.write_text(render_markdown(packet))

    def export_parquet(self, output_directory: Path) -> list[Path]:
        output_directory.mkdir(parents=True, exist_ok=True)
        paths: list[Path] = []
        for table in ["runs", "metrics", "findings", "attributions", "patches"]:
            path = output_directory / f"{table}.parquet"
            escaped = str(path.resolve()).replace("'", "''")
            self.connection.execute(f"COPY {table} TO '{escaped}' (FORMAT PARQUET, OVERWRITE true)")
            paths.append(path)
        return paths

    def table_count(self, table: str) -> int:
        allowed = {"runs", "metrics", "findings", "attributions", "patches"}
        if table not in allowed:
            raise ValueError("unknown table")
        row = self.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
        if row is None:
            raise RuntimeError(f"count query returned no row for {table}")
        return int(row[0])

    def _insert_metrics(self, run_id: str, metrics: list[MetricRecord]) -> None:
        self.connection.executemany(
            "INSERT INTO metrics VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                [
                    run_id,
                    metric.name,
                    metric.numerator,
                    metric.denominator,
                    metric.value,
                    metric.unit,
                    metric.measurement_status,
                ]
                for metric in metrics
            ],
        )

    def _insert_findings(self, run_id: str, bundle: TrialBundle) -> None:
        statuses = {
            result.proof.finding_id: result.proof for result in bundle.evaluation.verification
        }
        self.connection.executemany(
            "INSERT INTO findings VALUES (?, ?, ?, ?, ?)",
            [
                [
                    run_id,
                    finding.id,
                    finding.confidence,
                    statuses[finding.id].status,
                    statuses[finding.id].reason_code,
                ]
                for finding in bundle.evaluation.discovery.findings
            ],
        )

    def _insert_attributions(self, run_id: str, rows: list[AttributionRecord]) -> None:
        self.connection.executemany(
            "INSERT INTO attributions VALUES (?, ?, ?, ?, ?)",
            [[run_id, row.category, row.code, row.count, row.explanation] for row in rows],
        )

    def _insert_patch(self, run_id: str, bundle: TrialBundle) -> None:
        remediation = bundle.remediation
        self.connection.execute(
            "INSERT INTO patches VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                run_id,
                remediation.patch.patch_digest,
                remediation.patch.finding_id,
                remediation.patch.profile,
                remediation.promotion.action,
                remediation.gates.exploit_blocked,
                remediation.gates.functional_tests,
                remediation.gates.evidence_complete,
            ],
        )

    def _create_schema(self) -> None:
        statements = [
            """
            CREATE TABLE IF NOT EXISTS runs (
                run_id VARCHAR PRIMARY KEY, trial_id VARCHAR NOT NULL, config_id VARCHAR NOT NULL,
                evidence_date DATE NOT NULL, as_of_date DATE NOT NULL,
                manifest_digest VARCHAR NOT NULL,
                harness_version VARCHAR NOT NULL, bundle_json JSON NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS metrics (
                run_id VARCHAR NOT NULL, metric_name VARCHAR NOT NULL, numerator DOUBLE,
                denominator DOUBLE, value DOUBLE, unit VARCHAR NOT NULL,
                measurement_status VARCHAR NOT NULL,
                PRIMARY KEY (run_id, metric_name)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS findings (
                run_id VARCHAR NOT NULL, finding_id VARCHAR NOT NULL, confidence DOUBLE NOT NULL,
                status VARCHAR NOT NULL, reason_code VARCHAR NOT NULL,
                PRIMARY KEY (run_id, finding_id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS attributions (
                run_id VARCHAR NOT NULL, category VARCHAR NOT NULL, code VARCHAR NOT NULL,
                count INTEGER NOT NULL, explanation VARCHAR NOT NULL,
                PRIMARY KEY (run_id, category, code)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS patches (
                run_id VARCHAR PRIMARY KEY, patch_digest VARCHAR NOT NULL,
                finding_id VARCHAR NOT NULL,
                profile VARCHAR NOT NULL, action VARCHAR NOT NULL, exploit_blocked BOOLEAN NOT NULL,
                functional_tests BOOLEAN NOT NULL, evidence_complete BOOLEAN NOT NULL
            )
            """,
        ]
        for statement in statements:
            self.connection.execute(statement)


def render_markdown(packet: AssurancePacket) -> str:
    lines = [
        "# AppSec Assurance Packet",
        "",
        f"- Run: `{packet.run_id}`",
        f"- Trial: `{packet.trial_id}`",
        f"- Configuration: `{packet.config_id}`",
        (
            f"- Evidence date: `{packet.evidence_date.isoformat()}` "
            f"({packet.evidence_age_days} days old)"
        ),
        f"- Promotion action: `{packet.promotion_action}`",
        f"- Evidence complete: `{str(packet.evidence_complete).lower()}`",
        "",
        "## Metrics",
        "",
        "| Metric | Value | Numerator | Denominator | Status |",
        "| --- | ---: | ---: | ---: | --- |",
    ]
    for metric in packet.metrics:
        lines.append(
            f"| {metric.name} | {_display(metric.value)} | {_display(metric.numerator)} | "
            f"{_display(metric.denominator)} | {metric.measurement_status} |"
        )
    lines.extend(["", "## Defect Attribution", ""])
    for attribution in packet.attributions:
        lines.append(
            f"- **{attribution.category} / {attribution.code}: {attribution.count}.** "
            f"{attribution.explanation}"
        )
    lines.extend(["", "## Comparison Uncertainty", ""])
    for comparison in packet.comparisons:
        lines.append(
            f"- `{comparison.config_id}` / `{comparison.metric_name}`: n={comparison.samples}, "
            f"mean={comparison.mean:.6g}, "
            f"range=[{comparison.minimum:.6g}, {comparison.maximum:.6g}]"
        )
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {limitation}" for limitation in packet.limitations)
    return "\n".join(lines) + "\n"


def _display(value: Any) -> str:
    if value is None:
        return "not measured"
    if isinstance(value, float):
        return f"{value:.6g}"
    return str(value)
