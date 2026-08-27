"""Credential-free end-to-end AppSec harness demonstration."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, cast

from appsec_harness.eval.context import build_discovery_context, canonical_digest
from appsec_harness.eval.discovery import discover
from appsec_harness.eval.runner import assemble_evaluation
from appsec_harness.eval.verifier import verify
from appsec_harness.remediation.models import (
    PatchProfile,
    RemediationPolicy,
    RemediationRun,
)
from appsec_harness.remediation.runner import contain, decide, package_patch, stage
from appsec_harness.remediation.triage import triage_queue
from appsec_harness.reporting.models import RunMetadata, TrialBundle
from appsec_harness.reporting.store import EvidenceStore

_STATES = [
    "PREPARE",
    "DISCOVER",
    "VERIFY",
    "TRIAGE",
    "CONTAIN",
    "PATCH",
    "REGRESS",
    "STAGE",
    "PROMOTE_OR_ROLLBACK",
    "REPORT",
]


def run_demo(
    repository: Path,
    output: Path,
    *,
    profile: PatchProfile = "fixed-sql",
    approve: bool = False,
    trial_id: str = "appsec-demo",
) -> dict[str, Any]:
    repository = repository.resolve()
    output = output.resolve()
    if output.exists() and any(output.iterdir()):
        raise ValueError(f"output directory must be empty: {output}")
    output.mkdir(parents=True, exist_ok=True)

    control = GoLifecycle(repository, output / "control", trial_id)
    threat_model = json.loads(
        (repository / "fixtures/threat-models/order-service-v1.json").read_text()
    )
    control.initialize(canonical_digest(threat_model))
    control.step("PREPARE", {"workspace": "created", "network": "local-only"})

    context = build_discovery_context(repository)
    discovery = discover(context, trial_id)
    _write_model(output / "discovery.json", discovery)
    control.step(
        "DISCOVER",
        {
            "adapter": discovery.adapter,
            "input_digest": discovery.input_digest,
            "candidates": len(discovery.findings),
        },
    )

    verification = [verify(finding, discovery.input_digest) for finding in discovery.findings]
    _write_json(
        output / "verification.json",
        [result.model_dump(mode="json") for result in verification],
    )
    verified_ids = sorted(
        result.proof.finding_id for result in verification if result.proof.status == "confirmed"
    )
    control.step(
        "VERIFY",
        {
            "verifier": verification[0].proof.verifier_adapter,
            "confirmed": len(verified_ids),
            "rejected": sum(result.proof.status == "rejected" for result in verification),
            "flaky": sum(result.proof.status == "flaky" for result in verification),
        },
    )
    evaluation = assemble_evaluation(trial_id, discovery, verification)
    _write_model(output / "evaluation.json", evaluation)

    pairs = [
        (
            finding,
            next(result.proof for result in verification if result.proof.finding_id == finding.id),
        )
        for finding in discovery.findings
    ]
    queue = triage_queue(pairs)
    selected_triage = next(decision for decision in queue if decision.finding_id == "sql-injection")
    finding = next(item for item in discovery.findings if item.id == selected_triage.finding_id)
    proof = next(result.proof for result in verification if result.proof.finding_id == finding.id)
    control.step(
        "TRIAGE",
        {
            "finding_id": finding.id,
            "priority": selected_triage.priority,
            "severity": selected_triage.severity,
        },
    )

    control.step(
        "CONTAIN",
        {"finding_id": finding.id, "capability": "GET /orders/search"},
        verified_ids,
    )
    containment = contain(finding)

    policy = RemediationPolicy(mode="promote", human_approved=approve)
    control.step("PATCH", {"finding_id": finding.id, "profile": profile}, verified_ids)
    patch = package_patch(finding, proof, profile, policy)

    control.step("REGRESS", {"patch_digest": patch.patch_digest}, verified_ids)
    gates = stage(patch, policy)
    control.step(
        "STAGE",
        {"patch_digest": patch.patch_digest, "all_gates_passed": gates.passed},
        verified_ids,
    )
    promotion = decide(gates, policy)
    control.step(
        "PROMOTE_OR_ROLLBACK",
        {
            "action": promotion.action,
            "all_gates_passed": gates.passed,
            "human_approved": approve,
            "rollback_preserved_evidence": promotion.rollback_preserved_evidence,
            "reason_code": promotion.reason_code,
        },
        verified_ids,
    )
    remediation = RemediationRun(
        triage=selected_triage,
        containment=containment,
        patch=patch,
        gates=gates,
        promotion=promotion,
    )
    _write_model(output / "remediation.json", remediation)

    metadata = RunMetadata.model_validate_json(
        (repository / "fixtures/reporting/demo-metadata.json").read_text()
    )
    _write_model(output / "metadata.json", metadata)
    with EvidenceStore(output / "evidence.duckdb") as store:
        packet = store.import_bundle(
            TrialBundle(evaluation=evaluation, remediation=remediation, metadata=metadata)
        )
        store.write_packet(packet, output / "assurance")
        store.export_parquet(output / "assurance/parquet")
    assurance_digest = canonical_digest(packet.model_dump(mode="json"))
    control.step("REPORT", {"assurance_digest": assurance_digest})
    control.write_status(output / "lifecycle.json")

    regression = {
        "schema_version": "appsec-harness.dev/regression/v1",
        "finding_id": finding.id,
        "proof_digest": patch.proof_digest,
        "patch_digest": patch.patch_digest,
        "promotion_action": promotion.action,
        "reason_code": promotion.reason_code,
        "exploit_blocked": gates.exploit_blocked,
        "functional_behavior_preserved": gates.functional_tests,
    }
    _write_json(output / "regressions/sql-injection.json", regression)
    summary = {
        "schema_version": "appsec-harness.dev/demo/v1",
        "trial_id": trial_id,
        "profile": profile,
        "final_state": "REPORT",
        "verified_findings": verified_ids,
        "discovery_recall": evaluation.metrics.discovery_recall,
        "precision_before_verification": evaluation.metrics.precision_before_verification,
        "precision_after_verification": evaluation.metrics.precision_after_verification,
        "promotion_action": promotion.action,
        "promotion_reason": promotion.reason_code,
        "assurance_digest": assurance_digest,
        "regression_case": "regressions/sql-injection.json",
    }
    _write_json(output / "summary.json", summary)
    return summary


class GoLifecycle:
    def __init__(self, repository: Path, root: Path, trial_id: str) -> None:
        self.repository = repository
        self.root = root
        self.trial_id = trial_id
        self.requests = root / "requests"
        self.requests.mkdir(parents=True, exist_ok=True)
        self.sequence = 0

    def initialize(self, threat_model_digest: str) -> None:
        manifest = {
            "schema_version": "appsec-harness.dev/lifecycle/v1",
            "trial_id": self.trial_id,
            "target": "synthetic-order-service",
            "threat_model_digest": threat_model_digest,
            "budget": {
                "max_duration_ms": 60000,
                "max_tool_calls": 100,
                "max_cost_micros": 1000000,
            },
            "network_policy": "local-only",
        }
        path = self.root / "manifest.json"
        _write_json(path, manifest)
        self._run("trial", "init", "--root", str(self.root / "runs"), "--manifest", str(path))

    def step(
        self,
        state: str,
        evidence: dict[str, Any],
        verified_finding_ids: list[str] | None = None,
    ) -> None:
        self.sequence += 1
        if state != _STATES[self.sequence - 1]:
            raise ValueError(f"unexpected lifecycle state {state}")
        request = {
            "state": state,
            "idempotency_key": f"{self.trial_id}:{self.sequence:02d}:{state.lower()}",
            "usage": {"duration_ms": 1, "tool_calls": 1, "cost_micros": 0},
            "verified_finding_ids": verified_finding_ids or [],
            "evidence": evidence,
        }
        path = self.requests / f"{self.sequence:02d}-{state.lower()}.json"
        _write_json(path, request)
        self._run(
            "trial",
            "step",
            "--root",
            str(self.root / "runs"),
            "--trial",
            self.trial_id,
            "--request",
            str(path),
        )

    def write_status(self, path: Path) -> None:
        result = self._run(
            "trial",
            "status",
            "--root",
            str(self.root / "runs"),
            "--trial",
            self.trial_id,
        )
        _write_json(path, json.loads(result.stdout))

    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["go", "run", "./cmd/appsec-harness", *args],
            cwd=self.repository,
            check=True,
            capture_output=True,
            text=True,
        )


def _write_model(path: Path, model: Any) -> None:
    _write_json(path, model.model_dump(mode="json"))


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the complete synthetic AppSec demonstration")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", choices=["fixed-sql", "bad-sql"], default="fixed-sql")
    parser.add_argument("--approve", action="store_true")
    parser.add_argument("--trial-id", default="appsec-demo")
    args = parser.parse_args()
    summary = run_demo(
        args.root,
        args.output,
        profile=cast(PatchProfile, args.profile),
        approve=args.approve,
        trial_id=args.trial_id,
    )
    print(json.dumps(summary, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
