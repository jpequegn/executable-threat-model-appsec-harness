"""Run deterministic remediation profiles against verified synthetic evidence."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import cast

from appsec_harness.eval.runner import run_evaluation
from appsec_harness.remediation.models import PatchProfile, RemediationPolicy
from appsec_harness.remediation.runner import run_remediation


def main() -> None:
    parser = argparse.ArgumentParser(description="Stage an evidence-gated synthetic patch")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", choices=["fixed-sql", "bad-sql"], default="fixed-sql")
    parser.add_argument("--mode", choices=["advisory", "shadow", "promote"], default="advisory")
    parser.add_argument("--approve", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    evaluation = run_evaluation(args.root)
    finding = next(item for item in evaluation.discovery.findings if item.id == "sql-injection")
    proof = next(
        item.proof for item in evaluation.verification if item.proof.finding_id == finding.id
    )
    policy = RemediationPolicy(mode=args.mode, human_approved=args.approve)
    result = run_remediation(
        finding,
        proof,
        profile=cast(PatchProfile, args.profile),
        policy=policy,
    )
    payload = result.model_dump_json(indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload + "\n")
    else:
        print(payload)


if __name__ == "__main__":
    main()
