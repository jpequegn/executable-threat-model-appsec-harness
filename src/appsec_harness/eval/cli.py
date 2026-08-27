"""Command-line entry point for the deterministic baseline evaluation."""

from __future__ import annotations

import argparse
from pathlib import Path

from appsec_harness.eval.runner import run_evaluation


def main() -> None:
    parser = argparse.ArgumentParser(description="Run independent AppSec evaluation lanes")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--trial-id", default="deterministic-baseline")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run_evaluation(args.root, args.trial_id)
    payload = result.model_dump_json(indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload + "\n")
    else:
        print(payload)


if __name__ == "__main__":
    main()
