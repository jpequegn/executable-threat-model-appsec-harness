"""Import evaluation evidence and produce assurance artifacts."""

from __future__ import annotations

import argparse
from pathlib import Path

from pydantic import BaseModel

from appsec_harness.eval.models import EvaluationRun
from appsec_harness.remediation.models import RemediationRun
from appsec_harness.reporting.models import RunMetadata, TrialBundle
from appsec_harness.reporting.store import EvidenceStore


def main() -> None:
    parser = argparse.ArgumentParser(description="Persist and report AppSec evaluation evidence")
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--evaluation", type=Path, required=True)
    parser.add_argument("--remediation", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    bundle = TrialBundle(
        evaluation=_load(args.evaluation, EvaluationRun),
        remediation=_load(args.remediation, RemediationRun),
        metadata=_load(args.metadata, RunMetadata),
    )
    with EvidenceStore(args.database) as store:
        packet = store.import_bundle(bundle)
        store.write_packet(packet, args.output)
        store.export_parquet(args.output / "parquet")
    print(packet.model_dump_json(indent=2))


def _load[ModelT: BaseModel](path: Path, model: type[ModelT]) -> ModelT:
    return model.model_validate_json(path.read_text())


if __name__ == "__main__":
    main()
