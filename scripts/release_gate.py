"""Run replay, rollback, redaction, and release-asset gates."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from appsec_harness.demo import run_demo


def main() -> None:
    repository = Path(__file__).resolve().parents[1]
    with TemporaryDirectory(prefix="appsec-release-") as directory:
        root = Path(directory)
        first = root / "good-first"
        second = root / "good-second"
        bad = root / "bad-patch"
        run_demo(repository, first, profile="fixed-sql", approve=True)
        run_demo(repository, second, profile="fixed-sql", approve=True)
        run_demo(repository, bad, profile="bad-sql", approve=True)
        _assert_replay(first, second)
        _assert_golden(repository, first)
        _assert_rollback(bad)
        _assert_redacted(first)
        _assert_redacted(bad)
        _assert_compose(repository)
    print("release gate passed: promotion, rollback, replay, redaction, and isolation")


def _assert_replay(first: Path, second: Path) -> None:
    paths = [
        "discovery.json",
        "verification.json",
        "evaluation.json",
        "remediation.json",
        "metadata.json",
        "summary.json",
        "lifecycle.json",
        "assurance/assurance.json",
        "assurance/assurance.md",
        "regressions/sql-injection.json",
        "control/runs/appsec-demo/receipts/receipts.jsonl",
    ]
    for relative in paths:
        if (first / relative).read_bytes() != (second / relative).read_bytes():
            raise AssertionError(f"replay mismatch: {relative}")


def _assert_golden(repository: Path, output: Path) -> None:
    actual = json.loads((output / "summary.json").read_text())
    actual.pop("assurance_digest")
    expected = json.loads((repository / "fixtures/golden/demo-summary.json").read_text())
    if actual != expected:
        raise AssertionError(f"demo summary drifted from golden: {actual}")
    lifecycle = json.loads((output / "lifecycle.json").read_text())
    if lifecycle["state"] != "REPORT" or len(lifecycle["receipts"]) != 10:
        raise AssertionError("lifecycle did not complete all ten states")


def _assert_rollback(output: Path) -> None:
    summary = json.loads((output / "summary.json").read_text())
    regression = json.loads((output / "regressions/sql-injection.json").read_text())
    if summary["promotion_action"] != "rolled_back":
        raise AssertionError("bad patch did not roll back")
    if regression["functional_behavior_preserved"] is not False:
        raise AssertionError("bad patch regression was not captured")


def _assert_redacted(output: Path) -> None:
    forbidden = ["SYNTHETIC_CANARY_DO_NOT_EMIT_184", "' OR 1=1 --", "secret-value"]
    paths = list(output.rglob("*.json")) + list(output.rglob("*.jsonl"))
    for path in paths:
        content = path.read_text()
        for value in forbidden:
            if value in content:
                raise AssertionError(f"unsafe evidence in {path}: {value}")


def _assert_compose(repository: Path) -> None:
    compose = (repository / "docker-compose.yml").read_text()
    required = [
        "internal: true",
        "read_only: true",
        "no-new-privileges:true",
        "cap_drop:",
    ]
    missing = [value for value in required if value not in compose]
    if missing:
        raise AssertionError(f"Docker isolation controls missing: {missing}")
    if "ports:" in compose:
        raise AssertionError("the internal synthetic target must not publish host ports")


if __name__ == "__main__":
    main()
