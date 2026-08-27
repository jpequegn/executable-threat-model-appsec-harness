from __future__ import annotations

import json
from pathlib import Path

from appsec_harness import print_version
from appsec_harness.demo import run_demo
from appsec_harness.target.dead_code import unreachable_debug_query


def test_complete_promotion_and_rollback_demos(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    repository = Path.cwd()
    promoted = run_demo(
        repository,
        tmp_path / "promoted",
        profile="fixed-sql",
        approve=True,
    )
    rolled_back = run_demo(
        repository,
        tmp_path / "rolled-back",
        profile="bad-sql",
        approve=True,
    )

    assert promoted["final_state"] == "REPORT"
    assert promoted["promotion_action"] == "promoted"
    assert rolled_back["promotion_action"] == "rolled_back"
    assert promoted["precision_after_verification"] > promoted["precision_before_verification"]

    lifecycle = json.loads((tmp_path / "promoted/lifecycle.json").read_text())
    regression = json.loads((tmp_path / "rolled-back/regressions/sql-injection.json").read_text())
    assert lifecycle["state"] == "REPORT"
    assert len(lifecycle["receipts"]) == 10
    assert regression["functional_behavior_preserved"] is False
    assert (tmp_path / "promoted/assurance/parquet/findings.parquet").is_file()

    print_version()
    assert capsys.readouterr().out.strip() == "0.1.0"


def test_dead_code_control_is_present_but_not_routed() -> None:
    assert "retired_orders" in unreachable_debug_query("synthetic")
