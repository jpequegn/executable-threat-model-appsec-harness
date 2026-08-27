from __future__ import annotations

import json
from pathlib import Path


def test_release_docs_and_security_policy_exist() -> None:
    required = [
        Path("SECURITY.md"),
        Path("CHANGELOG.md"),
        Path("docs/operator-guide.md"),
        Path("docs/extensions.md"),
    ]
    assert all(path.read_text().strip() for path in required)


def test_docker_target_is_internal_read_only_and_unprivileged() -> None:
    compose = Path("docker-compose.yml").read_text()
    dockerfile = Path("Dockerfile").read_text()
    assert "ports:" not in compose
    assert "internal: true" in compose
    assert "read_only: true" in compose
    assert "cap_drop:" in compose and "- ALL" in compose
    assert "no-new-privileges:true" in compose
    assert "USER 10001:10001" in dockerfile


def test_golden_summary_captures_release_contract() -> None:
    golden = json.loads(Path("fixtures/golden/demo-summary.json").read_text())
    assert golden["final_state"] == "REPORT"
    assert golden["promotion_action"] == "promoted"
    assert golden["discovery_recall"] == 1
    assert golden["precision_after_verification"] > golden["precision_before_verification"]
    assert golden["regression_case"] == "regressions/sql-injection.json"
