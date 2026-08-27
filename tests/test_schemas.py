import json
from pathlib import Path


def test_contract_schemas_are_valid_json_and_closed() -> None:
    schema_paths = sorted(Path("schemas/v1").glob("*.schema.json"))
    assert {path.name for path in schema_paths} == {
        "finding.schema.json",
        "patch-evidence.schema.json",
        "threat-model.schema.json",
        "trial-report.schema.json",
        "triage-decision.schema.json",
        "verification-proof.schema.json",
    }
    for path in schema_paths:
        schema = json.loads(path.read_text())
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert schema["additionalProperties"] is False


def test_candidate_finding_cannot_set_severity() -> None:
    schema = json.loads(Path("schemas/v1/finding.schema.json").read_text())
    assert "severity" not in schema["properties"]
    assert schema["additionalProperties"] is False
