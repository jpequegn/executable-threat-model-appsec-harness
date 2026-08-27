from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from appsec_harness.target import create_app
from appsec_harness.target.network_policy import NetworkPolicyError, require_loopback_url
from appsec_harness.target.redaction import SYNTHETIC_CANARY, redact


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    return TestClient(create_app(tmp_path / "orders.sqlite3"))


def test_reset_restores_deterministic_orders(client: TestClient) -> None:
    initial = client.get("/orders/search", params={"q": "Synthetic"}).json()
    assert [order["id"] for order in initial] == [1, 2, 3]

    assert client.post("/orders/1/approve", headers={"x-actor": "buyer-a"}).status_code == 200
    assert client.post("/reset").json() == {"status": "reset"}
    restored = client.get("/orders/search", params={"q": "laptop"}).json()
    assert restored == [
        {"id": 1, "owner": "buyer-a", "description": "Synthetic laptop", "status": "pending"}
    ]


def test_seeded_injection_and_protected_control(client: TestClient) -> None:
    controlled_query = "' OR 1=1 --"
    vulnerable = client.get("/orders/search", params={"q": controlled_query})
    protected = client.get("/orders/protected-search", params={"q": controlled_query})

    assert vulnerable.status_code == 200
    assert len(vulnerable.json()) == 3
    assert protected.status_code == 200
    assert protected.json() == []


def test_seeded_authorization_mismatch_and_protected_control(client: TestClient) -> None:
    vulnerable = client.post("/orders/1/approve", headers={"x-actor": "buyer-a"})
    assert vulnerable.json() == {"approved": True, "order_id": 1}

    client.post("/reset")
    denied = client.post(
        "/orders/1/protected-approve",
        headers={"x-actor": "buyer-a", "x-role": "buyer"},
    )
    allowed = client.post(
        "/orders/1/protected-approve",
        headers={"x-actor": "approver-a", "x-role": "approver"},
    )
    assert denied.status_code == 403
    assert allowed.status_code == 200


@pytest.mark.parametrize(
    "url",
    ["https://example.com", "http://10.0.0.8", "http://192.168.1.1", "file:///tmp/x"],
)
def test_network_policy_rejects_non_loopback(url: str) -> None:
    with pytest.raises(NetworkPolicyError):
        require_loopback_url(url)


@pytest.mark.parametrize(
    "url", ["http://127.0.0.1:8081", "http://localhost:8081", "http://[::1]:8081"]
)
def test_network_policy_accepts_loopback(url: str) -> None:
    assert require_loopback_url(url) == url


def test_public_egress_attempt_fails_closed(client: TestClient) -> None:
    response = client.get("/outbound-preview", params={"url": "https://example.com"})
    assert response.status_code == 403
    assert "denied" in response.json()["detail"]


def test_clean_and_error_responses_do_not_emit_canary(client: TestClient) -> None:
    responses = [client.get("/clean"), client.get("/orders/search", params={"q": "'"})]
    assert all(SYNTHETIC_CANARY not in response.text for response in responses)
    assert redact(f"token={SYNTHETIC_CANARY}") == "[REDACTED]"


def test_unreachable_control_has_no_route(client: TestClient) -> None:
    assert client.get("/debug/query").status_code == 404


def test_corpus_denies_hidden_references() -> None:
    corpus = json.loads(Path("fixtures/corpus/cases.json").read_text())
    assert corpus["denied_discovery_paths"] == ["references/"]
    assert all(not path.startswith("references/") for path in corpus["discovery_inputs"])
    assert len(corpus["cases"]) == 8
