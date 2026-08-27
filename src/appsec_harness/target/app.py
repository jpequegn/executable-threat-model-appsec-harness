"""FastAPI application containing controlled synthetic security cases."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Literal, cast

from fastapi import FastAPI, Header, HTTPException, Query

from appsec_harness.target.network_policy import NetworkPolicyError, require_loopback_url
from appsec_harness.target.redaction import SYNTHETIC_CANARY, redact
from appsec_harness.target.store import OrderStore

TargetProfile = Literal["vulnerable", "fixed-sql", "bad-sql"]


def create_app(
    database_path: Path | None = None,
    *,
    profile: TargetProfile = "vulnerable",
    search_contained: bool = False,
) -> FastAPI:
    path = database_path or Path("runs/target/orders.sqlite3")
    store = OrderStore(path)
    store.reset()
    app = FastAPI(title="Synthetic Order Service", version="1.0.0")
    app.state.store = store
    app.state.synthetic_canary = SYNTHETIC_CANARY

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "scope": "synthetic-local-only"}

    @app.post("/reset")
    def reset() -> dict[str, str]:
        store.reset()
        return {"status": "reset"}

    @app.get("/orders/search")
    def vulnerable_search(q: str = Query(max_length=80)) -> list[dict[str, object]]:
        if search_contained:
            raise HTTPException(status_code=503, detail="search temporarily contained")
        try:
            if profile == "fixed-sql":
                orders = store.search_protected(q)
            elif profile == "bad-sql":
                orders = []
            else:
                orders = store.search_vulnerable(q)
            return [asdict(order) for order in orders]
        except Exception as exc:
            raise HTTPException(status_code=400, detail="synthetic query rejected") from exc

    @app.get("/orders/protected-search")
    def protected_search(q: str = Query(max_length=80)) -> list[dict[str, object]]:
        return [asdict(order) for order in store.search_protected(q)]

    @app.post("/orders/{order_id}/approve")
    def vulnerable_approve(order_id: int, x_actor: str = Header()) -> dict[str, object]:
        if not store.approve_vulnerable(order_id, x_actor):
            raise HTTPException(status_code=404, detail="synthetic order not found")
        return {"approved": True, "order_id": order_id}

    @app.post("/orders/{order_id}/protected-approve")
    def protected_approve(
        order_id: int, x_actor: str = Header(), x_role: str = Header()
    ) -> dict[str, object]:
        if not store.approve_protected(order_id, x_actor, x_role):
            raise HTTPException(status_code=403, detail="approval policy denied")
        return {"approved": True, "order_id": order_id}

    @app.get("/outbound-preview")
    def outbound_preview(url: str) -> dict[str, str]:
        try:
            permitted = require_loopback_url(url)
        except NetworkPolicyError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        return {"status": "mocked", "url": permitted}

    @app.get("/clean")
    def clean() -> dict[str, object]:
        payload = {"status": "clean", "controls": ["loopback-only", "synthetic-data"]}
        return cast(dict[str, object], redact(payload))

    return app
