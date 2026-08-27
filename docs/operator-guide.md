# Operator guide

## Quick start

Install the locked Python 3.12 environment, then run the successful-promotion demo:

```bash
make sync
uv run --no-sync appsec-demo \
  --root . --output artifacts/good --profile fixed-sql --approve
```

Run the deliberate bad-patch scenario:

```bash
uv run --no-sync appsec-demo \
  --root . --output artifacts/rollback --profile bad-sql --approve
```

Each output directory contains:

- `summary.json`: the concise outcome and precision change;
- `lifecycle.json`: all Go lifecycle receipts and cumulative budgets;
- `evaluation.json`: discovery candidates, independent proofs, and eval metrics;
- `remediation.json`: triage, containment, patch, gates, and promotion decision;
- `evidence.duckdb`: queryable run evidence;
- `assurance/`: JSON, Markdown, and Parquet assurance artifacts;
- `regressions/`: permanent evidence-backed regression cases.

## Inspect evidence

```bash
jq . artifacts/good/summary.json
jq '.receipts[] | {state, receipt_digest}' artifacts/good/lifecycle.json
jq '.metrics[] | {name, value, numerator, denominator}' \
  artifacts/good/assurance/assurance.json
uv run --no-sync python - <<'PY'
import duckdb
db = duckdb.connect("artifacts/good/evidence.duckdb", read_only=True)
print(db.sql("select finding_id, status, reason_code from findings order by finding_id"))
PY
```

## What the demo proves

- Discovery sees allowlisted code and threat context but cannot read hidden reference proofs.
- Verification runs under a different identity and clean state, rejecting false and flaky claims.
- No candidate gets severity or remediation eligibility before independent proof and context triage.
- The Go lifecycle refuses out-of-order, over-budget, unverified, or unapproved transitions.
- A patch must block the controlled exploit while preserving functional and authorized behavior.
- A bad patch automatically rolls back and keeps its evidence and regression record.

## Docker target

```bash
docker compose up --build synthetic-target
docker compose exec synthetic-target .venv/bin/python -c \
  "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8080/health').read().decode())"
docker compose down
```

Compose does not publish a host port. It drops Linux capabilities, uses a read-only filesystem,
and attaches the target only to an internal Docker network. Probe it through `docker compose exec`
as shown above. The no-Docker demo remains the canonical deterministic evaluation path.

## Limits

The included adapters are deterministic baselines, not autonomous security researchers. The
fixtures are intentionally small and synthetic. Timing in the demo metadata is a declared fixture,
not a production latency measurement. This project does not replace threat modeling, static
analysis, penetration testing, or professional security review.
