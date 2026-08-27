# Executable Threat Model AppSec Harness

A local evaluation harness for testing defensive AppSec agents against synthetic,
intentionally vulnerable services. The harness separates high-recall discovery from
independent verification, then requires evidence-backed policy gates before containment,
patching, staging, or promotion.

> [!IMPORTANT]
> This project is for synthetic targets owned by the operator. It does not scan public
> services, third-party repositories, private networks, or production systems. Network
> access is denied by default and generated evidence is sanitized.

## Status

The project is being implemented from
[`jpequegn/project-ideas#184`](https://github.com/jpequegn/project-ideas/issues/184).

## Development

Prerequisites: Go 1.24+, `uv`, and Python 3.12.

```bash
make sync
make check
```

Run the initial command-line smoke check:

```bash
go run ./cmd/appsec-harness version
uv run appsec-harness-version
```

Run the synthetic target locally:

```bash
uv run uvicorn appsec_harness.target.app:create_app --factory --host 127.0.0.1 --port 8080
```

Only loopback interfaces and synthetic data are supported. The controlled vulnerable routes
exist solely so the harness can measure discovery and independent verification behavior.

Initialize and inspect a deterministic trial workspace:

```bash
go run ./cmd/appsec-harness trial init \
  --root runs --manifest fixtures/trials/demo-manifest.json
go run ./cmd/appsec-harness trial step \
  --root runs --trial demo-good-patch --request fixtures/trials/prepare-request.json
go run ./cmd/appsec-harness trial status \
  --root runs --trial demo-good-patch
```

Each accepted transition appends a sanitized, digest-verified receipt. Invalid transitions,
budget exhaustion, conflicting idempotency keys, and remediation without independent proof fail
before the receipt log is mutated.

Run the credential-free discovery and independent-verification baseline:

```bash
make sync
uv run --no-sync appsec-eval --root . --output artifacts/evaluation.json
```

The baseline deliberately favors discovery recall, then measures whether the separate verifier
improves precision by rejecting protected, unreachable, clean, and flaky candidates. Discovery
inputs are allowlisted in `fixtures/corpus/cases.json`; `references/` is denied.

Stage a verified patch through containment and promotion gates:

```bash
uv run --no-sync appsec-remediate --root . \
  --profile fixed-sql --mode promote --approve \
  --output artifacts/remediation-good.json
uv run --no-sync appsec-remediate --root . \
  --profile bad-sql --mode promote --approve \
  --output artifacts/remediation-rollback.json
```

The first profile blocks the controlled exploit while preserving normal and authorized behavior.
The second also blocks the exploit but breaks normal search, so the deterministic gate rolls it
back. Advisory mode is the default, human approval is required for promotion, and GitHub writes
remain disabled.

Persist a completed evaluation and generate assurance artifacts:

```bash
uv run --no-sync appsec-report \
  --database artifacts/evidence.duckdb \
  --evaluation artifacts/evaluation.json \
  --remediation artifacts/remediation-good.json \
  --metadata fixtures/reporting/demo-metadata.json \
  --output artifacts/assurance
```

The output includes `assurance.json`, `assurance.md`, and Parquet exports for runs, metrics,
findings, defect attributions, and patches. Re-importing identical evidence is idempotent. Every
metric exposes its numerator, denominator, unit, and measurement status; configuration summaries
show sample count and observed range rather than implying causal certainty.

See [docs/architecture.md](docs/architecture.md) for the intended component and trust
boundaries.
Executable local AppSec evaluation harness with independent verification, remediation gates, and replayable evidence
