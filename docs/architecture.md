# Architecture and safety boundary

The harness is split into deterministic control and replaceable evaluation components.

```text
Go lifecycle CLI
  |-- versioned contracts and policy gates
  |-- local trial workspace and sanitized receipts
  |-- Python discovery adapter (reference proofs denied)
  |-- Python verifier adapter (separate identity and state)
  |-- synthetic FastAPI target and mock dependencies
  `-- DuckDB analysis and assurance reports
```

## Trust boundaries

- The Go orchestrator owns lifecycle transitions, budgets, evidence digests, and consequential
  action gates.
- Discovery may propose findings but cannot read hidden reference proofs, set severity, verify
  itself, or patch a target.
- Verification receives only a candidate finding and explicitly permitted target context. It
  runs in a fresh workspace and must produce a deterministic proof or rejection reason.
- Target services and dependencies bind to loopback interfaces and use disposable synthetic
  data. Public and private-network egress is prohibited.
- Patch and promotion adapters are disabled by default. The MVP stages only predefined patches
  against the synthetic service.

## Non-goals

This repository is not a vulnerability scanner, penetration-testing framework, exploit kit,
or production deployment controller. It must never be pointed at systems the operator does not
own and explicitly configure as synthetic fixtures.
