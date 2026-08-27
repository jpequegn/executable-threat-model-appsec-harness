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

See [docs/architecture.md](docs/architecture.md) for the intended component and trust
boundaries.
Executable local AppSec evaluation harness with independent verification, remediation gates, and replayable evidence
