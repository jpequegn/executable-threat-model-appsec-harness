.PHONY: sync format lint test check

sync:
	uv sync --frozen --all-groups --no-editable

format:
	gofmt -w $$(find cmd internal -name '*.go')
	uv run --no-sync ruff format .

lint:
	test -z "$$(gofmt -l $$(find cmd internal -name '*.go'))"
	go vet ./...
	uv run --no-sync ruff check .
	uv run --no-sync ruff format --check .
	uv run --no-sync mypy

test:
	go test ./...
	uv run --no-sync pytest

check: lint test
