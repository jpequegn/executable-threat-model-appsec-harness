.PHONY: sync format lint test check

sync:
	uv sync --frozen --all-groups

format:
	gofmt -w $$(find cmd internal -name '*.go')
	uv run ruff format .

lint:
	test -z "$$(gofmt -l $$(find cmd internal -name '*.go'))"
	go vet ./...
	uv run ruff check .
	uv run ruff format --check .
	uv run mypy

test:
	go test ./...
	uv run pytest

check: lint test
