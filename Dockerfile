FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

WORKDIR /app
RUN useradd --create-home --uid 10001 harness

COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

RUN mkdir -p /app/runs && chown -R harness:harness /app
USER 10001:10001

EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
  CMD [".venv/bin/python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2)"]

CMD [".venv/bin/uvicorn", "appsec_harness.target.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080"]
