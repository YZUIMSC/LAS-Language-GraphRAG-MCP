# syntax=docker/dockerfile:1

# ── builder ──────────────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Copy dependency manifests first — Docker layer cache
COPY pyproject.toml uv.lock ./

# Install production deps into /app/.venv (no dev, exact lock)
RUN uv sync --no-dev --frozen

# Copy application source
COPY cyber_graph_triage/ ./cyber_graph_triage/
COPY server.py ./

# ── runtime ───────────────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

WORKDIR /app

# Copy venv and source from builder
COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app/cyber_graph_triage /app/cyber_graph_triage
COPY --from=builder /app/server.py /app/server.py

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

CMD ["python", "server.py", "--transport", "sse", "--host", "0.0.0.0", "--port", "8080"]
