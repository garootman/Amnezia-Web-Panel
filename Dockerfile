# syntax=docker/dockerfile:1
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=0
WORKDIR /app

RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project --no-dev

COPY . /app
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev

# Trim wheel metadata and bundled test suites; keep __pycache__ (UV_COMPILE_BYTECODE=1).
RUN find /app/.venv -name '*.dist-info' -type d -exec rm -rf {} + \
 && find /app/.venv/lib -type d -name 'tests' -prune -exec rm -rf {} + \
 && find /app/.venv/lib -type d -name 'test' -prune -exec rm -rf {} +

FROM python:3.12-slim-bookworm
RUN groupadd --system --gid 999 app \
 && useradd --system --gid 999 --uid 999 --create-home app
COPY --from=builder --chown=app:app /app/.venv /app/.venv
COPY --from=builder --chown=app:app /app/src /app/src
COPY --from=builder --chown=app:app /app/assets /app/assets
RUN mkdir -p /app/data && chown -R app:app /app/data
ENV PATH="/app/.venv/bin:$PATH" \
    PANEL_HOST=0.0.0.0 \
    PANEL_PORT=5000 \
    DATA_DIR=/app/data
USER app
WORKDIR /app
VOLUME ["/app/data"]
EXPOSE 5000
CMD ["python", "-m", "amnezia_panel"]
