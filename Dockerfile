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

FROM python:3.12-slim-bookworm
RUN groupadd --system --gid 999 app \
 && useradd --system --gid 999 --uid 999 --create-home app
COPY --from=builder --chown=app:app /app /app
RUN mkdir -p /app/data && chown -R app:app /app/data
ENV PATH="/app/.venv/bin:$PATH" \
    PANEL_HOST=0.0.0.0 \
    PANEL_PORT=5000 \
    DATA_DIR=/app/data
USER app
WORKDIR /app
VOLUME ["/app/data"]
EXPOSE 5000
CMD ["python", "app.py"]
