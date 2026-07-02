# ── Build argument — injected by CI for version tracking ─────────────────────
ARG BUILD_SHA=dev

# ── Base image ────────────────────────────────────────────────────────────────
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PORT=8000

WORKDIR /app

# ── System deps (build-time only; kept in final image for psycopg2) ───────────
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential \
       libpq-dev \
       curl \
    && rm -rf /var/lib/apt/lists/*

# ── Python dependencies (separate layer for cache efficiency) ─────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Application source ────────────────────────────────────────────────────────
COPY . .

# ── Build metadata ────────────────────────────────────────────────────────────
# Bake the git SHA into the image so /version always reports the right commit,
# even when RAILWAY_GIT_COMMIT_SHA is unavailable (e.g. local Docker runs).
ARG BUILD_SHA
ENV APP_VERSION=${BUILD_SHA}

# ── Security: drop to a non-root user ────────────────────────────────────────
RUN groupadd --gid 1001 cafe \
    && useradd --uid 1001 --gid cafe --shell /bin/bash --create-home cafe \
    && chown -R cafe:cafe /app
USER cafe

# ── Port ──────────────────────────────────────────────────────────────────────
EXPOSE ${PORT}

# ── Health check (Docker / Railway container health, not a load-balancer probe)
# /healthz returns "ok" as plain text in < 50ms — no DB, no JSON parsing.
# Interval: 30s so Railway doesn't aggressively restart slow-starting containers.
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f "http://localhost:${PORT}/healthz" || exit 1

# ── Entrypoint ────────────────────────────────────────────────────────────────
CMD ["python", "start.py"]
