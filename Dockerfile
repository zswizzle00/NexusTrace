# syntax=docker/dockerfile:1
FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH" \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# appuser is created first so nothing downstream needs a recursive chown. The venv is
# 307 MB / 7300 files; a `chown -R` over it copies every file into a new layer, which
# on a 2-core VM was the step that appeared to hang for ~20 minutes.
RUN useradd -m appuser && mkdir -p /app/logs && chmod 777 /app/logs

COPY requirements.txt ./

# --only-binary names just the packages whose source build is expensive: a missing wheel
# must fail the build loudly rather than silently compile cryptography (Rust, ~15 min) or
# numpy/pandas (~25 min) on a 2-core VM. Everything else keeps pip's default, so the
# sdist-only pure-Python packages (builtwith, python-whois, future, otxv2) still install.
# That is also why build-essential is not installed here - nothing needs a compiler.
#
# No `RUN --mount=type=cache` here: the production host runs docker-compose v1 with the
# legacy builder and no buildx, where a cache mount is a hard build failure. Once buildx
# and the compose v2 plugin are installed, wrap this in
#   RUN --mount=type=cache,target=/root/.cache/pip
# and drop --no-cache-dir (the two are mutually exclusive) to stop re-downloading wheels.
RUN python -m venv /app/.venv && \
    /app/.venv/bin/pip install --no-cache-dir \
        --only-binary=cryptography,numpy,pandas,pillow,cffi,greenlet,maxminddb,aiohttp,multidict,yarl,frozenlist,propcache \
        -r requirements.txt

# google-cloud-storage is an optional extra (see [project.optional-dependencies] in
# pyproject.toml) that app/utils/storage.py imports lazily, so it is absent from
# requirements.txt - `uv export` does not emit extras. It is needed ONLY by an image
# that will run with STORAGE_BACKEND=gcs, i.e. Cloud Run; the VM/Compose deployment
# would just be carrying dead weight. Build that image with:
#     docker build --build-arg INSTALL_GCS=true ...
# Kept as its own layer so toggling it does not invalidate the expensive install above.
# The version is pinned to match the extra; pip resolves the transitive google-auth /
# google-api-core chain at build time. If you need those pinned too, generate
# `uv export --no-dev --no-hashes --extra gcs -o requirements-gcs.txt` and build from it
# instead of using this flag.
ARG INSTALL_GCS=false
RUN if [ "$INSTALL_GCS" = "true" ]; then \
        /app/.venv/bin/pip install --no-cache-dir \
            --only-binary=google-crc32c,cryptography \
            "google-cloud-storage==3.13.0"; \
    fi

# Chromium's system libraries, then the browser itself into PLAYWRIGHT_BROWSERS_PATH.
# Installing as root into a shared world-readable path avoids the USER root/appuser
# flip-flop and the dependence on /home/appuser/.cache/.
RUN /app/.venv/bin/playwright install-deps chromium && \
    rm -rf /var/lib/apt/lists/*
RUN /app/.venv/bin/playwright install chromium && \
    chmod -R a+rX /ms-playwright

# --chown on the COPY, not a chown -R afterwards. data/ is excluded by .dockerignore
# and bind-mounted at runtime; these dirs only guard against a missing mount.
COPY --chown=appuser:appuser . .
RUN mkdir -p /app/data/scans /app/data/screenshots /app/data/analyses \
        /app/data/cyberchef_recipes && \
    chown appuser:appuser /app/data /app/data/*

USER appuser

# Fail the BUILD if the browser Playwright will actually resolve is missing or not
# executable as appuser. run_scan() resolves it lazily on the first scan, long after
# the compose healthcheck has gone green - so without this, a wrong
# PLAYWRIGHT_BROWSERS_PATH or a permissions regression ships a container that looks
# healthy and dies on the first analyst request.
RUN python -c "import os, sys; \
from playwright.sync_api import sync_playwright; \
p = sync_playwright().start(); \
ep = p.chromium.executable_path; \
p.stop(); \
print('chromium:', ep); \
sys.exit(0 if os.access(ep, os.X_OK) else 1)"

EXPOSE 5050

# Threads, not processes: each scan drives a real Chromium instance inside the request.
# See CLAUDE.md's URL Scanner section before changing this.
#
# Shell form (via `sh -c exec`) rather than a plain exec-form array because the bind
# port has to be resolved at runtime: Cloud Run injects PORT=8080 and fails the startup
# probe if the container listens anywhere else, while docker-compose.yml sets
# FLASK_PORT=5050 and maps 5050:5050. `exec` keeps gunicorn as PID 1 so SIGTERM still
# reaches it (Cloud Run sends SIGTERM, then kills after 10s). Precedence here must match
# main.py:resolve_port().
CMD ["sh", "-c", "exec gunicorn --bind 0.0.0.0:${PORT:-${FLASK_PORT:-5050}} --workers 1 --threads 8 --worker-class gthread --timeout 120 main:app"]
