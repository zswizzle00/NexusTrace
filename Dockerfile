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
# The cache mount needs BuildKit; it is mutually exclusive with --no-cache-dir.
RUN --mount=type=cache,target=/root/.cache/pip \
    python -m venv /app/.venv && \
    /app/.venv/bin/pip install \
        --only-binary=cryptography,numpy,pandas,pillow,cffi,greenlet,maxminddb,aiohttp,multidict,yarl,frozenlist,propcache \
        -r requirements.txt

# Chromium's system libraries, then the browser itself into PLAYWRIGHT_BROWSERS_PATH.
# Installing as root into a shared world-readable path avoids the USER root/appuser
# flip-flop and the dependence on /home/appuser/.cache/.
# apt cache mounts survive --no-cache, so a --clean rebuild re-uses the ~100 downloaded
# .debs instead of re-fetching them. docker-clean must go or Debian's DPkg::Post-Invoke
# deletes them straight back out of the cache. Nothing apt-related enters the image.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean && \
    /app/.venv/bin/playwright install-deps chromium
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
CMD ["gunicorn", "--bind", "0.0.0.0:5050", "--workers", "1", "--threads", "8", "--worker-class", "gthread", "--timeout", "120", "main:app"]
