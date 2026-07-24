FROM python:3.12-slim

# Bring in the uv binary from the official image (pinned to match local tooling)
COPY --from=ghcr.io/astral-sh/uv:0.9.22 /uv /uvx /bin/

# Set working directory
WORKDIR /app

# Environment
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PATH="/app/.venv/bin:$PATH"

# System dependencies (build tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Create logs directory
RUN mkdir -p /app/logs && chmod 777 /app/logs

# Install Python dependencies first as a cached layer.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

# Create appuser now so the browser install below runs as that user,
# putting Chromium in /home/appuser/.cache/ms-playwright/ — exactly
# where Playwright looks at runtime.
RUN useradd -m appuser && chown -R appuser:appuser /app

# Install Chromium system libraries (apt-get needs root)
RUN /app/.venv/bin/playwright install-deps chromium

# Install the Chromium browser binary as appuser so it lands in the
# correct cache path (/home/appuser/.cache/ms-playwright/)
USER appuser
RUN /app/.venv/bin/playwright install chromium

# Back to root for the remaining file setup
USER root

# Copy app code
COPY . .

# Create the data directory and set permissions
RUN mkdir -p /app/data/cyberchef_recipes && chown -R appuser:appuser /app/data

# Ensure static files and the virtualenv are accessible to the app user
RUN chown -R appuser:appuser /app/static && chmod -R 755 /app/static && \
    chown -R appuser:appuser /app/.venv

USER appuser

# Expose port (internal)
EXPOSE 5050

# Start Gunicorn (resolved from /app/.venv via PATH).
# Single worker + threads (gthread): the response cache and per-service rate limiters are
# in-process, so one shared process keeps API throttling correct; threads provide concurrency
# for the many blocking external-API calls. Scale threads (not workers) for more concurrency.
CMD ["gunicorn", "--bind", "0.0.0.0:5050", "--workers", "1", "--threads", "8", "--worker-class", "gthread", "--timeout", "120", "main:app"]
