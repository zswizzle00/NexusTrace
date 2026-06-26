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

# System dependencies (for building any wheels that lack manylinux builds)
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Create logs directory and set permissions
RUN mkdir -p /app/logs && chmod 777 /app/logs

# Install dependencies first as a cached layer - only the manifests, no app code yet.
# --frozen requires uv.lock to be in sync with pyproject.toml (CI-safe, no implicit relock).
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

# Create a non-root user
RUN useradd -m appuser && chown -R appuser:appuser /app

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
