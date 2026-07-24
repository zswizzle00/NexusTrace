FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH"

# System build deps + Playwright will add its own via install-deps below
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Create logs directory
RUN mkdir -p /app/logs && chmod 777 /app/logs

# Create virtualenv and install Python dependencies
COPY requirements.txt ./
RUN python -m venv /app/.venv && \
    /app/.venv/bin/pip install --no-cache-dir --upgrade pip && \
    /app/.venv/bin/pip install --no-cache-dir -r requirements.txt

# Create appuser before the browser install so the binary lands in the
# right place (/home/appuser/.cache/ms-playwright/) at runtime
RUN useradd -m appuser && chown -R appuser:appuser /app

# Install Chromium system libraries (apt-get must run as root)
RUN /app/.venv/bin/playwright install-deps chromium

# Install the Chromium browser binary as appuser
USER appuser
RUN /app/.venv/bin/playwright install chromium

USER root

# Copy app code
COPY . .

# Pre-create data subdirs so they're owned by appuser even if the bind-mount
# is missing or empty on the host
RUN mkdir -p /app/data/scans /app/data/screenshots /app/data/cyberchef_recipes && \
    chown -R appuser:appuser /app/data && \
    chown -R appuser:appuser /app/static && chmod -R 755 /app/static && \
    chown -R appuser:appuser /app/.venv

USER appuser

EXPOSE 5050

CMD ["gunicorn", "--bind", "0.0.0.0:5050", "--workers", "1", "--threads", "8", "--worker-class", "gthread", "--timeout", "120", "main:app"]
