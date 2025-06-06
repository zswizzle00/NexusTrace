FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Environment
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# System dependencies (if needed)
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Create logs directory and set permissions
RUN mkdir -p /app/logs && chmod 777 /app/logs

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create a non-root user
RUN useradd -m appuser && chown -R appuser:appuser /app

# Copy app code
COPY . .

# Create the data directory and set permissions
RUN mkdir -p /app/data && chown -R appuser:appuser /app/data

# Ensure static files are accessible
RUN chown -R appuser:appuser /app/static && \
    chmod -R 755 /app/static

USER appuser

# Expose port (internal)
EXPOSE 5050

# Start Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:5050", "--timeout", "120", "main:app"]
