FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Environment
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# System dependencies (if needed)
RUN apt-get update && apt-get install -y --no-install-recommends gcc curl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app code
COPY . .

# Create a non-root user
RUN adduser --disabled-password --gecos '' appuser
USER appuser

# Expose port (internal)
EXPOSE 5050

# Start Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:5050", "main:app"]
