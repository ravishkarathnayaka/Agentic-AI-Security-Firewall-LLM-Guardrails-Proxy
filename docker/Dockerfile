# Multi-stage production container for Agentic AI Security Firewall & Guardrails Proxy
FROM python:3.11-slim as base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY pyproject.toml .
RUN pip install --upgrade pip && \
    pip install ".[dev]"

# Copy application source code
COPY proxy/ ./proxy/
COPY red_teaming/ ./red_teaming/
COPY tests/ ./tests/

# Run as non-root user
RUN useradd -m -u 10001 appuser && \
    chown -R appuser:appuser /app
USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

CMD ["uvicorn", "proxy.main:app", "--host", "0.0.0.0", "--port", "8080"]
