# AI-based Network Intrusion Detection System
# Multi-stage Docker build for production deployment

# Build stage
FROM python:3.9-slim as builder

# Set build arguments
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION

# Set labels
LABEL maintainer="NIDS Team" \
      org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.name="AI-based NIDS" \
      org.label-schema.description="AI-based Network Intrusion Detection System" \
      org.label-schema.url="https://github.com/nids/ai-based-nids" \
      org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.vcs-url="https://github.com/nids/ai-based-nids" \
      org.label-schema.vendor="NIDS Team" \
      org.label-schema.version=$VERSION \
      org.label-schema.schema-version="1.0"

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies for building
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    make \
    libpcap-dev \
    tcpdump \
    wget \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN groupadd -r nids && useradd -r -g nids nids

# Set work directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Production stage
FROM python:3.9-slim as production

# Set production labels
LABEL maintainer="NIDS Team" \
      description="AI-based Network Intrusion Detection System - Production"

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/app/.venv/bin:$PATH" \
    NIDS_ENV=production \
    NIDS_CONFIG_FILE=/app/config/settings.yaml \
    NIDS_LOG_FILE=/app/data/logs/nids.log \
    NIDS_DATA_DIR=/app/data \
    NIDS_MODEL_DIR=/app/data/models

# Install runtime system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    tcpdump \
    net-tools \
    iproute2 \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN groupadd -r nids && useradd -r -g nids nids

# Set work directory
WORKDIR /app

# Copy Python packages from builder stage
COPY --from=builder /usr/local/lib/python3.9/site-packages /usr/local/lib/python3.9/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Create necessary directories
RUN mkdir -p /app/data/{logs,models,datasets} \
    /app/config \
    /app/tmp \
    && chown -R nids:nids /app

# Copy application code
COPY --chown=nids:nids src/ ./src/
COPY --chown=nids:nids config/ ./config/
COPY --chown=nids:nids main.py ./
COPY --chown=nids:nids README.md ./

# Copy default configuration
COPY --chown=nids:nids docker/settings.yaml /app/config/settings.yaml

# Set permissions
RUN chmod +x main.py

# Create entrypoint script
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
# Check if running as root for packet capture\n\
if [ "$EUID" -ne 0 ]; then\n\
    echo "Warning: Running without root privileges. Packet capture may not work properly."\n\
    echo "Consider running with: docker run --cap-add=NET_ADMIN --device=/dev/net/tun ..."\n\
fi\n\
\n\
# Create data directories if they don\'t exist\n\
mkdir -p /app/data/{logs,models,datasets,backups}\n\
\n\
# Set proper permissions\n\
chown -R nids:nids /app/data 2>/dev/null || true\n\
\n\
# Check configuration file\n\
if [ ! -f "$NIDS_CONFIG_FILE" ]; then\n\
    echo "Configuration file not found at $NIDS_CONFIG_FILE"\n\
    echo "Using default configuration"\n\
    cp /app/config/settings.yaml.default "$NIDS_CONFIG_FILE" 2>/dev/null || true\n\
fi\n\
\n\
# Initialize logging\n\
mkdir -p "$(dirname "$NIDS_LOG_FILE")"\n\
touch "$NIDS_LOG_FILE" 2>/dev/null || true\n\
\n\
# Start the NIDS application\n\
echo "Starting AI-based Network Intrusion Detection System..."\n\
echo "Environment: $NIDS_ENV"\n\
echo "Configuration: $NIDS_CONFIG_FILE"\n\
echo "Data directory: $NIDS_DATA_DIR"\n\
echo "Log file: $NIDS_LOG_FILE"\n\
\n\
exec python main.py\n\
' > /app/entrypoint.sh && \
chmod +x /app/entrypoint.sh && \
chown nids:nids /app/entrypoint.sh

# Switch to non-root user for security
USER nids

# Expose ports
EXPOSE 5000 5001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/api/health || exit 1

# Set entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]

# Default command
CMD ["python", "main.py"]

# Development stage (for development and testing)
FROM production as development

# Switch back to root for development tools
USER root

# Install development dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    vim \
    nano \
    htop \
    ipython3 \
    python3-pip \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install development Python packages
RUN pip install --upgrade pip && \
    pip install pytest pytest-cov black flake8 mypy ipython jupyter

# Copy development configuration
COPY docker/settings-dev.yaml /app/config/settings.yaml

# Create development entrypoint
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
# Development mode setup\n\
export NIDS_ENV=development\n\
export NIDS_DEBUG=true\n\
export NIDS_LOG_LEVEL=DEBUG\n\
\n\
# Enable hot reloading\n\
export FLASK_ENV=development\n\
export FLASK_DEBUG=1\n\
\n\
# Start development server\n\
echo "Starting NIDS in development mode..."\n\
exec python main.py --debug\n\
' > /app/entrypoint-dev.sh && \
chmod +x /app/entrypoint-dev.sh

# Switch back to nids user
USER nids

# Override entrypoint for development
ENTRYPOINT ["/app/entrypoint-dev.sh"]

# Testing stage
FROM development as testing

# Install testing dependencies
RUN pip install pytest pytest-cov pytest-mock pytest-asyncio coverage

# Copy test files
COPY --chown=nids:nids tests/ ./tests/
COPY --chown=nids:nids pytest.ini ./

# Create test entrypoint
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
echo "Running NIDS test suite..."\n\
\n\
# Run unit tests\n\
python -m pytest tests/ -v --cov=src --cov-report=html --cov-report=term\n\
\n\
# Run integration tests if available\n\
if [ -d "tests/integration" ]; then\n\
    python -m pytest tests/integration/ -v\n\
fi\n\
\n\
echo "Tests completed successfully!"\n\
' > /app/entrypoint-test.sh && \
chmod +x /app/entrypoint-test.sh

# Override entrypoint for testing
ENTRYPOINT ["/app/entrypoint-test.sh"]