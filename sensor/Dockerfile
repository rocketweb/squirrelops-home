# SquirrelOps Home Sensor -- Production Docker Image
#
# Build:   docker build -t squirrelops-sensor .
# Run:     docker compose up -d
#
# Base:    Debian Bookworm slim (avoids Alpine compatibility issues
#          with cryptography, scapy, and other C-extension packages)
# Deps:    uv for fast, reproducible Python dependency management

FROM python:3.11-slim-bookworm AS base

ARG VERSION=dev

# -----------------------------------------------------------------------
# System dependencies
# -----------------------------------------------------------------------
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libpcap-dev \
        curl \
    && rm -rf /var/lib/apt/lists/*

# -----------------------------------------------------------------------
# Install uv (Python package manager)
# -----------------------------------------------------------------------
COPY --from=ghcr.io/astral-sh/uv:0.6 /uv /usr/local/bin/uv

# -----------------------------------------------------------------------
# Working directory
# -----------------------------------------------------------------------
WORKDIR /app

# -----------------------------------------------------------------------
# OCI image labels
# -----------------------------------------------------------------------
LABEL org.opencontainers.image.title="SquirrelOps Home Sensor" \
      org.opencontainers.image.description="Home network security sensor with passive monitoring and active deception" \
      org.opencontainers.image.source="https://github.com/rocketweb/squirrelops-home" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"

# -----------------------------------------------------------------------
# Install Python dependencies (cached layer -- only changes when lock
# file changes)
# -----------------------------------------------------------------------
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

# -----------------------------------------------------------------------
# Copy application code
# -----------------------------------------------------------------------
COPY src/ ./src/
COPY config/ ./config/
COPY signatures/ ./signatures/

# -----------------------------------------------------------------------
# Non-root user for runtime security
# -----------------------------------------------------------------------
RUN useradd --system --create-home --shell /bin/false squirrelops && \
    chown -R squirrelops:squirrelops /app

# -----------------------------------------------------------------------
# Runtime configuration
# -----------------------------------------------------------------------
ENV SQUIRRELOPS_DATA_DIR=/app/data
ENV SQUIRRELOPS_PORT=8443

EXPOSE 8443

# -----------------------------------------------------------------------
# Health check -- probe the /system/health endpoint
# -----------------------------------------------------------------------
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD curl -f http://localhost:${SQUIRRELOPS_PORT}/system/health || exit 1

# -----------------------------------------------------------------------
# Entry point
# -----------------------------------------------------------------------
STOPSIGNAL SIGTERM
USER squirrelops
CMD ["uv", "run", "python", "-m", "squirrelops_home_sensor"]
