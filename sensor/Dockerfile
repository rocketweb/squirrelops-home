# SquirrelOps Home -- sensor and constrained Linux network-helper images
#
# Sensor:
#   docker build --target sensor -t squirrelops-sensor .
# Network helper:
#   docker build --target network-helper -t squirrelops-network-helper .

FROM ghcr.io/astral-sh/uv:0.10.2@sha256:94a23af2d50e97b87b522d3cea24aaf8a1faedec1344c952767434f69585cbf9 AS uv
FROM python:3.11-slim-bookworm@sha256:b18992999dbe963a45a8a4da40ac2b1975be1a776d939d098c647482bcad5cba AS app

ARG VERSION=dev

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        iproute2 \
        iptables \
        libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=uv /uv /usr/local/bin/uv

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY src/ ./src/
COPY config/ ./config/
COPY signatures/ ./signatures/
RUN uv sync --frozen --no-dev --no-editable

# A fixed numeric identity lets the helper authenticate the sensor with
# SO_PEERCRED even though the processes run in separate containers.
RUN groupadd --system --gid 10001 squirrelops && \
    useradd --system --uid 10001 --gid 10001 \
        --create-home --shell /usr/sbin/nologin squirrelops && \
    mkdir -p /app/data && \
    chown -R 10001:10001 /app

ENV SQUIRRELOPS_DATA_DIR=/app/data
ENV SQUIRRELOPS_PORT=8443
ENV SQUIRRELOPS_NETWORK_HELPER_SOCKET=/run/squirrelops/network-helper.sock
ENV SQUIRRELOPS_SENSOR_BRIDGE_IP=172.30.0.2

STOPSIGNAL SIGTERM

FROM app AS network-helper

USER root
LABEL org.opencontainers.image.title="SquirrelOps Home Network Helper" \
      org.opencontainers.image.description="Constrained Linux network companion for SquirrelOps Home" \
      org.opencontainers.image.source="https://github.com/rocketweb/squirrelops-home" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 CMD ["/app/.venv/bin/python", "-m", "squirrelops_home_sensor.privileged.linux_sidecar", "--healthcheck"]
CMD ["/app/.venv/bin/python", "-m", "squirrelops_home_sensor.privileged.linux_sidecar"]

# Keep the sensor target last: release builds that omit --target must produce
# the unprivileged sensor entry point. The published image can also run the
# helper command under the separately constrained Compose service.
FROM app AS sensor

LABEL org.opencontainers.image.title="SquirrelOps Home Sensor" \
      org.opencontainers.image.description="Unprivileged home network security sensor with constrained helper entry point" \
      org.opencontainers.image.source="https://github.com/rocketweb/squirrelops-home" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"

EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD curl -fsSk https://localhost:${SQUIRRELOPS_PORT}/system/health || exit 1

USER 10001:10001
CMD ["/app/.venv/bin/python", "-m", "squirrelops_home_sensor"]
