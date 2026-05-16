# containarium-otel-sidecar
#
# Per docs/PLATFORM-SIDECAR-DESIGN.md + docs/OTEL-AGENT-RELAY-DESIGN.md.
# Thin wrapper over otelcol-contrib with a fail-closed entrypoint that
# validates Containarium identity env vars before starting the
# collector. The upstream otel/opentelemetry-collector-contrib image
# is distroless (no shell), so we build on a slim Debian base and
# install the binary from the upstream release tarball — same result,
# but with a /bin/sh for the entrypoint script.
#
# Image versions track the Containarium project release version per
# platform-sidecar decision #4: each Containarium release publishes
# matching tags ghcr.io/footprintai/containarium-otel-sidecar:vX.Y.Z.

FROM debian:bookworm-slim

# Pin to the same upstream collector version the central
# containarium-core-otelcollector LXC runs (decision O1).
ARG OTELCOL_VERSION=0.110.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates wget \
    && rm -rf /var/lib/apt/lists/*

RUN wget -qO /tmp/otelcol.tar.gz \
        "https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v${OTELCOL_VERSION}/otelcol-contrib_${OTELCOL_VERSION}_linux_amd64.tar.gz" \
    && tar -xzf /tmp/otelcol.tar.gz -C /usr/local/bin/ otelcol-contrib \
    && chmod +x /usr/local/bin/otelcol-contrib \
    && rm /tmp/otelcol.tar.gz

# Baked-in config (image is config-immutable per platform-sidecar
# contract). Operators who want a different config write a different
# image.
COPY config.yaml /etc/otelcol-contrib/config.yaml

# Entrypoint validates required identity env vars and fail-closes if
# any are missing (platform-sidecar contract point 3). --chmod=0755
# so we don't depend on the host's executable bit propagating.
COPY --chmod=0755 entrypoint.sh /usr/local/bin/containarium-entrypoint.sh

# Expose for documentation only — actual listening is controlled by
# the config.
EXPOSE 4317 4318 13133

ENTRYPOINT ["/usr/local/bin/containarium-entrypoint.sh"]
