# containarium-otel-sidecar
#
# Per docs/PLATFORM-SIDECAR-DESIGN.md + docs/OTEL-AGENT-RELAY-DESIGN.md.
# Thin wrapper over a purpose-built collector with a fail-closed entrypoint
# that validates Containarium identity env vars before starting the
# collector. The upstream otel/opentelemetry-collector-contrib image
# is distroless (no shell), so we build on a slim Debian base — with a
# /bin/sh for the entrypoint script.
#
# The collector is compiled here from builder-manifest.yaml (only the
# components config.yaml uses) instead of downloading the upstream
# otelcol-contrib release tarball, whose stdlib and x/net are frozen at
# upstream's build time and failed the v0.101.0 Trivy gate with no fixed
# upstream release to move to.
#
# Image versions track the Containarium project release version per
# platform-sidecar decision #4: each Containarium release publishes
# matching tags ghcr.io/footprintai/containarium-otel-sidecar:vX.Y.Z.

FROM golang:1.26.9-bookworm AS build
# The image's Go is the toolchain the binary is built with; never let go.mod
# pull a different one (the stdlib CVE fixes depend on it).
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
# Same version as builder-manifest.yaml's otelcol_version.
ARG OTELCOL_VERSION=0.162.0
RUN go install go.opentelemetry.io/collector/cmd/builder@v${OTELCOL_VERSION}
COPY builder-manifest.yaml /build/builder-manifest.yaml
RUN builder --config /build/builder-manifest.yaml

FROM debian:bookworm-slim

# apt-get upgrade: picks up security patches that shipped since
# debian:bookworm-slim's last rebuild (e.g. libpcre2 deb12u2, which failed the
# release Trivy gate on v0.99.0). Same fix as images/agent-box/Dockerfile.
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates wget \
    && rm -rf /var/lib/apt/lists/*
# wget stays: the compose healthcheck internal/cmd/sidecar.go emits runs
# `wget -qO- http://localhost:13133/` inside this image.

COPY --from=build /out/otelcol-contrib /usr/local/bin/otelcol-contrib

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
