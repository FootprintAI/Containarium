#!/bin/sh
# containarium-otel-sidecar entrypoint
#
# Validates the identity env vars Containarium stamps via the LXC's
# --monitoring flag before handing off to otelcol-contrib. Fail-closed
# per the platform-sidecar contract: missing required env = exit
# non-zero with a clear message, so `docker compose up` reports it.
#
# See docs/OTEL-AGENT-RELAY-DESIGN.md.

set -eu

missing=""
for var in CONTAINARIUM_CONTAINER_ID CONTAINARIUM_BACKEND_ID CONTAINARIUM_TENANT_ID OTEL_EXPORTER_OTLP_ENDPOINT; do
    eval "val=\${$var:-}"
    if [ -z "$val" ]; then
        missing="$missing $var"
    fi
done

if [ -n "$missing" ]; then
    cat >&2 <<EOF
containarium-otel-sidecar: required identity env vars unset:$missing

The platform stamps these on a --monitoring=true LXC. If you're
seeing this from inside docker-compose, your compose service is
missing the \${VAR} interpolation, e.g.:

  payment-api-otel:
    image: ghcr.io/footprintai/containarium-otel-sidecar:v0.16.10
    environment:
      OTEL_EXPORTER_OTLP_ENDPOINT: \${OTEL_EXPORTER_OTLP_ENDPOINT}
      CONTAINARIUM_CONTAINER_ID:   \${CONTAINARIUM_CONTAINER_ID}
      CONTAINARIUM_BACKEND_ID:     \${CONTAINARIUM_BACKEND_ID}
      CONTAINARIUM_TENANT_ID:      \${CONTAINARIUM_TENANT_ID}

If the LXC itself is missing these, enable monitoring on it:
  containarium monitoring enable <username>

See docs/OTEL-AGENT-RELAY-DESIGN.md for the full contract.
EOF
    exit 64
fi

# SERVICE_VERSION is tenant-controlled and optional. We default to
# "unset" here (rather than leaving the env unset and tripping the
# OTel collector's "value must be specified" check on an empty
# interpolation result) so the `insert` action in the resource
# processor has something to write. Tenants who care about
# canary/rollback breakdowns set their own SERVICE_VERSION in compose.
: "${SERVICE_VERSION:=unset}"
export SERVICE_VERSION

exec /usr/local/bin/otelcol-contrib --config=/etc/otelcol-contrib/config.yaml
