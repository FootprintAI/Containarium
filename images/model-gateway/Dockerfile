# containarium-model-gateway
#
# The model-gateway credential proxy (cmd/model-gateway,
# docs/AGENT-MODEL-GATEWAY-DESIGN.md): the single egress point that holds
# real provider API keys, verifies a box's scoped gateway token, injects the
# real key, and proxies to the provider. Runs standalone — no LXC daemon
# required — which is the point of shipping it as its own image: it can run
# as a plain pod in front of an agent sandbox (see
# docs/architecture/execution-scoped-authorization.md, "Model gateway admin
# revoke and image", and the upstream agent-sandbox example that deploys it).
#
# Published per-release as
# ghcr.io/footprintai/containarium-model-gateway:vX.Y.Z / :latest by
# .github/workflows/release.yml (release tags), mirroring the daemon
# (images/daemon/Dockerfile) and sidecar images. Build context is the repo
# root:
#   docker build -f images/model-gateway/Dockerfile -t containarium-model-gateway .
#
# Keys and the admin token enter by env (provider keys, e.g. ANTHROPIC_API_KEY)
# and mounted files (--secret-file, --admin-token-file) only — never baked
# into the image.

# --- build the gateway ------------------------------------------------------
FROM golang:1.26.7-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/model-gateway ./cmd/model-gateway

# --- runtime ---------------------------------------------------------------
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 --shell /usr/sbin/nologin model-gateway

COPY --from=build /out/model-gateway /usr/local/bin/model-gateway

USER model-gateway
ENV HOME=/home/model-gateway
# Data plane + admin mux (/__gateway/*) — documentation only; the gateway
# binds this single port for both.
EXPOSE 8866
ENTRYPOINT ["/usr/local/bin/model-gateway"]
# `serve` is the default subcommand; `mint`/`revoke` are one-shot CLI calls an
# operator runs with `docker run <image> mint ...` / `... revoke ...`,
# overriding this CMD.
CMD ["serve"]
