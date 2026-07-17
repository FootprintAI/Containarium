# containarium (daemon)
#
# The Containarium daemon image for the Kubernetes runtime: the control plane
# the containarium-k8s Helm chart deploys (charts/containarium-k8s/). It serves
# the gRPC + REST API, drives the box backend, and — when
# CONTAINARIUM_K8S_OPERATOR is set — runs the Box CRD controller.
#
# Published per-release as ghcr.io/footprintai/containarium:vX.Y.Z / :latest by
# .github/workflows/containarium-daemon.yml (release tags), mirroring the
# sidecar images. Build context is the repo root:
#   docker build -f images/daemon/Dockerfile --build-arg VERSION=0.53.0 -t containarium .
#
# Note: built WITHOUT `-tags embed_bpf`. The eBPF network-isolation features
# (phase A) need a pre-compiled BPF object; they're not part of the k8s-runtime
# daemon image, which isolates tenants via NetworkPolicy. eBPF-embedded builds
# remain the binary release (`make build-release`).

# --- build the daemon ------------------------------------------------------
FROM golang:1.26.5-bookworm AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO_ENABLED=0 → a fully static binary (matches make build-release). The k8s
# backend has no build tag on non-test sources, so a plain build includes it.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w -X github.com/footprintai/containarium/pkg/version.Version=${VERSION}" \
    -o /out/containarium ./cmd/containarium

# --- runtime ---------------------------------------------------------------
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 --shell /usr/sbin/nologin containarium

COPY --from=build /out/containarium /usr/local/bin/containarium

USER containarium
ENV HOME=/home/containarium
# gRPC (50051) + REST (8080) — documentation only; the daemon binds these.
EXPOSE 8080 50051
ENTRYPOINT ["/usr/local/bin/containarium"]
