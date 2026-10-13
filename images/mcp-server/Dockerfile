# containarium-mcp-server
#
# The platform MCP server (cmd/mcp-server): the outside-the-box admin
# surface (create_container, list_containers, expose_port, ...). Reached
# over stdio (JSON-RPC), speaking HTTP + JWT Bearer to the Containarium
# REST API — see cmd/mcp-server/README.md for the full contract.
#
# This image exists so the server can be built, deployed, and scored
# (glama.ai) as a standalone MCP server (Containarium#967). It is a pure-Go
# REST/gRPC client with no host-side dependencies (unlike cmd/agent-box,
# which must run inside a Containarium box).
#
# Build (context is the repo root):
#   docker build -f images/mcp-server/Dockerfile -t containarium-mcp-server .
#
# Run (stdio MCP transport — attach stdin/stdout, e.g. `docker run -i`):
#   docker run -i --rm \
#     -e CONTAINARIUM_SERVER_URL=http://host.docker.internal:8080 \
#     -e CONTAINARIUM_JWT_TOKEN=... \
#     containarium-mcp-server

FROM golang:1.26.9-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/mcp-server ./cmd/mcp-server

FROM debian:bookworm-slim
# apt-get upgrade: picks up security patches that shipped since
# debian:bookworm-slim's last rebuild (e.g. libpcre2 deb12u2, which failed the
# release Trivy gate for the other images on v0.99.0). Same fix as
# images/agent-box/Dockerfile.
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 --shell /usr/sbin/nologin mcp

COPY --from=build /out/mcp-server /usr/local/bin/mcp-server

USER mcp
ENV HOME=/home/mcp
# Required at runtime (see cmd/mcp-server/README.md):
#   CONTAINARIUM_SERVER_URL, and one of CONTAINARIUM_JWT_TOKEN /
#   CONTAINARIUM_JWT_TOKEN_FILE. No ports are exposed — the MCP protocol
# runs over stdio, not a network listener.
ENTRYPOINT ["/usr/local/bin/mcp-server"]
