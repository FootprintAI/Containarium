# containarium-agent-box
#
# The in-the-box image for the Kubernetes backend (docs/K8S-AGENT-BOX-RUNTIME-DESIGN.md):
# a minimal SSH server whose every session is pinned by forced command to
# `agent-box` (the in-the-box MCP — shell/file ops over stdio). An agent reaches
# it over SSH and can do nothing but talk to agent-box.
#
# Hardening posture (matches the StatefulSet securityContext the daemon sets, so
# the pod satisfies the `restricted` Pod Security profile):
#   - runs as a non-root user (uid 1000)
#   - SSH listens on :2222, an UNPRIVILEGED port — so no capabilities are
#     needed at all (the agent connects to the gateway on :22; :2222 is the
#     internal sshpiper→pod hop).
#   - dropbear instead of OpenSSH: it runs cleanly rootless and supports a
#     forced command, so there's no sshd privsep/PAM/root dance.
#
# Published per-release as ghcr.io/footprintai/containarium-agent-box:vX.Y.Z.
# Build context is the repo root:
#   docker build -f images/agent-box/Dockerfile -t containarium-agent-box .

# --- build agent-box -------------------------------------------------------
# No `k8s` build tag here: agent-box is the in-box MCP and never imports
# client-go, so this stays a small static binary.
FROM golang:1.25.12-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/agent-box ./cmd/agent-box

# --- runtime: rootless dropbear + agent-box --------------------------------
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends dropbear-bin ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 --shell /bin/bash agent \
    && mkdir -p /home/agent/.ssh /etc/agent-box \
    && chown -R agent:agent /home/agent /etc/agent-box

COPY --from=build /out/agent-box /usr/local/bin/agent-box
# Plain COPY + chmod (not COPY --chmod) so the image also builds with the
# legacy builder, not only BuildKit.
COPY images/agent-box/entrypoint.sh /usr/local/bin/agent-box-entrypoint.sh
RUN chmod 0755 /usr/local/bin/agent-box-entrypoint.sh

USER agent
ENV HOME=/home/agent
# Documentation only; the entrypoint binds this port.
EXPOSE 2222
ENTRYPOINT ["/usr/local/bin/agent-box-entrypoint.sh"]
