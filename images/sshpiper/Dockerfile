# containarium-sshpiper
#
# The SSH gateway image for the Kubernetes backend: sshpiperd with its
# bundled plugins, from the SAME pinned upstream release the sentinel
# installs (terraform startup-sentinel.sh pins SSHPIPER_VERSION) — one
# canonical gateway version across the LXC and K8s worlds, published under
# our registry so the chart never depends on a third-party :latest tag
# (Containarium#976).
#
# Published per-release as ghcr.io/footprintai/containarium-sshpiper (see
# .github/workflows/sidecars.yml). Build:
#   docker build -f images/sshpiper/Dockerfile -t containarium-sshpiper images/sshpiper
#
# Runtime contract (drop-in for the deployment shape the chart/example use):
#   - PLUGIN selects the routing plugin (default: kubernetes)
#   - SSHPIPERD_* env flows through to sshpiperd (SERVER_KEY, LOG_LEVEL, ...)
#   - listens on :2222, runs as non-root uid 1000

FROM debian:bookworm-slim AS fetch
ARG SSHPIPER_VERSION=v1.5.3
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /sshpiperd \
    && curl -fsSL "https://github.com/tg123/sshpiper/releases/download/${SSHPIPER_VERSION}/sshpiperd_with_plugins_linux_x86_64.tar.gz" \
       | tar -xz -C /sshpiperd \
    && test -x /sshpiperd/sshpiperd

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 --shell /usr/sbin/nologin sshpiper
COPY --from=fetch /sshpiperd /sshpiperd
COPY entrypoint.sh /sshpiperd/entrypoint.sh
RUN chmod 0755 /sshpiperd/entrypoint.sh

USER sshpiper
EXPOSE 2222
ENTRYPOINT ["/sshpiperd/entrypoint.sh"]
