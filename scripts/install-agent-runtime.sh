#!/usr/bin/env bash
# install-agent-runtime.sh — assemble the agent-runtime box (Phase 4a/4b/4c).
#
# Runs INSIDE an agent-runtime LXC. Installs the two pieces the in-box loop
# needs so the daemon's `agent-runtime` exec (run mode) and serve mode work:
#   1. agent-box  (Go binary, the in-box MCP tool surface)
#   2. agent-runtime (the Node loop component) + a PATH launcher
# Node itself is installed by the recipe's post_start (Node 20).
#
# Artifacts are pulled from a GitHub release:
#   <base>/agent-box-linux-amd64
#   <base>/agent-runtime-bundle.tar.gz
# where <base> = https://github.com/<REPO>/releases/download/<RELEASE>.
# Built by `make build-agent-box-all` + `make bundle-agent-runtime`.
#
# Env:
#   REPO     default FootprintAI/Containarium
#   RELEASE  required — the release tag to pull (e.g. v0.27.0)
#   ARTIFACT_BASE_URL  optional — overrides the computed release base URL
set -euo pipefail

REPO="${REPO:-FootprintAI/Containarium}"
RELEASE="${RELEASE:-}"
if [[ -z "${ARTIFACT_BASE_URL:-}" ]]; then
  if [[ -z "$RELEASE" ]]; then
    echo "install-agent-runtime: set RELEASE (the release tag) or ARTIFACT_BASE_URL" >&2
    exit 2
  fi
  ARTIFACT_BASE_URL="https://github.com/${REPO}/releases/download/${RELEASE}"
fi

PREFIX="${PREFIX:-/usr/local/bin}"
APP_DIR="${APP_DIR:-/opt/agent-runtime}"

echo "==> installing agent-box from ${ARTIFACT_BASE_URL}"
curl -fsSL "${ARTIFACT_BASE_URL}/agent-box-linux-amd64" -o "${PREFIX}/agent-box" </dev/null
chmod +x "${PREFIX}/agent-box"

echo "==> installing agent-runtime component into ${APP_DIR}"
mkdir -p "${APP_DIR}"
curl -fsSL "${ARTIFACT_BASE_URL}/agent-runtime-bundle.tar.gz" -o /tmp/agent-runtime-bundle.tar.gz </dev/null
tar -xzf /tmp/agent-runtime-bundle.tar.gz -C "${APP_DIR}"
# The bundle ships dist/ + package manifests; install runtime deps (the agent
# harness SDKs) in-box. --omit=dev: we only need the runtime deps, not tsc.
( cd "${APP_DIR}" && npm ci --omit=dev )

# PATH launcher so the daemon's `agent-runtime` exec resolves (run + serve mode).
cat > "${PREFIX}/agent-runtime" <<LAUNCH
#!/usr/bin/env bash
exec node ${APP_DIR}/dist/index.js "\$@"
LAUNCH
chmod +x "${PREFIX}/agent-runtime"

echo "==> agent-runtime box assembled: $(command -v agent-box), $(command -v agent-runtime)"
