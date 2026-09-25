#!/usr/bin/env bash
# install-agent-runtime.sh — assemble the agent-runtime box (Phase 4a/4b/4c).
#
# Runs INSIDE an agent-runtime LXC. Installs the pieces the in-box loop needs
# so the daemon's `agent-runtime` exec (run mode) and serve mode work:
#   1. agent-box  (Go binary, the in-box MCP tool surface)
#   2. mcp-server (Go binary, the platform MCP — spawned by agent-runtime for a
#      run bound to a tracker connection; #1922 D4). Best-effort, see below.
#   3. agent-runtime (the Node loop component) + a PATH launcher
# Node itself is installed by the recipe's post_start (Node 20).
#
# Artifacts are pulled from a GitHub release:
#   <base>/agent-box-linux-amd64
#   <base>/mcp-server-linux-amd64
#   <base>/agent-runtime-bundle.tar.gz
# where <base> = https://github.com/<REPO>/releases/download/<RELEASE>.
# Built by `make build-agent-box-all` + `make bundle-agent-runtime`.
#
# Flags:
#   --no-agent-runtime  install agent-box + mcp-server only; skip the Node
#                       bundle, npm ci, and the agent-runtime launcher (for
#                       boxes that run a coding agent directly, e.g. the
#                       `coding-agent` recipe, and need no Node loop).
#
# Env:
#   REPO     default FootprintAI/Containarium
#   RELEASE  required — the release tag to pull (e.g. v0.27.0)
#   ARTIFACT_BASE_URL  optional — overrides the computed release base URL
set -euo pipefail

INSTALL_AGENT_RUNTIME=1
for arg in "$@"; do
  case "$arg" in
    --no-agent-runtime) INSTALL_AGENT_RUNTIME=0 ;;
    *)
      echo "install-agent-runtime: unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

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

# mcp-server is what agent-runtime spawns to give a tracker-bound run its
# tracker_* tools (the daemon seeds that mount whether or not this binary
# exists). Best-effort on purpose: a release without the asset must not take
# down every agent box, since boxes not bound to a tracker never needed it —
# but the gap is loud, because the alternative is an agent that silently has no
# tracker tools. Downloaded to a temp file and moved into place so a failed
# fetch never leaves a truncated binary on PATH.
echo "==> installing mcp-server from ${ARTIFACT_BASE_URL}"
MCP_TMP="$(mktemp)"
if curl -fsSL "${ARTIFACT_BASE_URL}/mcp-server-linux-amd64" -o "${MCP_TMP}" </dev/null; then
  chmod +x "${MCP_TMP}"
  mv "${MCP_TMP}" "${PREFIX}/mcp-server"
else
  rm -f "${MCP_TMP}"
  echo "WARNING: could not fetch mcp-server-linux-amd64 from ${ARTIFACT_BASE_URL}; tracker tools will NOT work in this box (runs bound to a tracker connection get no tracker_* tools)" >&2
fi

if [[ "$INSTALL_AGENT_RUNTIME" -eq 0 ]]; then
  echo "==> agent-box + mcp-server installed (--no-agent-runtime): $(command -v agent-box || echo "${PREFIX}/agent-box"), $(command -v mcp-server || echo 'mcp-server MISSING')"
  exit 0
fi

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

echo "==> agent-runtime box assembled: $(command -v agent-box), $(command -v mcp-server || echo 'mcp-server MISSING'), $(command -v agent-runtime)"
