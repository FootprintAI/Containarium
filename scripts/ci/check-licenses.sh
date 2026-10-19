#!/usr/bin/env bash
# Dependency licence gate (#2561): every Go module linked into a binary we ship
# must carry a licence on the allow-list. Run it locally the same way CI does:
#
#   go install github.com/google/go-licenses@v1.6.0
#   scripts/ci/check-licenses.sh
#
# What is checked: the full transitive package graph of each shipped program
# (the daemon, the platform MCP, agent-box, the model gateway, and the client
# built with -tags containarium_client), not just go.mod's direct requirements.
# The allow-list and the two exceptions are policy; see
# docs/security/DEPENDENCY-LICENSES.md before changing them.
set -euo pipefail

GO_LICENSES="${GO_LICENSES:-go-licenses}"
command -v "$GO_LICENSES" >/dev/null || { echo "go-licenses not found; go install github.com/google/go-licenses@v1.6.0" >&2; exit 2; }

# go-licenses resolves the standard library through GOROOT and reports every
# stdlib package as "does not have module info" without it.
GOROOT="$(go env GOROOT)"
export GOROOT

# Permissive licences, plus MPL-2.0: weak, file-level copyleft that only
# obliges us to keep MPL-covered files' source available, which unmodified
# dependencies already satisfy. Strong copyleft (GPL, AGPL, LGPL, SSPL) and
# source-available licences (BUSL) are deliberately not listed.
ALLOWED="Apache-2.0,MIT,BSD-2-Clause,BSD-3-Clause,ISC,Unlicense,MPL-2.0"

# Not third-party code:
#   - this repository's own module.
# Shipped without a licence file in its module zip but Apache-2.0 upstream
# (the GitHub repository declares Apache-2.0; its LICENSE is not at the module
# subdirectory go-licenses scans):
#   - github.com/rootless-containers/proto/go-proto
IGNORES=(--ignore github.com/footprintai/containarium --ignore github.com/rootless-containers/proto/go-proto)

log="$(mktemp)"
trap 'rm -f "$log"' EXIT

check() {
  local label="$1"; shift
  if "$GO_LICENSES" check "$@" --allowed_licenses="$ALLOWED" "${IGNORES[@]}" >"$log" 2>&1; then
    echo "licences ok: $label"
    return 0
  fi
  echo "::error::licence check failed for $label" >&2
  # The findings are the lines go-licenses itself prints as "Not allowed" or
  # "Forbidden"; the rest is progress noise (assembly-file notices).
  grep -E "Not allowed|Forbidden|Failed to find license|cannot find" "$log" >&2 || cat "$log" >&2
  return 1
}

rc=0
check "daemon, platform MCP, agent-box, model gateway" \
  ./cmd/containariumd ./cmd/mcp-server ./cmd/agent-box ./cmd/model-gateway || rc=1
GOFLAGS="${GOFLAGS:-} -tags=containarium_client" check "client CLI (-tags containarium_client)" \
  ./cmd/containarium || rc=1
exit "$rc"
