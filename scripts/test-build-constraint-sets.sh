#!/usr/bin/env bash
# Whole-tree build-constraint gate (#2864, #2886).
#
# The client-split gates build ./cmd/containarium with -tags
# containarium_client and for GOOS=windows, but only that binary's graph.
# Packages outside it could drift out of sync with the constraints of the
# packages they use, so a broad local `go vet -tags containarium_client
# ./...` or `GOOS=windows go build ./...` failed on a clean main and was
# easy to misread as a regression in an unrelated change. This script runs
# both whole-tree invocations so the tree stays consistent:
#
#   1. go vet -tags containarium_client ./...   (every package, tests too)
#   2. GOOS=windows go build <every package except WINDOWS_EXCLUDED>
#
# WINDOWS_EXCLUDED is the daemon side, which ships for Linux only. Each
# entry is there because it is, or imports, one of two Linux-only roots:
#   - internal/agentbox: Unix process and file-locking APIs; every file is
#     //go:build !windows on purpose (cli-split-gates.yml checks that).
#   - internal/netbpf: cilium/ebpf's Linux attach API (link.AttachTCX,
#     link.Tracepoint, perf.Record) has no Windows build.
# The list is explicit, not computed: a new package that stops building for
# Windows fails this gate, and adding it here is a reviewed decision. A
# package listed here that builds for Windows again also fails, so the list
# cannot keep stale entries.
set -uo pipefail
cd "$(dirname "$0")/.."

MOD="github.com/footprintai/containarium"
WINDOWS_EXCLUDED=(
  # Linux-only roots.
  "$MOD/internal/netbpf"
  "$MOD/cmd/ebpf-phase0"          # uses cilium/ebpf link.AttachTCX directly
  # Import internal/agentbox (via internal/server).
  "$MOD/internal/server"
  "$MOD/internal/cmd"             # untagged daemon tree; the tagged client build is checked separately
  "$MOD/cmd/containariumd"
  "$MOD/cmd/netpolicy-smoke"
  # Import internal/netbpf.
  "$MOD/internal/threatdetect"
  "$MOD/internal/security"
  "$MOD/internal/sentinel"
  "$MOD/internal/gateway"
  "$MOD/pkg/core/box/k8s"
  "$MOD/cmd/ebpf-phaseA"
  "$MOD/test/fixtures/proxyproto-relay"
)

fail=0

echo "== go vet -tags containarium_client ./..."
if go vet -tags containarium_client ./...; then
  echo "PASS  client-tag vet over the whole tree"
else
  echo "FAIL  go vet -tags containarium_client ./... (a file that uses a !containarium_client symbol needs the same constraint)"
  fail=1
fi

echo "== GOOS=windows go build (whole tree minus the Linux-only daemon set)"
# Packages with Go files for Windows. Packages whose files are all excluded
# for Windows (internal/agentbox, cmd/agent-box) or that hold only tests
# print nothing here, as `go build ./...` skips them too.
all="$(GOOS=windows GOARCH=amd64 go list -e -f '{{if .GoFiles}}{{.ImportPath}}{{end}}' ./...)"
if [ -z "$all" ]; then
  echo "FAIL  'go list ./...' for windows produced no packages — the command itself is broken, not passing"
  exit 1
fi
excluded="$(printf '%s\n' "${WINDOWS_EXCLUDED[@]}")"
pkgs=()
while IFS= read -r p; do pkgs+=("$p"); done < <(echo "$all" | grep -vxF "$excluded")
if GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o /dev/null "${pkgs[@]}"; then
  echo "PASS  ${#pkgs[@]} packages build for windows/amd64 (${#WINDOWS_EXCLUDED[@]} excluded)"
else
  echo "FAIL  windows build. If the failing package is daemon-only and imports internal/agentbox or internal/netbpf, add it to WINDOWS_EXCLUDED with the reason; otherwise guard the Unix-only file with a build constraint."
  fail=1
fi

# A stale entry hides nothing today but would hide a real regression later.
for pkg in "${WINDOWS_EXCLUDED[@]}"; do
  if ! echo "$all" | grep -qxF "$pkg"; then
    echo "FAIL  $pkg is in WINDOWS_EXCLUDED but is not a package with Windows Go files; remove it"
    fail=1
  elif GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o /dev/null "$pkg" >/dev/null 2>&1; then
    echo "FAIL  $pkg is in WINDOWS_EXCLUDED but builds for windows; remove it from the list"
    fail=1
  fi
done

exit "$fail"
