#!/usr/bin/env bash
# Build or check the NOTICE file (#2561).
#
#   scripts/ci/notice.sh generate   write NOTICE to stdout
#   scripts/ci/notice.sh check      fail if NOTICE is missing a module that needs it
#
# Apache-2.0 section 4(d): a redistribution that includes a work with a NOTICE
# file must carry that file's attribution notices. A Go binary embeds its
# dependencies, so the NOTICE texts of every module linked into a program we
# ship belong in ours. `generate` collects them; `check` is the CI half, so a
# new dependency that brings a NOTICE of its own cannot be added without the
# file being regenerated.
#
# Same program set, and same build tag for the client CLI, as
# scripts/ci/check-licenses.sh. Needs the module cache (go mod download).
set -euo pipefail

mode="${1:?usage: notice.sh generate|check}"
cd "$(dirname "$0")/../.."

# "<module> <version> <dir>" for every non-main module linked into a shipped
# program.
modules() {
  {
    go list -deps -f '{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}} {{.Dir}}{{end}}{{end}}' \
      ./cmd/containariumd ./cmd/mcp-server ./cmd/agent-box ./cmd/model-gateway
    GOFLAGS="${GOFLAGS:-} -tags=containarium_client" \
      go list -deps -f '{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}} {{.Dir}}{{end}}{{end}}' \
      ./cmd/containarium
  } | sort -u
}

# Print "<module> <version> <notice file>" for those that carry a NOTICE.
with_notice() {
  local p v d f
  while read -r p v d; do
    [ -n "$d" ] || continue
    for f in "$d"/NOTICE "$d"/NOTICE.txt "$d"/NOTICE.md; do
      [ -f "$f" ] && echo "$p $v $f"
    done
  done < <(modules) | sort -u
}

case "$mode" in
generate)
  cat <<'HEADER'
Containarium
Copyright 2025-2026 FootprintAI

This product is licensed under the Apache License, Version 2.0 (see LICENSE).
The names Containarium and Containarium Cloud are not licensed under it; see
TRADEMARKS.md.

This product includes software developed by third parties. Their licences are
recorded per module by the dependency licence check
(docs/security/DEPENDENCY-LICENSES.md). The notices below are the ones those
projects ask redistributors to carry.

================================================================================
Vendored protocol definitions (third_party/proto)
================================================================================

third_party/proto/externalgrpc is the cluster-autoscaler external gRPC provider
contract, vendored from github.com/kubernetes/autoscaler (cluster-autoscaler
1.33.0), and third_party/proto/k8s.io holds the Kubernetes API protos it imports.
Code generated from them is in pkg/pb/thirdparty.

  Copyright The Kubernetes Authors.
  Licensed under the Apache License, Version 2.0.
  http://www.apache.org/licenses/LICENSE-2.0

================================================================================
Notices from Go dependencies linked into the shipped programs
================================================================================
HEADER
  with_notice | while read -r p v f; do
    printf '\n== %s %s ==\n\n' "$p" "$v"
    cat "$f"
    printf '\n'
  done
  ;;
check)
  [ -f NOTICE ] || { echo "::error::NOTICE is missing; run scripts/ci/notice.sh generate > NOTICE" >&2; exit 1; }
  missing=0
  while read -r p v _; do
    grep -qF "== $p " NOTICE || { echo "::error::NOTICE has no section for $p $v, which ships a NOTICE file" >&2; missing=1; }
  done < <(with_notice)
  [ "$missing" -eq 0 ] || { echo "regenerate: scripts/ci/notice.sh generate > NOTICE" >&2; exit 1; }
  echo "NOTICE ok: $(with_notice | wc -l | tr -d ' ') module notices present"
  ;;
*)
  echo "usage: notice.sh generate|check" >&2; exit 2 ;;
esac
