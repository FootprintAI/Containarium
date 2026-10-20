#!/usr/bin/env bash
# Fail if any GitHub Actions `uses:` is not pinned to a full 40-hex commit SHA.
#
# Usage:
#   scripts/ci/check-action-pins.sh [dir-or-file ...]   # default: .github
#   scripts/ci/check-action-pins.sh --self-test
#
# Scans workflow files (*.yml, *.yaml) and composite actions under the given
# paths. Exempt, by design:
#   - local references (`uses: ./...`), which are pinned by the checkout itself;
#   - `docker://` references that carry an @sha256:<64-hex> digest.
# There is no other allowlist. To add one, list it here with a reason.
set -euo pipefail

SHA_RE='^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$'
DIGEST_RE='^docker://.+@sha256:[0-9a-f]{64}$'

check() {
  local bad=0 file ref
  while IFS= read -r -d '' file; do
    while IFS=$'\t' read -r lineno ref; do
      case "$ref" in
        ./*) continue ;;
      esac
      if [[ "$ref" =~ $SHA_RE || "$ref" =~ $DIGEST_RE ]]; then continue; fi
      echo "UNPINNED: $file:$lineno: uses: $ref"
      bad=1
    done < <(awk -v q="'" '
               /^[[:space:]]*#/ {next}
               match($0, /^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]*/) {
                 r = substr($0, RLENGTH + 1)
                 if (substr(r,1,1)=="\"" || substr(r,1,1)==q) r = substr(r,2)
                 sub(/["\t #].*$/, "", r); sub(q ".*$", "", r)
                 printf "%d\t%s\n", NR, r
               }' "$file")
  done < <(find "$@" -type f \( -name '*.yml' -o -name '*.yaml' \) -print0)
  return "$bad"
}

self_test() {
  local d
  d=$(mktemp -d); trap 'rm -rf "$d"' RETURN
  cat >"$d/tag.yml" <<'Y'
jobs:
  a:
    steps:
      - uses: actions/checkout@v4
Y
  cat >"$d/branch.yml" <<'Y'
jobs:
  a:
    steps:
      - uses: aquasecurity/trivy-action@master
Y
  cat >"$d/pass.yml" <<'Y'
jobs:
  a:
    uses: ./.github/workflows/x.yml
    steps:
      # uses: actions/checkout@v4 (comment is ignored)
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7
      - uses: "docker://alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000"
Y
  mkdir "$d/t" "$d/b" "$d/p"; mv "$d/tag.yml" "$d/t/"; mv "$d/branch.yml" "$d/b/"; mv "$d/pass.yml" "$d/p/"
  for c in t b; do
    if check "$d/$c" >/dev/null; then echo "self-test FAIL: tag/branch pin accepted ($c)"; return 1; fi
  done
  check "$d/p" >/dev/null || { echo "self-test FAIL: SHA-pinned fixture rejected"; check "$d/p"; return 1; }
  echo "self-test ok: tag and branch pins rejected, SHA/local/digest pins accepted"
}

if [[ "${1:-}" == "--self-test" ]]; then self_test; exit; fi
[[ $# -gt 0 ]] || set -- .github
if check "$@"; then echo "all uses: references are SHA-pinned"; else
  echo "Pin each action to a full commit SHA with the ref as a trailing comment: uses: owner/repo@<40-hex> # v1.2.3" >&2
  exit 1
fi
