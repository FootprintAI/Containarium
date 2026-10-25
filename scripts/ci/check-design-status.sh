#!/usr/bin/env bash
# Fail when a design document has no Status line (#2558).
#
# Usage:
#   scripts/ci/check-design-status.sh [docs-root]     # default: docs
#   scripts/ci/check-design-status.sh --self-test
#
# Checked: docs/*DESIGN*.md and docs/architecture/*.md.
# A Status line is one of the first 30 lines that starts with `Status:`,
# optionally behind `> ` and/or bold/italic markers, or `| Status |` in a
# table. It must also say something: at least one word after the marker.
# A design note whose work shipped must say so (README, "Design documents"
# in docs/security/CLAIMS.md); this gate only proves the line exists.
set -euo pipefail

STATUS_RE='^(>[[:space:]]*)?([*_]{0,2})status([*_]{0,2})[[:space:]]*(:|\|)[[:space:]*_]*[[:alnum:]]'

check() {
  local root=$1 f bad=0
  while IFS= read -r -d '' f; do
    if ! head -n 30 "$f" | grep -qiE "$STATUS_RE"; then
      echo "NO STATUS: $f"; bad=1
    fi
  done < <(find "$root" -maxdepth 1 -type f -name '*DESIGN*.md' -print0 | sort -z; \
           find "$root/architecture" -maxdepth 1 -type f -name '*.md' -print0 | sort -z)
  return "$bad"
}

self_test() {
  local d rc=0
  d=$(mktemp -d); trap 'rm -rf "$d"' RETURN
  mkdir -p "$d/architecture"
  printf '# A\n\nNo status here.\n' >"$d/FOO-DESIGN.md"
  printf '# B\n\n> Status: **Implemented**\n' >"$d/BAR-DESIGN.md"
  printf '# C\n\nStatus:\n' >"$d/architecture/empty.md"
  printf '# D\n\n**Status:** accepted\n' >"$d/architecture/ok.md"
  local out; out=$(check "$d" 2>&1) && { echo "self-test FAIL: seeded gaps accepted"; return 1; }
  for want in FOO-DESIGN.md architecture/empty.md; do
    grep -q "$want" <<<"$out" || { echo "self-test FAIL: $want not flagged"; rc=1; }
  done
  for no in BAR-DESIGN.md architecture/ok.md; do
    ! grep -q "$no" <<<"$out" || { echo "self-test FAIL: $no wrongly flagged"; rc=1; }
  done
  [[ $rc -eq 0 ]] && echo "self-test ok: missing and empty Status lines rejected, real ones accepted"
  return $rc
}

if [[ "${1:-}" == "--self-test" ]]; then self_test; exit; fi
if check "${1:-docs}"; then echo "every design doc has a Status line"; else
  echo "Add a Status line (e.g. '> Status: **Implemented** (<code path>)') within the first 30 lines." >&2
  exit 1
fi
