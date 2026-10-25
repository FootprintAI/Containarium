#!/usr/bin/env bash
# Fail unless .github/CODEOWNERS covers every path decided on #2649 (Q1) and
# names the required owners on each of those lines.
#
# Usage:
#   scripts/ci/check-codeowners.sh [CODEOWNERS-file]   # default: .github/CODEOWNERS
#   scripts/ci/check-codeowners.sh --self-test
#
# The decided path list is exact patterns, not a glob match: a pattern that is
# present but spelled differently (e.g. `/go.mod` for `go.mod`) fails, so the
# file and the decision stay in step. Owners are the two current repository
# admins (#2792); change REQUIRED_OWNERS when a team replaces them.
set -euo pipefail

REQUIRED_PATHS=(
  'go.mod'
  'go.sum'
  '.github/**'
  'Makefile'
  'scripts/**'
  'install.sh'
  '**/Dockerfile*'
  '**/package*.json'
  'proto/**'
  'deploy/**'
  'terraform/**'
)
REQUIRED_OWNERS=(@hsinhoyeh @hsinatfootprintai)

check() {
  local file=$1 bad=0 p o line
  if [[ ! -f "$file" ]]; then
    echo "MISSING FILE: $file"
    return 1
  fi
  for p in "${REQUIRED_PATHS[@]}"; do
    # first field must equal the pattern exactly; comments are skipped
    line=$(awk -v p="$p" '$0 !~ /^[[:space:]]*#/ && $1 == p {print; exit}' "$file")
    if [[ -z "$line" ]]; then
      echo "UNCOVERED: no CODEOWNERS line for pattern: $p"
      bad=1
      continue
    fi
    for o in "${REQUIRED_OWNERS[@]}"; do
      if ! awk -v l="$line" -v o="$o" 'BEGIN{n=split(l,f,/[ \t]+/); for(i=2;i<=n;i++) if(f[i]==o) exit 0; exit 1}'; then
        echo "MISSING OWNER: $o on pattern: $p"
        bad=1
      fi
    done
  done
  return "$bad"
}

self_test() {
  local d rc=0
  d=$(mktemp -d); trap 'rm -rf "$d"' RETURN
  local good="$d/good"
  : >"$good"
  for p in "${REQUIRED_PATHS[@]}"; do echo "$p ${REQUIRED_OWNERS[*]}" >>"$good"; done
  # a comment line naming a pattern must not count as coverage
  printf '# terraform/** @nobody\n' >"$d/comment-only"
  grep -v '^terraform/' "$good" >>"$d/comment-only"
  grep -v '^deploy/' "$good" >"$d/missing-path"
  sed 's/^go.sum .*/go.sum @hsinhoyeh/' "$good" >"$d/missing-owner"
  sed 's#^install.sh #/install.sh #' "$good" >"$d/respelled"

  check "$good" >/dev/null || { echo "SELF-TEST FAIL: complete file rejected"; rc=1; }
  local bad
  for bad in missing-path missing-owner respelled comment-only; do
    if check "$d/$bad" >/dev/null; then
      echo "SELF-TEST FAIL: seeded '$bad' was accepted"; rc=1
    fi
  done
  if check "$d/does-not-exist" >/dev/null; then
    echo "SELF-TEST FAIL: absent file was accepted"; rc=1
  fi
  [[ $rc -eq 0 ]] && echo "self-test ok"
  return "$rc"
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
else
  check "${1:-.github/CODEOWNERS}"
fi
