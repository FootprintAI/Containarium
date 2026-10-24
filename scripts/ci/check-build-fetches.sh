#!/usr/bin/env bash
# Fail when a build-time network fetch appears that is not in the inventory.
#
# A "fetch" is a line in a workflow, composite action, Makefile, shell script
# or Dockerfile that runs one of: curl, wget, go install, go get,
# npm/pnpm/yarn install|ci|add, pip install. The inventory is
# scripts/ci/build-fetches.allow (one "<path><TAB><tool>" per line, keyed by
# file and tool, never by line number) and is documented, with how each fetch
# is pinned, in docs/security/BUILD-SUPPLY-CHAIN.md.
#
# Usage:
#   scripts/ci/check-build-fetches.sh              # check the repo
#   scripts/ci/check-build-fetches.sh --self-test  # seeded fixtures must fail
#
# Env (used by the self-test): ROOT (default: repo root), ALLOW, DOC.
#
# Never allowed, even if listed: a floating `@latest`, and a project-level
# `npm install` (use `npm ci` against the lockfile; `npm install -g <pkg>@<ver>`
# is a pinned global and is only a normal listed fetch).
#
# Not scanned: scripts/ci/testdata, this script, markdown, and the trees that
# are not part of building or releasing the product: hacks/ (operator
# install-time scripts), benchmark/, examples/, terraform/, experimental/. Lines that only talk to a local
# address (127.0.0.1, localhost) are not fetches. Comment lines are ignored.
# The apt-get/apk package-manager installs are one category listed in the doc,
# not tracked per file.
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)

# tool<TAB>ERE matched against a non-comment line
PATTERNS=$'curl\t(^|[^A-Za-z0-9_./-])curl([[:space:]]|$)
wget\t(^|[^A-Za-z0-9_./-])wget([[:space:]]|$)
go install\t(^|[^A-Za-z0-9_./-])go[[:space:]]+install([[:space:]]|$)
go get\t(^|[^A-Za-z0-9_./-])go[[:space:]]+get([[:space:]]|$)
npm install\t(^|[^A-Za-z0-9_./-])(npm|pnpm|yarn)[[:space:]]+(install|i|add)([[:space:]]|$)
npm ci\t(^|[^A-Za-z0-9_./-])npm[[:space:]]+ci([[:space:]]|$)
pip install\t(^|[^A-Za-z0-9_./-])pip3?[[:space:]]+install([[:space:]]|$)'

# NUL-separated list of files in scope: workflow/action YAML under .github,
# plus shell scripts, Makefiles and Dockerfiles anywhere.
files() {
  find "$1" \( -path '*/node_modules' -o -path '*/.git' \) -prune -o -type f \
    \( \( \( -name '*.yml' -o -name '*.yaml' \) -path '*/.github/*' \) \
       -o -name '*.sh' -o -name Makefile -o -name 'Dockerfile*' \) -print0 | sort -z
}

# Prints "<relpath>\t<tool>" for every fetch found under ROOT.
scan() {
  local root=$1 file rel tool re hits
  while IFS= read -r -d '' file; do
    rel=${file#"$root"/}
    case "$rel" in
      scripts/ci/testdata/*|scripts/ci/check-build-fetches.sh|hacks/*|benchmark/*|examples/*|terraform/*|experimental/*) continue ;;
    esac
    while IFS=$'\t' read -r tool re; do
      # No `grep -q` in a pipeline: it exits early and, under pipefail, the
      # SIGPIPE'd upstream turns a real hit into "no match".
      hits=$(grep -vE '^[[:space:]]*#' "$file" | grep -vE '127\.0\.0\.1|localhost' | grep -E "$re" || true)
      if [[ -n "$hits" ]]; then
        printf '%s\t%s\n' "$rel" "$tool"
      fi
    done <<<"$PATTERNS"
  done < <(files "$root")
}

# Prints "<relpath>:<line>: <text>" for each forbidden construct.
forbidden() {
  local root=$1 file rel
  while IFS= read -r -d '' file; do
    rel=${file#"$root"/}
    case "$rel" in
      scripts/ci/testdata/*|scripts/ci/check-build-fetches.sh|hacks/*|benchmark/*|examples/*|terraform/*|experimental/*) continue ;;
    esac
    { grep -nE '@latest([^A-Za-z0-9_]|$)' "$file" || true; } | grep -vE '^[0-9]+:[[:space:]]*#' \
      | sed "s|^|$rel:|;s|:\([0-9]*\):|:\1: @latest: |" || true
    { grep -nE '(^|[^A-Za-z0-9_./-])npm[[:space:]]+(install|i)([[:space:]]|$)' "$file" || true; } \
      | grep -vE '^[0-9]+:[[:space:]]*#' | grep -vE -- '[[:space:]](-g|--global)([[:space:]]|$)' \
      | sed "s|^|$rel:|;s|:\([0-9]*\):|:\1: npm install (use npm ci): |" || true
  done < <(files "$root")
}

check() {
  local root=$1 allow=$2 doc=$3 bad=0 path tool
  local forb; forb=$(forbidden "$root")
  if [[ -n "$forb" ]]; then
    while IFS= read -r line; do echo "FORBIDDEN: $line"; done <<<"$forb"
    bad=1
  fi
  local found; found=$(scan "$root" | sort -u)
  local listed; listed=$(grep -vE '^[[:space:]]*(#|$)' "$allow" | sort -u)
  while IFS=$'\t' read -r path tool; do
    [[ -n "$path" ]] || continue
    echo "UNLISTED FETCH: $path ($tool) — pin it, then add it to $(basename "$allow") and the doc"
    bad=1
  done < <(comm -23 <(printf '%s\n' "$found") <(printf '%s\n' "$listed"))
  while IFS=$'\t' read -r path tool; do
    [[ -n "$path" ]] || continue
    echo "STALE ENTRY: $path ($tool) is allow-listed but no longer fetches"
    bad=1
  done < <(comm -13 <(printf '%s\n' "$found") <(printf '%s\n' "$listed"))
  while IFS=$'\t' read -r path tool; do
    [[ -n "$path" ]] || continue
    if ! grep -qF "\`$path\`" "$doc"; then
      echo "UNDOCUMENTED: $path is allow-listed but missing from $(basename "$doc")"
      bad=1
    fi
  done <<<"$listed"
  return "$bad"
}

self_test() {
  local d; d=$(mktemp -d); trap 'rm -rf "$d"' RETURN
  mkdir -p "$d/bad/.github/workflows" "$d/good/scripts" "$d/good/web-ui"
  printf 'jobs:\n  a:\n    steps:\n      - run: curl -fsSL https://example.invalid/x | sh\n' >"$d/bad/.github/workflows/x.yml"
  printf 'all:\n\tgo install example.invalid/tool@v1\n' >"$d/bad/Makefile"
  printf 'RUN pip install requests\n' >"$d/bad/Dockerfile"
  printf 'cd web && npm ci\n' >"$d/bad/build.sh"
  printf '# curl is only mentioned in a comment\ncurl -s http://127.0.0.1:8080/healthz\n' >"$d/good/scripts/ok.sh"
  # Forbidden constructs fail even when the file/tool pair is listed.
  mkdir -p "$d/forb"
  printf 'cd web && npm install\n' >"$d/forb/a.sh"
  printf 'go install example.invalid/tool@latest\n' >"$d/forb/b.sh"
  printf 'npm install -g pnpm@9\n# npm install in a comment\n' >"$d/forb/c.sh"
  printf 'a.sh\tnpm install\nb.sh\tgo install\nc.sh\tnpm install\n' >"$d/forb.allow"
  printf '`a.sh` `b.sh` `c.sh`\n' >"$d/forb.md"
  out=$(check "$d/forb" "$d/forb.allow" "$d/forb.md" || true)
  grep -qF 'a.sh:1: npm install' <<<"$out" || { echo "self-test FAIL: npm install not forbidden"; echo "$out"; return 1; }
  grep -qF 'b.sh:1: @latest' <<<"$out" || { echo "self-test FAIL: @latest not forbidden"; echo "$out"; return 1; }
  if grep -qF 'c.sh:' <<<"$out"; then echo "self-test FAIL: pinned global npm install / comment flagged"; echo "$out"; return 1; fi
  # Early hit in a large file: guards against grep -q SIGPIPE under pipefail.
  mkdir -p "$d/big"; { printf 'curl -fsSL https://example.invalid/y\n'; seq 1 60000; } >"$d/big/big.sh"
  : >"$d/empty.allow"; printf '# none\n' >"$d/empty.allow"; : >"$d/doc.md"
  local out; out=$(check "$d/bad" "$d/empty.allow" "$d/doc.md" || true)
  for want in '.github/workflows/x.yml (curl)' 'Makefile (go install)' 'Dockerfile (pip install)' 'build.sh (npm ci)'; do
    grep -qF "$want" <<<"$out" || { echo "self-test FAIL: seeded fetch not reported: $want"; echo "$out"; return 1; }
  done
  out=$(check "$d/big" "$d/empty.allow" "$d/doc.md" || true)
  grep -qF 'big.sh (curl)' <<<"$out" || { echo "self-test FAIL: early fetch in large file missed"; return 1; }
  check "$d/good" "$d/empty.allow" "$d/doc.md" >/dev/null || { echo "self-test FAIL: comment/localhost fixture rejected"; return 1; }
  # Listing the fetches (and documenting them) turns the bad tree green.
  scan "$d/bad" | sort -u >"$d/full.allow"
  printf '`.github/workflows/x.yml` `Makefile` `Dockerfile` `build.sh`\n' >"$d/doc.md"
  check "$d/bad" "$d/full.allow" "$d/doc.md" >/dev/null || { echo "self-test FAIL: listed+documented fetches rejected"; return 1; }
  # Dropping one entry must fail again; a stale entry must fail too.
  grep -v 'Makefile' "$d/full.allow" >"$d/short.allow"
  if check "$d/bad" "$d/short.allow" "$d/doc.md" >/dev/null; then echo "self-test FAIL: missing entry accepted"; return 1; fi
  printf 'gone.sh\tcurl\n' >>"$d/full.allow"
  if check "$d/bad" "$d/full.allow" "$d/doc.md" >/dev/null; then echo "self-test FAIL: stale entry accepted"; return 1; fi
  echo "self-test ok: unlisted/stale/undocumented fetches rejected, listed ones accepted"
}

if [[ "${1:-}" == "--self-test" ]]; then self_test; exit; fi
ROOT=${ROOT:-$REPO}
ALLOW=${ALLOW:-$REPO/scripts/ci/build-fetches.allow}
DOC=${DOC:-$REPO/docs/security/BUILD-SUPPLY-CHAIN.md}
if check "$ROOT" "$ALLOW" "$DOC"; then echo "build-time fetch inventory is complete"; else
  echo "Every build-time fetch must be pinned (version + checksum) and listed in $ALLOW and $DOC." >&2
  exit 1
fi
