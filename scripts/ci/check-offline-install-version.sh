#!/usr/bin/env bash
# Fail when the air-gapped install guide (and README) hardcodes a release version (#2557).
#
# hacks/offline-install/docs/INSTALL.md pinned one release in its commands
# and kept it long after newer releases shipped. A pinned version is older than
# the latest tag as soon as the next release is cut, so the rule is stricter
# than "not older than the latest tag": the guide names no release version at
# all. Its commands take the version from a variable (`VERSION=<release tag>`)
# or a placeholder (`vX.Y.Z`). A version is `v` followed by two or three dotted
# numbers (v0.1, v1.2.3); placeholders such as vX.Y.Z do not match.
#
# Usage:
#   scripts/ci/check-offline-install-version.sh              # check the guide and README
#   scripts/ci/check-offline-install-version.sh FILE...      # check FILEs
#   scripts/ci/check-offline-install-version.sh --self-test  # seeded fixtures
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# The README carried a pinned build example too (#3063), so it is gated with the guide.
DEFAULT_DOCS=("$ROOT/hacks/offline-install/docs/INSTALL.md" "$ROOT/hacks/offline-install/README.md")

# check FILE... prints every offending line and returns 1 if there is one.
check() {
  local rc=0 f hits
  for f in "$@"; do
    if [ ! -f "$f" ]; then
      echo "::error::$f not found"
      rc=1
      continue
    fi
    # grep exits 1 on no match, which is the passing case here.
    if hits="$(grep -nE '(^|[^[:alnum:]_])v[0-9]+\.[0-9]+(\.[0-9]+)?([^[:alnum:]_.]|\.([^0-9]|$)|$)' "$f")"; then
      while IFS= read -r line; do
        echo "::error file=${f#"$ROOT"/},line=${line%%:*}::hardcoded release version; use \${VERSION} or vX.Y.Z: ${line#*:}"
      done <<< "$hits"
      rc=1
    fi
  done
  return "$rc"
}

self_test() {
  local dir rc=0
  dir="$(mktemp -d)"
  trap 'rm -rf "$dir"' RETURN

  printf 'VERSION=v0.19.0\n' > "$dir/pinned-var.md"
  printf 'sudo containarium create t --image containarium-base:v1.2.3\n' > "$dir/pinned-image.md"
  printf 'Signing is shipping in v0.1.\n' > "$dir/two-part.md"
  printf 'ok line\nfrom https://x/releases/download/v0.116.0/b.tgz\n' > "$dir/in-url.md"
  # The literal ${VERSION} is the point: it must pass unexpanded.
  # shellcheck disable=SC2016
  printf 'VERSION=<release tag>\ntar xzf containarium-bundle-vX.Y.Z-linux-amd64.tar.gz\n${VERSION}\n' > "$dir/placeholders.md"

  # The default set must cover the README, or a pin there goes unseen.
  if ! printf '%s\n' "${DEFAULT_DOCS[@]}" | grep -q 'offline-install/README.md$'; then
    echo "self-test FAIL: README.md is not in the default doc set"
    rc=1
  fi

  local f
  for f in pinned-var pinned-image two-part in-url; do
    if check "$dir/$f.md" > /dev/null; then
      echo "self-test FAIL: $f.md has a hardcoded version but passed"
      rc=1
    fi
  done
  if ! check "$dir/placeholders.md"; then
    echo "self-test FAIL: placeholders.md has only placeholders but failed"
    rc=1
  fi
  [ "$rc" -eq 0 ] && echo "self-test ok: 4 seeded versions caught, placeholders pass"
  return "$rc"
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
elif [ "$#" -gt 0 ]; then
  check "$@"
else
  check "${DEFAULT_DOCS[@]}"
fi
