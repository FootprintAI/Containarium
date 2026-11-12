#!/bin/bash
# Tests for the bundle download in scripts/install-agent-runtime.sh (#3657, F8).
# Runs the real fetch_bundle function against a file:// URL (curl supports it,
# so no network is needed).
set -euo pipefail

FILE="$(cd "$(dirname "$0")" && pwd)/install-agent-runtime.sh"
fail=0
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

eval "$(sed -n '/^fetch_bundle()/,/^}/p' "$FILE")"
if ! declare -F fetch_bundle >/dev/null; then
    echo "FAIL: fetch_bundle not defined in install-agent-runtime.sh"
    exit 1
fi

# A fake bundle served from a local directory.
src="$tmp/src"
mkdir "$src"
echo "bundle-bytes" > "$src/agent-runtime-bundle.tar.gz"

# Case 1: the download lands at a private, freshly created path with the
# expected content.
got="$(fetch_bundle "file://$src/agent-runtime-bundle.tar.gz")"
if [[ -f "$got" ]] && [[ "$(cat "$got")" == "bundle-bytes" ]] && [[ "$(stat -c '%a' "$got")" == "600" ]]; then
    echo "PASS: bundle downloaded to a private temp file (mode 600)"
else
    echo "FAIL: download path=$got"; fail=1
fi
rm -f "$got"

# Case 2: the function never writes to the old fixed /tmp name.
if grep -q '/tmp/agent-runtime-bundle.tar.gz' "$FILE"; then
    echo "FAIL: script still uses the fixed /tmp/agent-runtime-bundle.tar.gz name"; fail=1
else
    echo "PASS: no fixed /tmp bundle name remains"
fi

# Case 3: a symlink planted at the old fixed name is not followed. The
# download must go to the mktemp path, and the planted target must not change.
target="$tmp/victim"
echo "keep" > "$target"
planted="$tmp/fixed-name.tar.gz"
ln -s "$target" "$planted"
got="$(fetch_bundle "file://$src/agent-runtime-bundle.tar.gz")"
if [[ "$(cat "$target")" == "keep" && "$got" != "$planted" ]]; then
    echo "PASS: planted symlink target is untouched"
else
    echo "FAIL: planted target was modified or download used the fixed name"; fail=1
fi
rm -f "$got"

exit "$fail"
