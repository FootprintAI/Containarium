#!/bin/bash
# Tests for the ZFS keyfile creation in scripts/setup-gpu-host.sh (#3655, F6).
# Runs the real create_keyfile helper under a permissive umask, so the test
# shows the helper sets the mode itself rather than inheriting it.
set -euo pipefail

FILE="$(cd "$(dirname "$0")" && pwd)/setup-gpu-host.sh"
fail=0
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

eval "$(sed -n '/^create_keyfile()/,/^}/p' "$FILE")"
if ! declare -F create_keyfile >/dev/null; then
    echo "FAIL: create_keyfile not defined in setup-gpu-host.sh"
    exit 1
fi

# Case 1: under umask 022 (which would normally give 0644), the helper leaves
# the key 0400 and 32 bytes long.
key="$tmp/zfs.key"
(umask 022; create_keyfile "$key")
mode=$(stat -c '%a' "$key")
size=$(stat -c '%s' "$key")
if [[ "$mode" == "400" && "$size" == "32" ]]; then
    echo "PASS: keyfile is 0400, 32 bytes, under umask 022"
else
    echo "FAIL: keyfile mode=$mode size=$size (want 400 and 32)"; fail=1
fi

# Static: the only dd that writes the keyfile is inside the helper.
dd_lines=$(grep -n 'dd if=/dev/urandom of=' "$FILE" | cut -d: -f1)
helper_start=$(grep -n '^create_keyfile()' "$FILE" | cut -d: -f1)
helper_end=$(awk -v s="$helper_start" 'NR>s && /^}/ {print NR; exit}' "$FILE")
outside=0
while IFS= read -r ln; do
    if (( ln < helper_start || ln > helper_end )); then outside=1; fi
done <<< "$dd_lines"
if (( outside == 0 )); then
    echo "PASS: keyfile dd only runs inside create_keyfile"
else
    echo "FAIL: a keyfile dd runs outside create_keyfile"; fail=1
fi

exit "$fail"
