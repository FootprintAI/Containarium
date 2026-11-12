#!/bin/bash
# Tests for the symlink guard in scripts/setup-peer-user.sh (#3653, F4).
# Runs the real refuse_symlink function extracted from the script, plus
# static checks that every write/chown site is behind the guard.
set -euo pipefail

SCRIPT="$(cd "$(dirname "$0")" && pwd)/setup-peer-user.sh"
fail=0

# Load the function exactly as shipped. If the function is missing, the
# extraction is empty and every case below fails.
eval "$(sed -n '/^refuse_symlink()/,/^}/p' "$SCRIPT")"
if ! declare -F refuse_symlink >/dev/null; then
    echo "FAIL: refuse_symlink not defined in $SCRIPT"
    exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Case 1: a real directory is allowed (guard returns 0).
mkdir "$tmp/realdir"
if (refuse_symlink "$tmp/realdir") 2>/dev/null; then
    echo "PASS: real directory is accepted"
else
    echo "FAIL: real directory was refused"; fail=1
fi

# Case 2: a symlink to a directory is refused with a non-zero exit.
ln -s "$tmp/realdir" "$tmp/linkdir"
if (refuse_symlink "$tmp/linkdir") 2>/dev/null; then
    echo "FAIL: symlink to a directory was accepted"; fail=1
else
    echo "PASS: symlink to a directory is refused"
fi

# Case 3: a symlink to a file is refused (authorized_keys case).
echo "k" > "$tmp/target"
ln -s "$tmp/target" "$tmp/linkfile"
if (refuse_symlink "$tmp/linkfile") 2>/dev/null; then
    echo "FAIL: symlink to a file was accepted"; fail=1
else
    echo "PASS: symlink to a file is refused"
fi

# Case 4: a missing path is not a symlink and is accepted (first run).
if (refuse_symlink "$tmp/absent") 2>/dev/null; then
    echo "PASS: missing path is accepted"
else
    echo "FAIL: missing path was refused"; fail=1
fi

# Static: the guard runs before each write site, and the recursive chown
# does not dereference symlinks.
check_order() {
    local guard="$1" site="$2"
    local gl sl
    gl=$(grep -nF "$guard" "$SCRIPT" | head -1 | cut -d: -f1)
    sl=$(grep -nF "$site" "$SCRIPT" | head -1 | cut -d: -f1)
    if [[ -n "$gl" && -n "$sl" && "$gl" -lt "$sl" ]]; then
        echo "PASS: '$guard' precedes '$site'"
    else
        echo "FAIL: expected '$guard' before '$site' (guard line=${gl:-none}, site line=${sl:-none})"
        fail=1
    fi
}
check_order 'refuse_symlink "/home/$USERNAME/.ssh"' 'mkdir -p "/home/$USERNAME/.ssh"'
check_order 'refuse_symlink "/home/$USERNAME/.ssh/authorized_keys"' 'echo "$SENTINEL_PUBKEY" > "/home/$USERNAME/.ssh/authorized_keys"'
check_order 'refuse_symlink "/home/$USERNAME"' 'chmod 755 "/home/$USERNAME"'

if grep -qF 'chown -R -h "$USERNAME:$USERNAME" "/home/$USERNAME/.ssh"' "$SCRIPT"; then
    echo "PASS: recursive chown uses -h"
else
    echo "FAIL: recursive chown of .ssh does not use -h"; fail=1
fi

exit "$fail"
