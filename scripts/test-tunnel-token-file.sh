#!/bin/bash
# Tests for the tunnel token in scripts/setup-peer.sh and
# scripts/install-lab-tunnel.sh (#3672). The token goes to a root-only file and
# the unit reads it with --token-file, so it never appears in ExecStart.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
fail=0
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

for script in setup-peer.sh install-lab-tunnel.sh; do
    file="$HERE/$script"
    echo "== $script"

    # Static: the unit's ExecStart reads the token from a file, not the argv.
    if grep -qE '^\s+--token-file \$\{TOKEN_FILE\}' "$file"; then
        echo "PASS: ExecStart uses --token-file"
    else
        echo "FAIL: ExecStart does not use --token-file"; fail=1
    fi
    if grep -qE '^\s+--token \$\{(TUNNEL|LAB)_TOKEN\}' "$file"; then
        echo "FAIL: the token is still passed on the command line"; fail=1
    else
        echo "PASS: the token is not on the ExecStart command line"
    fi

    # Static: the token file is written through the 0600 helper, from stdin.
    if grep -qE 'printf .*\| write_secret_unit "\$\{TOKEN_FILE\}"' "$file"; then
        echo "PASS: token file is written via write_secret_unit"
    else
        echo "FAIL: token file is not written via write_secret_unit"; fail=1
    fi

    # Behaviour: the real helper writes the token to a 0600 file, even when a
    # looser file already exists at the path.
    eval "$(sed -n '/^write_secret_unit()/,/^}/p' "$file")"
    if ! declare -F write_secret_unit >/dev/null; then
        echo "FAIL: write_secret_unit not defined in $script"; fail=1
        continue
    fi
    target="$tmp/$script.token"
    echo "stale" > "$target"
    chmod 0644 "$target"
    printf '%s\n' "tok-value-123" | write_secret_unit "$target"
    mode="$(stat -c '%a' "$target")"
    if [[ "$mode" == "600" ]] && [[ "$(cat "$target")" == "tok-value-123" ]]; then
        echo "PASS: token file is 0600 and holds the token"
    else
        echo "FAIL: token file mode=$mode content=$(cat "$target")"; fail=1
    fi
done

exit "$fail"
