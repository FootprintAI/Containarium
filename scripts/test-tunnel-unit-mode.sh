#!/bin/bash
# Tests for the tunnel unit mode in scripts/setup-peer.sh and
# scripts/install-lab-tunnel.sh (#3654, F5). Runs the real write_secret_unit
# helper extracted from each script.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
fail=0
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

mode_of() { stat -c '%a' "$1"; }

for script in setup-peer.sh install-lab-tunnel.sh; do
    file="$HERE/$script"
    echo "== $script"

    # Load the helper exactly as shipped. Missing helper -> empty extraction
    # -> the call below fails, so the test cannot pass vacuously.
    if ! eval "$(sed -n '/^write_secret_unit()/,/^}/p' "$file")" 2>/dev/null \
        || ! declare -F write_secret_unit >/dev/null; then
        echo "FAIL: write_secret_unit not defined in $script"; fail=1
        continue
    fi

    # Case 1: a new unit file is created 0600 and holds the content.
    unit="$tmp/new-$script.service"
    write_secret_unit "$unit" <<'UNIT'
ExecStart=/usr/local/bin/containariumd tunnel --token SECRET
UNIT
    if [[ "$(mode_of "$unit")" == "600" ]] && grep -q -- '--token SECRET' "$unit"; then
        echo "PASS: new unit is 0600 with content"
    else
        echo "FAIL: new unit mode=$(mode_of "$unit") (want 600)"; fail=1
    fi

    # Case 2: a pre-existing world-readable unit is tightened to 0600.
    old="$tmp/old-$script.service"
    echo "stale" > "$old"
    chmod 0644 "$old"
    write_secret_unit "$old" <<'UNIT'
ExecStart=/usr/local/bin/containariumd tunnel --token SECRET
UNIT
    if [[ "$(mode_of "$old")" == "600" ]]; then
        echo "PASS: pre-existing 0644 unit is tightened to 0600"
    else
        echo "FAIL: pre-existing unit mode=$(mode_of "$old") (want 600)"; fail=1
    fi

    # Case 3: the token-bearing unit is written through the helper.
    if grep -q '^write_secret_unit /etc/systemd/system/containarium-tunnel.service <<TUNNEL' "$file"; then
        echo "PASS: tunnel unit is written via write_secret_unit"
    else
        echo "FAIL: tunnel unit still written with a bare cat"; fail=1
    fi
done

exit "$fail"
