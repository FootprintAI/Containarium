#!/usr/bin/env bash
# Regression test for #1596: the sentinel's admin sshd (port 2222) host key
# must survive repeated runs of startup-sentinel.sh — it was observed to
# regenerate on every containarium-sentinel restart, degrading
# StrictHostKeyChecking from a real MITM signal into routine noise.
#
# Helper copied verbatim from terraform/modules/containarium/scripts/
# startup-sentinel.sh (the /etc/containarium path is real production
# state there; here it's redirected under a throwaway temp dir so this
# test never touches the real filesystem).
set -uo pipefail

generate_admin_hostkey() { # root — path to use in place of /etc/containarium
    local root="$1"
    mkdir -p "$root/etc/containarium"
    if [ ! -f "$root/etc/containarium/ssh_host_ed25519_key" ]; then
        ssh-keygen -t ed25519 -f "$root/etc/containarium/ssh_host_ed25519_key" -N "" -q
        echo "admin sshd host key generated"
    fi
    chmod 600 "$root/etc/containarium/ssh_host_ed25519_key"
}
# --- end helper ---

pass=0; fail=0
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

first_out="$(generate_admin_hostkey "$tmpdir")"
if [ ! -f "$tmpdir/etc/containarium/ssh_host_ed25519_key" ]; then
  echo "  FAIL  first run creates a key"; fail=$((fail+1))
else
  echo "  PASS  first run creates a key"; pass=$((pass+1))
fi
if [ "$first_out" = "admin sshd host key generated" ]; then
  echo "  PASS  first run reports generating a key"; pass=$((pass+1))
else
  echo "  FAIL  first run did not report generating a key (got: $first_out)"; fail=$((fail+1))
fi
first_key="$(cat "$tmpdir/etc/containarium/ssh_host_ed25519_key" 2>/dev/null)"

# Second run must be a pure no-op: the "generated" line only prints when
# ssh-keygen actually ran, so its absence here is the real assertion —
# content equality below just confirms the file wasn't touched at all.
second_out="$(generate_admin_hostkey "$tmpdir")"
second_key="$(cat "$tmpdir/etc/containarium/ssh_host_ed25519_key" 2>/dev/null)"

if [ -z "$second_out" ]; then
  echo "  PASS  second run is silent (ssh-keygen did not run again)"; pass=$((pass+1))
else
  echo "  FAIL  second run re-generated the key (got: $second_out) — this is the #1596 bug"; fail=$((fail+1))
fi
if [ "$first_key" = "$second_key" ]; then
  echo "  PASS  key content is identical after a second run"; pass=$((pass+1))
else
  echo "  FAIL  key content changed after a second run — this is the #1596 bug"; fail=$((fail+1))
fi

# The real startup script must actually pin sshd to this path and strip the
# distro's own default HostKey lines, or the persisted key above is inert.
SCRIPT="$(cd "$(dirname "$0")/.." && pwd)/terraform/modules/containarium/scripts/startup-sentinel.sh"
check_contains() {
  local desc="$1" pattern="$2"
  if grep -qF -- "$pattern" "$SCRIPT"; then
    echo "  PASS  $desc"; pass=$((pass+1))
  else
    echo "  FAIL  $desc"; fail=$((fail+1))
  fi
}
check_contains "sshd_config.d pins HostKey to the persisted path" \
  'HostKey /etc/containarium/ssh_host_ed25519_key'
check_contains "the distro's default HostKey lines are stripped" \
  "sed -i '/^HostKey /d' /etc/ssh/sshd_config"

echo "passed=$pass failed=$fail"
[ "$fail" = "0" ]
