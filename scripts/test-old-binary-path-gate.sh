#!/usr/bin/env bash
# Stale-install-path gate for the containarium -> containariumd rename
# (#1781, docs/architecture/cli-client-server-split.md Test strategy).
#
# Every host-side script/unit/terraform file must install, download, or
# reconcile the daemon binary as /usr/local/bin/containariumd — the old
# path is legitimate ONLY as the compat symlink target (`ln -sf
# .../containariumd /usr/local/bin/containarium`), as the symlink-removal
# check in hacks/uninstall.sh, or in tests that deliberately exercise the
# mid-rollout / pre-rollout state. A bare, non-allow-listed hit means some
# script still downloads or installs the OLD path as if it were the real
# binary — exactly the class of bug #1781 exists to catch.
#
# Pattern uses a negative lookahead (grep -P) so it does NOT false-positive
# on unrelated binaries that happen to share the "containarium" prefix
# (containarium-shell, containarium-info, containarium-runtime,
# containarium-runner-loop, containarium-zfs-backup, containariumd itself).
set -uo pipefail
cd "$(dirname "$0")/.."

PATTERN='/usr/local/bin/containarium(?![a-zA-Z0-9_-])'

# Client-side / compat-shim files where the OLD path is the correct,
# intentional value — not a stale reference.
ALLOWLIST=(
  "internal/cmd/service.go"                    # compatSymlinkOldPath constant
  "internal/cmd/pool_join_test.go"              # deliberate old-path fixtures (mid-rollout flag preservation)
  "internal/cmd/compat_symlink_test.go"         # comment describing the compat symlink
  "internal/hostcheck/posture_test.go"          # generic ExecStart-parsing fixtures, unrelated to the rename
  "hacks/uninstall.sh"                          # removes the compat symlink, never installs to it
  "scripts/deploy-binary.sh"                    # creates the compat symlink after installing containariumd
  "scripts/setup-peer.sh"                       # creates the compat symlink after installing containariumd
  "scripts/install-lab-tunnel.sh"               # creates the compat symlink after installing containariumd
  "scripts/backup-all-tenants.sh"               # CLI invocation path; relies on the compat symlink, not an install target
  "scripts/restore-tenant.sh"                   # CLI invocation path; relies on the compat symlink, not an install target
  "terraform/modules/containarium/scripts/startup.sh"
  "terraform/modules/containarium/scripts/startup-spot.sh"
  "terraform/modules/containarium/scripts/startup-sentinel.sh"
  "terraform/gce/scripts/startup.sh"
  "terraform/gce/scripts/startup-spot.sh"
  "terraform/gce/scripts/startup-sentinel.sh"
  "benchmark/agent-sandbox-density/scripts/03-provision-containarium.sh"
  "benchmark/agent-sandbox-density/scripts/05-provision-containarium-lxc.sh"
  "benchmark/agent-sandbox-density/scripts/07-provision-containarium-sentinel.sh"
)

is_allowlisted() {
  local f="$1"
  for a in "${ALLOWLIST[@]}"; do
    [ "$f" = "$a" ] && return 0
  done
  return 1
}

SELF="scripts/$(basename "$0")"

fail=0
while IFS= read -r -d '' file; do
  # Skip this gate script itself — its own comments and PATTERN literal
  # necessarily contain the string being searched for.
  [ "$file" = "$SELF" ] && continue

  hits="$(grep -nP "$PATTERN" "$file" 2>/dev/null || true)"
  [ -z "$hits" ] && continue

  if is_allowlisted "$file"; then
    continue
  fi

  echo "FAIL  $file references the old /usr/local/bin/containarium install path:"
  echo "$hits" | sed 's/^/        /'
  fail=1
done < <(git ls-files -z -- '*.go' '*.sh' '*.tf' '*.service')

# Catch allow-list entries that no longer match anything (a rename, a
# deletion, or a fix means the entry is dead weight that would silently
# hide a REAL regression if that path became stale again under the same
# filename).
for a in "${ALLOWLIST[@]}"; do
  if [ ! -f "$a" ]; then
    echo "FAIL  allow-list entry '$a' no longer exists — remove it from scripts/test-old-binary-path-gate.sh"
    fail=1
    continue
  fi
  if ! grep -qP "$PATTERN" "$a"; then
    echo "FAIL  allow-list entry '$a' no longer references the old path — remove it from scripts/test-old-binary-path-gate.sh"
    fail=1
  fi
done

if [ "$fail" -eq 0 ]; then
  echo "PASS  no stale /usr/local/bin/containarium install-path references"
fi

exit $fail
