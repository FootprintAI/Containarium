#!/usr/bin/env bash
# Prove the remote install step of deploy-binary.sh keeps the previous binary
# as <bin>.old, checks health after the restart, and restores it on failure (#3060).
# Runs the real command from scripts/lib/deploy-install.sh against fake
# sudo/systemctl/curl, so it needs no host and no network.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/deploy-install.sh
. "$here/lib/deploy-install.sh"

work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
mkdir -p "$work/fakebin"
cat > "$work/fakebin/sudo" <<'F'
#!/usr/bin/env bash
exec "$@"
F
cat > "$work/fakebin/systemctl" <<'F'
#!/usr/bin/env bash
echo "systemctl $*" >> "$FAKE_LOG"
exit 0
F
# curl succeeds only while the installed binary's content says "good".
cat > "$work/fakebin/curl" <<'F'
#!/usr/bin/env bash
grep -q good "$FAKE_BIN"
F
chmod +x "$work/fakebin/"*

pass=0; fail=0
ok() { echo "  PASS  $1"; pass=$((pass+1)); }
bad() { echo "  FAIL  $1"; fail=$((fail+1)); }

# run_case <name> <previous-content|-> <new-content> <want-rc>
run_case() {
  local name="$1" prev="$2" new="$3" want="$4" d="$work/$1"
  mkdir -p "$d/bin"; : > "$d/log"
  [ "$prev" = "-" ] || printf '%s' "$prev" > "$d/bin/containariumd"
  printf '%s' "$new" > /tmp/containariumd.$$
  local cmd; cmd="$(BIN_DIR="$d/bin" SRC="/tmp/containariumd.$$" HEALTH_TRIES=2 HEALTH_INTERVAL=0 \
    deploy_install_cmd containarium http://localhost:8080/health)"
  PATH="$work/fakebin:$PATH" FAKE_LOG="$d/log" FAKE_BIN="$d/bin/containariumd" bash -c "$cmd" >"$d/out" 2>&1
  local rc=$?; rm -f /tmp/containariumd.$$
  CASE_DIR="$d"
  if { [ "$want" = 0 ] && [ $rc = 0 ]; } || { [ "$want" != 0 ] && [ $rc != 0 ]; }; then ok "$name: exit status ($rc)"; else bad "$name: exit status $rc, want $want"; fi
}

run_case healthy old-good new-good 0
[ "$(cat "$CASE_DIR/bin/containariumd")" = new-good ] && ok "healthy: new binary installed" || bad "healthy: new binary installed"
[ "$(cat "$CASE_DIR/bin/containariumd.old" 2>/dev/null)" = old-good ] && ok "healthy: previous binary kept as .old" || bad "healthy: previous binary kept as .old"

run_case unhealthy old-good new-bad 1
[ "$(cat "$CASE_DIR/bin/containariumd")" = old-good ] && ok "unhealthy: previous binary restored" || bad "unhealthy: previous binary restored"
[ "$(grep -c 'systemctl start' "$CASE_DIR/log")" -ge 2 ] && ok "unhealthy: service started again after restore" || bad "unhealthy: service started again after restore"
grep -q 'rolled back' "$CASE_DIR/out" && ok "unhealthy: says it rolled back" || bad "unhealthy: says it rolled back"

run_case first-install - new-good 0
[ ! -e "$CASE_DIR/bin/containariumd.old" ] && ok "first install: no .old invented" || bad "first install: no .old invented"

run_case first-unhealthy - new-bad 1
grep -qi 'no previous' "$CASE_DIR/out" && ok "first install unhealthy: reports nothing to restore" || bad "first install unhealthy: reports nothing to restore"

echo "passed=$pass failed=$fail"
[ "$fail" = 0 ]
