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
# FAKE_START_OK=n: only the first n `start` calls succeed (restore-restart failure).
if [ "$1" = start ] && [ -n "${FAKE_START_OK:-}" ]; then
  n=$(grep -c '^systemctl start' "$FAKE_LOG")
  [ "$n" -le "$FAKE_START_OK" ] || exit 1
fi
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
  PATH="$work/fakebin:$PATH" FAKE_LOG="$d/log" FAKE_START_OK="${START_OK:-}" FAKE_BIN="$d/bin/containariumd" bash -c "$cmd" >"$d/out" 2>&1
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

# The restored binary's restart fails: must not claim a rollback.
START_OK=1 run_case restart-fails old-good new-bad 1
if grep -q 'rolled back' "$CASE_DIR/out"; then bad "restart fails: must not say rolled back"; else ok "restart fails: does not claim a rollback"; fi
grep -q 'ROLLBACK FAILED' "$CASE_DIR/out" && ok "restart fails: reports the failed rollback" || bad "restart fails: reports the failed rollback"

# The restore itself (mv) fails: .old missing at restore time.
mkdir -p "$work/mvfail/bin"; : > "$work/mvfail/log"
cmd="$(BIN_DIR="$work/mvfail/bin" SRC=/dev/null HEALTH_TRIES=1 HEALTH_INTERVAL=0 deploy_install_cmd containarium http://x)"
printf old-good > "$work/mvfail/bin/containariumd"
cat > "$work/fakebin/sudo2" <<'F'
#!/usr/bin/env bash
if [ "$1" = mv ]; then exit 1; fi
exec "$@"
F
chmod +x "$work/fakebin/sudo2"; mkdir -p "$work/mvbin"; cp "$work/fakebin/"{systemctl,curl} "$work/mvbin/"; cp "$work/fakebin/sudo2" "$work/mvbin/sudo"
PATH="$work/mvbin:$PATH" FAKE_LOG="$work/mvfail/log" FAKE_BIN="$work/mvfail/bin/containariumd" bash -c "$cmd" >"$work/mvfail/out" 2>&1; rc=$?
[ $rc != 0 ] && ok "mv fails: non-zero exit" || bad "mv fails: non-zero exit"
if grep -q 'rolled back' "$work/mvfail/out"; then bad "mv fails: must not say rolled back"; else ok "mv fails: does not claim a rollback"; fi
grep -q 'ROLLBACK FAILED' "$work/mvfail/out" && ok "mv fails: reports the failed rollback" || bad "mv fails: reports the failed rollback"

run_case first-install - new-good 0
[ ! -e "$CASE_DIR/bin/containariumd.old" ] && ok "first install: no .old invented" || bad "first install: no .old invented"

run_case first-unhealthy - new-bad 1
grep -qi 'no previous' "$CASE_DIR/out" && ok "first install unhealthy: reports nothing to restore" || bad "first install unhealthy: reports nothing to restore"

echo "passed=$pass failed=$fail"
[ "$fail" = 0 ]
