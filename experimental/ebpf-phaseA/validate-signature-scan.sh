#!/usr/bin/env bash
#
# Backend acceptance for eBPF virtual patching — Tier 2 inbound cleartext
# signature scanning (#661). Companion to VIRTUAL-PATCHING-TIER2.md.
#
# It sends a request carrying a built-in exploit signature (Log4Shell's
# "${jndi:") TO a listener inside a managed container and asserts:
#   - a network_policy.signature_match audit row / log line appears (the scan
#     fired and named the signature), and
#   - with enforcement armed, the exploit request is DROPPED (the listener never
#     sees it) while a benign request still gets through.
#
# Adapts to whether enforcement is armed (CONTAINARIUM_NETWORK_POLICY_ENFORCE=1):
#   - armed   -> the drop is asserted.
#   - not     -> drop asserts become SKIPs; the match/audit path is still checked
#                (the safe soak default).
#
# The BPF object only builds/runs on a Linux backend; this is not a CI test.
# Anonymise before pasting results anywhere public: <backend>, <container>.
#
# Usage:
#   CONTAINER=<tenant>-container JOURNAL_UNIT=containarium \
#     ./validate-signature-scan.sh
#
# Optional env:
#   LISTEN_PORT   port to run the in-container test listener on (default 8099)
#   SIGNATURE     the cleartext signature to send (default '${jndi:ldap://x/a}')
#   JOURNAL_UNIT  systemd unit for the audit/log check (default containarium)
#   SETTLE        seconds to wait for an event to surface (default 3)
#
set -euo pipefail

CONTAINER="${CONTAINER:?set CONTAINER to a managed (policy-attached) tenant container}"
LISTEN_PORT="${LISTEN_PORT:-8099}"
SIGNATURE="${SIGNATURE:-\${jndi:ldap://x/a}}"
JOURNAL_UNIT="${JOURNAL_UNIT:-containarium}"
SETTLE="${SETTLE:-3}"

PASS=0 FAIL=0 SKIP=0
pass() { printf '  \033[32mPASS\033[0m %s\n' "$*"; PASS=$((PASS + 1)); }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAIL=$((FAIL + 1)); }
skip() { printf '  \033[33mSKIP\033[0m %s\n' "$*"; SKIP=$((SKIP + 1)); }
info() { printf '  ·    %s\n' "$*"; }
phase() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing tool: $1" >&2; exit 2; }; }

# The container's IP on the bridge (the peer dials this).
container_ip() {
  incus list "$CONTAINER" -c 4 -f csv 2>/dev/null | awk '{print $1}' | head -1
}

cleanup() {
  set +e
  incus exec "$CONTAINER" -- pkill -f "nc -l" </dev/null >/dev/null 2>&1
}
trap cleanup EXIT

phase "Preflight"
need incus
incus info "$CONTAINER" >/dev/null 2>&1 && pass "container exists" || { fail "container not found"; exit 1; }

ARMED=no
if command -v journalctl >/dev/null 2>&1; then
  if journalctl -u "$JOURNAL_UNIT" --since "10 min ago" 2>/dev/null | grep -qi "ENFORCE ARMED"; then
    ARMED=yes
  fi
  if journalctl -u "$JOURNAL_UNIT" --since "30 min ago" 2>/dev/null | grep -qi "Tier 2 .*signature scanning ENABLED\|signature scanning enabled"; then
    pass "daemon log shows Tier 2 signature scanning enabled"
  else
    fail "daemon did NOT log Tier 2 signature scanning enabled — set CONTAINARIUM_NETWORK_POLICY_SIGNATURES=1 and restart"
  fi
else
  skip "journalctl unavailable — can't confirm scan-enabled / armed from logs; assuming observe-only"
fi
info "enforcement armed: $ARMED"

IP="$(container_ip)"
[ -n "$IP" ] && pass "container IP = $IP" || { fail "could not resolve container IP"; exit 1; }

# Start a one-shot listener in the container that records what it received.
phase "Start in-container listener on :$LISTEN_PORT"
incus exec "$CONTAINER" -- sh -c "command -v nc >/dev/null 2>&1" </dev/null \
  || { skip "container has no 'nc' — install netcat or set a container that has it; cannot run the live test"; exit 0; }
incus exec "$CONTAINER" -- sh -c "rm -f /tmp/sig_seen; (nc -l -p $LISTEN_PORT >/tmp/sig_seen 2>/dev/null &) " </dev/null
sleep 1
pass "listener started"

# Helper: did the listener receive anything?
listener_saw_data() {
  incus exec "$CONTAINER" -- sh -c "[ -s /tmp/sig_seen ] && echo yes || echo no" </dev/null 2>/dev/null | tr -d '[:space:]'
}

phase "Send the exploit signature to the container"
SINCE="$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo '2 min ago')"
# Dial from the host (a 'peer' on the bridge) into the container's listener.
printf 'GET /?x=%s HTTP/1.0\r\n\r\n' "$SIGNATURE" | timeout 5 nc -w2 "$IP" "$LISTEN_PORT" >/dev/null 2>&1 || true
sleep "$SETTLE"

# 1. The scan fired and audited the match.
if command -v journalctl >/dev/null 2>&1; then
  if journalctl -u "$JOURNAL_UNIT" --since "$SINCE" 2>/dev/null | grep -qiE "signature_match|\[netpolicy\] signature:"; then
    pass "audit/log shows a signature match (network_policy.signature_match)"
  else
    fail "no signature-match audit/log line after sending the exploit payload"
  fi
else
  skip "journalctl unavailable — verify the network_policy.signature_match audit row via your log path"
fi

# 2. Drop semantics.
if [ "$ARMED" = yes ]; then
  if [ "$(listener_saw_data)" = no ]; then
    pass "ENFORCE: exploit request was DROPPED — the in-container listener received nothing"
  else
    fail "ENFORCE: listener received the exploit payload — it was not dropped"
  fi
else
  if [ "$(listener_saw_data)" = yes ]; then
    info "observe-only: payload reached the listener (expected — nothing drops); match was logged above"
    skip "drop not asserted (enforcement not armed)"
  else
    skip "drop not asserted (enforcement not armed); listener saw no data — check the listener/probe"
  fi
fi

# 3. A benign request is unaffected (no false-positive drop).
phase "Benign request still passes"
cleanup
incus exec "$CONTAINER" -- sh -c "rm -f /tmp/benign_seen; (nc -l -p $LISTEN_PORT >/tmp/benign_seen 2>/dev/null &)" </dev/null
sleep 1
printf 'GET /health HTTP/1.0\r\n\r\n' | timeout 5 nc -w2 "$IP" "$LISTEN_PORT" >/dev/null 2>&1 || true
sleep "$SETTLE"
if incus exec "$CONTAINER" -- sh -c "[ -s /tmp/benign_seen ] && echo yes || echo no" </dev/null 2>/dev/null | grep -q yes; then
  pass "benign request reached the listener (no false-positive drop)"
else
  fail "benign request did NOT reach the listener — possible over-broad drop"
fi
incus exec "$CONTAINER" -- rm -f /tmp/sig_seen /tmp/benign_seen </dev/null >/dev/null 2>&1 || true

phase "Result"
printf 'PASS=%d  FAIL=%d  SKIP=%d   (enforcement armed: %s)\n' "$PASS" "$FAIL" "$SKIP" "$ARMED"
echo "Record the outcome (anonymised) on the Tier 2 PR; on a clean armed pass, mark it ready."
[ "$FAIL" -eq 0 ]
