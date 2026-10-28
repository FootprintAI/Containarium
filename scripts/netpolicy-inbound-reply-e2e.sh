#!/usr/bin/env bash
#
# netpolicy-inbound-reply-e2e.sh — #2618: are a box's REPLIES to an inbound
# connection judged as new outbound flows when the box's policy is enforced?
#
# The eBPF enforcer (experimental/ebpf-phaseA/netpolicy.bpf.c,
# netpolicy_ingress) runs on the box's host veth TC_INGRESS, i.e. on every
# packet the box sends, and keeps no connection state. A SYN-ACK or an ICMP
# echo reply the box sends back to a peer that connected IN is therefore
# evaluated exactly like a packet the box initiated. Under a sound policy an
# egress policy governs what the box may OPEN, not whether it may answer a
# connection someone else opened, so this script asserts the sound
# expectation:
#
#   A (the box under test): mode=ENFORCE, egress_mode=ENFORCE, empty
#   allow-list, no presets.
#     inbound  host (bridge gateway) -> A tcp   connects and echoes   (reverse-proxy shape)
#     inbound  host (bridge gateway) -> A icmp  gets echo replies
#     inbound  B (no stored policy)  -> A tcp   connects and echoes
#     inbound  B (no stored policy)  -> A icmp  gets echo replies
#   controls (egress enforcement must stay intact):
#     outbound A -> host tcp   dropped
#     outbound A -> host icmp  dropped
#     outbound A -> B    icmp  dropped
#
# Every probe first runs with A in log_only (nothing dropped) as a positive
# control, so a failure under enforce can only come from the enforcer and
# not from a listener that never came up or a route that never existed.
#
# All probes run and are reported in one table before the exit status is
# decided, so one CI run records the whole picture. The deny rows the daemon
# audited for A during the inbound window are printed as evidence: a reply
# shows up as a deny toward the peer whose dport is the PEER'S ephemeral
# port, which is the signature #2618 describes.
#
# Runs after scripts/netpolicy-split-egress-e2e.sh in the same job and needs
# the same preconditions (see that script's header): the daemon with the
# real eBPF object, CONTAINARIUM_NETWORK_POLICY_ENFORCE=1, --postgres,
# CONTAINARIUM_TENANT_GUARD=off, containers <tenant-a>-container and
# <tenant-b>-container, B without a stored policy.
#
# Usage: scripts/netpolicy-inbound-reply-e2e.sh <tenant-a> <tenant-b>
# Environment: SERVER, CONTAINARIUM_TOKEN, CONTAINARIUM_HTTP=true,
# CONTAINARIUM_POSTGRES_URL, CONTAINARIUM_CLI (default /tmp/containarium).
#
# Exit status: 0 when every assertion held, 1 otherwise.

set -euo pipefail

A=${1:?usage: $0 <tenant-a> <tenant-b>}
B=${2:?usage: $0 <tenant-a> <tenant-b>}
CLI=${CONTAINARIUM_CLI:-/tmp/containarium}
: "${SERVER:?SERVER (daemon HTTP address) is required}"
: "${CONTAINARIUM_TOKEN:?CONTAINARIUM_TOKEN (admin token) is required}"
: "${CONTAINARIUM_POSTGRES_URL:?CONTAINARIUM_POSTGRES_URL (audit store) is required}"
AC="${A}-container"
BC="${B}-container"

# Ports: BOX_PORT is the echo listener inside A, HOST_PORT the one on the
# runner host for the outbound control.
BOX_PORT=18618
HOST_PORT=18619

fail() { echo "::error::$*"; exit 1; }
step() { echo; echo "=== $* ==="; }
cli() { "$CLI" --server "$SERVER" "$@"; }
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

for tool in jq sudo python3 timeout; do
  command -v "$tool" >/dev/null || fail "$tool is required on the runner"
done
test -x "$CLI" || fail "CLI binary $CLI is missing"

RESULTS=()
FAILED=0
record() { # record <pass|FAIL> <text>
  RESULTS+=("$1  $2")
  echo "$1: $2"
  if [ "$1" != pass ]; then FAILED=1; fi
}

# ---------------------------------------------------------------------------
# Probes. Each returns 0 on success (connected+echoed / got a reply).
# ---------------------------------------------------------------------------

# tcp_echo_from_host <dst> <port>: open a TCP connection from the runner
# host, send a token, and require it echoed back. Proves the box's SYN-ACK
# AND its data segments reached the initiator.
tcp_echo_from_host() {
  local dst=$1 port=$2
  timeout 8 python3 - "$dst" "$port" <<'PY'
import socket, sys
s = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=5)
s.sendall(b"inbound-2618\n")
got = b""
while not got.endswith(b"\n"):
    chunk = s.recv(64)
    if not chunk:
        break
    got += chunk
sys.exit(0 if got == b"inbound-2618\n" else 1)
PY
}

# tcp_echo_from_box <container> <dst> <port>: the same from inside a box,
# with bash's /dev/tcp (no tooling assumed in the image).
tcp_echo_from_box() {
  local c=$1 dst=$2 port=$3
  sudo incus exec "$c" -- timeout 8 bash -c \
    "exec 3<>/dev/tcp/$dst/$port && printf 'inbound-2618\n' >&3 && IFS= read -r -t 5 line <&3 && [ \"\$line\" = inbound-2618 ]" \
    >/dev/null 2>&1
}

# tcp_connect_from_box <container> <dst> <port>: handshake only.
tcp_connect_from_box() {
  local c=$1 dst=$2 port=$3
  sudo incus exec "$c" -- timeout 5 bash -c "exec 3<>/dev/tcp/$dst/$port" >/dev/null 2>&1
}

# Retried: a fresh ARP entry or a just-started listener can lose the first try.
retry3() {
  for _ in 1 2 3; do
    if "$@"; then return 0; fi
    sleep 1
  done
  return 1
}

ping_from_host() { ping -c 2 -W 2 "$1" >/dev/null 2>&1; }
ping_from_box() { sudo incus exec "$1" -- ping -c 2 -W 2 "$2" >/dev/null 2>&1; }

wait_applied() {
  local tenant=$1 mode=$2 egress=$3 st got=""
  for _ in $(seq 1 30); do
    st=$(cli network-policy status "$tenant" --json 2>/dev/null) || st=""
    if [ -n "$st" ]; then
      got=$(printf '%s' "$st" | jq -r '[.state, .effectiveMode, .effectiveEgressMode, (.enforcementArmed|tostring)] | join(" ")')
      if [ "$got" = "NETWORK_POLICY_APPLIED_STATE_LOADED NETWORK_POLICY_MODE_$mode NETWORK_POLICY_MODE_$egress true" ]; then
        echo "ok: $tenant applied mode=$mode egress_mode=$egress (enforce armed)"
        return 0
      fi
    fi
    sleep 2
  done
  echo "--- last status for $tenant ---"; printf '%s\n' "${st:-<none>}"
  fail "$tenant never reported LOADED mode=$mode egress_mode=$egress armed=true (last: ${got:-<none>})"
}

# ---------------------------------------------------------------------------
step "Resolve addresses and start listeners"
A_IP=$(cli get "$A" --format json | jq -r '.containers[0].IPAddress') || fail "could not get $A"
B_IP=$(cli get "$B" --format json | jq -r '.containers[0].IPAddress') || fail "could not get $B"
GW=$(sudo incus exec "$AC" -- ip -4 route show default | awk '{print $3; exit}') || fail "could not read $AC's default route"
for v in "$A_IP" "$B_IP" "$GW"; do
  if [ -z "$v" ] || [ "$v" = "null" ]; then
    fail "could not resolve A=$A_IP B=$B_IP gateway=$GW"
  fi
done
echo "A=$A_IP B=$B_IP host (bridge gateway)=$GW"

POLICIES=$(cli network-policy list --json) || fail "network-policy list failed"
if printf '%s' "$POLICIES" | jq -e --arg t "$B" 'any(.[]?; .tenant == $t)' >/dev/null; then
  fail "$B has a stored network policy; the scenario needs B on the default posture"
fi

# Echo listener inside A: systemd-socket-activate ships with systemd, which
# the box image always has, so no package install is needed.
sudo incus exec "$AC" -- sh -c 'command -v systemd-socket-activate' >/dev/null \
  || fail "$AC has no systemd-socket-activate; the harness cannot start a listener in the box"
# The redirections are inside the box: the detached listener must not hold the
# exec session's stdio open, or `incus exec` never returns.
sudo incus exec "$AC" -- sh -c \
  "setsid -f systemd-socket-activate -l 0.0.0.0:$BOX_PORT -a --inetd /bin/cat </dev/null >/dev/null 2>&1" \
  || fail "could not start the echo listener in $AC"
for _ in $(seq 1 10); do
  if sudo incus exec "$AC" -- ss -Hltn "sport = :$BOX_PORT" | grep LISTEN >/dev/null; then break; fi
  sleep 1
done
sudo incus exec "$AC" -- ss -Hltn "sport = :$BOX_PORT" | grep LISTEN >/dev/null \
  || fail "the echo listener in $AC never bound :$BOX_PORT"

# Listener on the runner host, bound to the bridge gateway, for the outbound
# control (A -> host must stay dropped).
python3 - "$GW" "$HOST_PORT" >/tmp/inbound-2618-host-listener.log 2>&1 <<'PY' &
import socket, sys
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind((sys.argv[1], int(sys.argv[2]))); srv.listen(16)
while True:
    c, _ = srv.accept(); c.close()
PY
HOST_LISTENER=$!
trap 'kill "$HOST_LISTENER" 2>/dev/null || true; sudo incus exec "$AC" -- pkill -f "systemd-socket-activate -l 0.0.0.0:$BOX_PORT" 2>/dev/null || true' EXIT
sleep 1
kill -0 "$HOST_LISTENER" 2>/dev/null || { cat /tmp/inbound-2618-host-listener.log; fail "host listener on $GW:$HOST_PORT did not start"; }

# ---------------------------------------------------------------------------
step "Positive control: $A mode=LOG_ONLY, egress_mode=LOG_ONLY (nothing dropped)"
cli network-policy set "$A" --mode log_only --egress-mode log_only
wait_applied "$A" LOG_ONLY LOG_ONLY
sleep 3

# The controls are preconditions: if one fails, the enforce phase below would
# prove nothing, so this phase stops the script.
retry3 tcp_echo_from_host "$A_IP" "$BOX_PORT"       || fail "control: host -> A tcp echo failed with nothing enforced"
retry3 ping_from_host "$A_IP"                        || fail "control: host -> A ping failed with nothing enforced"
retry3 tcp_echo_from_box "$BC" "$A_IP" "$BOX_PORT"  || fail "control: B -> A tcp echo failed with nothing enforced"
retry3 ping_from_box "$BC" "$A_IP"                   || fail "control: B -> A ping failed with nothing enforced"
retry3 tcp_connect_from_box "$AC" "$GW" "$HOST_PORT" || fail "control: A -> host tcp failed with nothing enforced"
retry3 ping_from_box "$AC" "$GW"                     || fail "control: A -> host ping failed with nothing enforced"
retry3 ping_from_box "$AC" "$B_IP"                   || fail "control: A -> B ping failed with nothing enforced"
echo "ok: every probe passes with nothing enforced"

# ---------------------------------------------------------------------------
step "Enforce: $A mode=ENFORCE, egress_mode=ENFORCE, empty allow-list"
cli network-policy set "$A" --mode enforce --egress-mode enforce
wait_applied "$A" ENFORCE ENFORCE
sleep 5
T_IN=$(now)

# Inbound: a sound egress policy lets the box answer.
if retry3 tcp_echo_from_host "$A_IP" "$BOX_PORT"; then
  record pass "inbound host -> A tcp: connected and echoed"
else
  record FAIL "inbound host -> A tcp: no working connection (A's SYN-ACK/data judged as A's own egress)"
fi
if retry3 ping_from_host "$A_IP"; then
  record pass "inbound host -> A icmp: echo replies received"
else
  record FAIL "inbound host -> A icmp: no echo reply (A's reply judged as A's own egress)"
fi
if retry3 tcp_echo_from_box "$BC" "$A_IP" "$BOX_PORT"; then
  record pass "inbound B -> A tcp: connected and echoed"
else
  record FAIL "inbound B -> A tcp: no working connection (A's reply judged as cross-tenant egress)"
fi
if retry3 ping_from_box "$BC" "$A_IP"; then
  record pass "inbound B -> A icmp: echo replies received"
else
  record FAIL "inbound B -> A icmp: no echo reply (A's reply judged as cross-tenant egress)"
fi

# Keep the controls' own deny rows out of the inbound window.
sleep 3
T_CTRL=$(now)

# Controls: what A opens itself must still be judged and dropped.
if tcp_connect_from_box "$AC" "$GW" "$HOST_PORT"; then
  record FAIL "outbound A -> host tcp: connected; egress enforcement is broken"
else
  record pass "outbound A -> host tcp: dropped"
fi
if ping_from_box "$AC" "$GW"; then
  record FAIL "outbound A -> host icmp: got a reply; egress enforcement is broken"
else
  record pass "outbound A -> host icmp: dropped"
fi
if ping_from_box "$AC" "$B_IP"; then
  record FAIL "outbound A -> B icmp: got a reply; cross-tenant enforcement is broken"
else
  record pass "outbound A -> B icmp: dropped"
fi

# ---------------------------------------------------------------------------
step "Evidence: deny rows audited for $A during the inbound window [$T_IN, $T_CTRL)"
# Diagnostic output, not an assertion. The rows are what the issue predicts:
# denies toward the initiator, with dport = the initiator's ephemeral port.
sleep 4
if ROWS=$("$CLI" audit query --resource-type network_policy --from "$T_IN" --to "$T_CTRL" --limit 1000 --raw); then
  # The row limit is inside awk: `| head` would SIGPIPE awk, and under
  # pipefail that kills the script before the summary.
  printf '%s\n' "$ROWS" | awk -F'\t' -v t="$A" '$5 == t && n < 40 { print; n++ }'
  N=$(printf '%s\n' "$ROWS" | awk -F'\t' -v t="$A" '$5 == t { n++ } END { print n + 0 }')
  echo "($N deny row(s) for $A in the inbound window)"
else
  echo "audit query failed; no deny-row evidence for this run"
fi

# ---------------------------------------------------------------------------
step "Summary (#2618)"
printf '%s\n' "${RESULTS[@]}"
if [ "$FAILED" -ne 0 ]; then
  fail "inbound-reply scenario: at least one assertion failed (see the summary above)"
fi
echo
echo "Inbound connections into an enforced box work, and its own egress stays judged."
