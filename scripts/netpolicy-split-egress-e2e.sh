#!/usr/bin/env bash
#
# netpolicy-split-egress-e2e.sh — proves the split egress mode (#2970 / #2974)
# end to end with the daemon's enforce switch ON (#2981): a real daemon, the
# real eBPF object, two real tenant containers on one Incus bridge, real
# packets, and the audit rows the daemon writes from each deny event's
# verdict byte.
#
# A tenant's policy has two modes. `mode` governs the cross-tenant,
# intra-tenant and metadata checks; `egress_mode` governs only a miss on the
# egress allow-list (experimental/ebpf-phaseA/netpolicy.bpf.c, netpolicy_ingress:
# `deny_mode = cfg->egress_mode` on an allow-list miss). The scenario:
#
#   phase 1  A: mode=ENFORCE, egress_mode=LOG_ONLY
#            A -> B             dropped, audited network_policy.deny_dropped
#            A -> unlisted host passes,  audited network_policy.deny_logged
#   phase 2  A: mode=LOG_ONLY, egress_mode=ENFORCE (the reverse split)
#            A -> unlisted host dropped, audited network_policy.deny_dropped
#            A -> B             follows mode: passes, audited deny_logged
#   both     B (no stored policy) keeps its reachability and is never dropped.
#
# Why the audit action proves the verdict byte: OnDenyEvent labels a row from
# the verdict the program reported, and falls back to the tenant-wide `mode`
# only for an event without one (network_policy_enforcer.go,
# denyEventDropped). In both split phases that fallback gives the OPPOSITE
# label for the allow-list miss, so `deny_logged` in phase 1 and
# `deny_dropped` in phase 2 can only come from the verdict byte.
#
# The "unlisted host" is the bridge gateway (the runner host itself): it is
# not a managed container (so it reaches the allow-list branch, not the
# cross-tenant one), A's policy lists no egress CIDR and no preset (so the
# gateway is not implicitly allowed), and it answers ICMP without any
# internet dependency. ICMP is used throughout so neither box needs a
# listener installed.
#
# The enforcer is sender-side with no connection tracking: a reply is policed
# as the replier's own egress. So "B is unaffected" is asserted on B's own
# egress and on B's audit verdicts, not on B -> A (A's echo replies are A -> B
# traffic and follow A's `mode`).
#
# Preconditions (the workflow sets them; the script checks what it can):
#   - the daemon runs with CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT set,
#     CONTAINARIUM_NETWORK_POLICY_ENFORCE=1 and --postgres;
#   - CONTAINARIUM_TENANT_GUARD=off, so the eBPF enforcer is the only filter
#     between the two boxes (the guard's Incus NIC ACL drops cross-tenant
#     ingress regardless of policy, which would hide phase 2's "A -> B
#     follows mode"; the guard has its own lane, tenant-guard-e2e.yml);
#   - containers <tenant-a>-container and <tenant-b>-container exist, owned
#     by the two tenants, and B has no stored network policy.
#
# Usage (on the lane host, with incus access via sudo):
#   scripts/netpolicy-split-egress-e2e.sh <tenant-a> <tenant-b>
#
# Environment:
#   SERVER                      daemon HTTP address (required)
#   CONTAINARIUM_TOKEN          admin token (required; read by the CLI)
#   CONTAINARIUM_HTTP=true      talk REST (read by the CLI)
#   CONTAINARIUM_POSTGRES_URL   audit store DSN for `audit query` (required)
#   CONTAINARIUM_CLI            CLI binary (default /tmp/containarium)
#
# Exit status: 0 when every assertion held, 1 on the first that did not.

set -euo pipefail

A=${1:?usage: $0 <tenant-a> <tenant-b>}
B=${2:?usage: $0 <tenant-a> <tenant-b>}
CLI=${CONTAINARIUM_CLI:-/tmp/containarium}
: "${SERVER:?SERVER (daemon HTTP address) is required}"
: "${CONTAINARIUM_TOKEN:?CONTAINARIUM_TOKEN (admin token) is required}"
: "${CONTAINARIUM_POSTGRES_URL:?CONTAINARIUM_POSTGRES_URL (audit store) is required}"
AC="${A}-container"
BC="${B}-container"

fail() { echo "::error::$*"; exit 1; }
step() { echo; echo "=== $* ==="; }
cli() { "$CLI" --server "$SERVER" "$@"; }
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

for tool in jq sudo; do
  command -v "$tool" >/dev/null || fail "$tool is required"
done
test -x "$CLI" || fail "CLI binary $CLI is missing"

# ---------------------------------------------------------------------------
# Reachability probes. ping exits 0 only when a reply came back.
# ---------------------------------------------------------------------------

# reaches <container> <dst>: retried, because a fresh bridge or ARP entry can
# lose the first echo; a single success is enough.
reaches() {
  local c=$1 dst=$2
  for _ in 1 2 3; do
    if sudo incus exec "$c" -- ping -c 2 -W 2 "$dst" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

expect_reach() {
  local what=$1 c=$2 dst=$3
  if reaches "$c" "$dst"; then
    echo "ok: $what ($c -> $dst) passes"
  else
    fail "$what: $c -> $dst got no reply, want it to pass"
  fi
}

# expect_blocked: one burst of 3 echoes; ANY reply is a failure.
expect_blocked() {
  local what=$1 c=$2 dst=$3
  if sudo incus exec "$c" -- ping -c 3 -W 2 "$dst" >/dev/null 2>&1; then
    fail "$what: $c -> $dst got a reply, want it dropped"
  fi
  echo "ok: $what ($c -> $dst) dropped"
}

# ---------------------------------------------------------------------------
# Audit rows. `audit query --raw` is tab-separated:
# timestamp, username, action, resource_type, resource_id, status, detail.
# ---------------------------------------------------------------------------

# audit_rows <action> <tenant> <dst> <from>: matching rows, one per line.
audit_rows() {
  local action=$1 tenant=$2 dst=$3 from=$4 out
  out=$("$CLI" audit query --resource-type network_policy --action "$action" \
          --from "$from" --limit 1000 --raw) || fail "audit query failed (action=$action)"
  printf '%s\n' "$out" | awk -F'\t' -v t="$tenant" '$5 == t' | grep -F "\"dst\":\"$dst\"" || true
}

# expect_audit: poll up to 30s for at least one matching row.
expect_audit() {
  local action=$1 tenant=$2 dst=$3 from=$4 rows
  for _ in $(seq 1 15); do
    rows=$(audit_rows "$action" "$tenant" "$dst" "$from")
    if [ -n "$rows" ]; then
      echo "ok: audited $action for $tenant -> $dst"
      printf '%s\n' "$rows" | head -1
      return 0
    fi
    sleep 2
  done
  echo "--- every network_policy audit row since $from ---"
  "$CLI" audit query --resource-type network_policy --from "$from" --limit 200 --raw || true
  fail "no $action audit row for $tenant -> $dst since $from"
}

# expect_no_audit: call only after a positive expect_audit of the same flow,
# so the deny events of the probe have already been written.
expect_no_audit() {
  local action=$1 tenant=$2 dst=$3 from=$4 rows
  rows=$(audit_rows "$action" "$tenant" "$dst" "$from")
  if [ -n "$rows" ]; then
    printf '%s\n' "$rows"
    fail "unexpected $action audit row(s) for $tenant -> $dst since $from"
  fi
  echo "ok: no $action audit row for $tenant -> $dst"
}

# ---------------------------------------------------------------------------
# Applied state. Wait until the daemon reports the tenant's policy loaded on
# every running box with the wanted effective modes and the enforce switch
# armed — so the probes below hit the kernel state they are meant to test.
# ---------------------------------------------------------------------------
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
step "Resolve addresses"
A_IP=$(cli get "$A" --format json | jq -r '.containers[0].IPAddress') || fail "could not get $A"
B_IP=$(cli get "$B" --format json | jq -r '.containers[0].IPAddress') || fail "could not get $B"
GW=$(sudo incus exec "$AC" -- ip -4 route show default | awk '{print $3; exit}') || fail "could not read $AC's default route"
for v in "$A_IP" "$B_IP" "$GW"; do
  if [ -z "$v" ] || [ "$v" = "null" ]; then
    fail "could not resolve A=$A_IP B=$B_IP gateway=$GW"
  fi
done
echo "A=$A_IP B=$B_IP unlisted host (bridge gateway)=$GW"

POLICIES=$(cli network-policy list --json) || fail "network-policy list failed"
if printf '%s' "$POLICIES" | jq -e --arg t "$B" 'any(.[]?; .tenant == $t)' >/dev/null; then
  fail "$B has a stored network policy; the scenario needs B on the default posture"
fi

T0=$(now)

# Baseline, before A has any stored policy: every path the scenario later
# expects dropped must pass here, or a later "dropped" would prove nothing.
step "Baseline (no stored policy for $A)"
expect_reach "baseline A -> B" "$AC" "$B_IP"
expect_reach "baseline A -> unlisted host" "$AC" "$GW"
expect_reach "baseline B -> unlisted host" "$BC" "$GW"

# ---------------------------------------------------------------------------
step "Phase 1: $A mode=ENFORCE, egress_mode=LOG_ONLY"
cli network-policy set "$A" --mode enforce --egress-mode log_only
wait_applied "$A" ENFORCE LOG_ONLY
# Audit timestamps have second resolution: keep baseline rows out of phase 1.
sleep 5
T1=$(now)

expect_blocked "phase 1 A -> B (mode=ENFORCE)" "$AC" "$B_IP"
expect_reach "phase 1 A -> unlisted host (egress_mode=LOG_ONLY)" "$AC" "$GW"
expect_reach "phase 1 B -> unlisted host" "$BC" "$GW"

expect_audit network_policy.deny_dropped "$A" "$B_IP" "$T1"
expect_audit network_policy.deny_logged "$A" "$GW" "$T1"
expect_no_audit network_policy.deny_dropped "$A" "$GW" "$T1"

# ---------------------------------------------------------------------------
step "Phase 2 (reverse split): $A mode=LOG_ONLY, egress_mode=ENFORCE"
cli network-policy set "$A" --mode log_only --egress-mode enforce
wait_applied "$A" LOG_ONLY ENFORCE
# Let any phase-1 audit write still in flight land before T2.
sleep 5
T2=$(now)

expect_blocked "phase 2 A -> unlisted host (egress_mode=ENFORCE)" "$AC" "$GW"
expect_reach "phase 2 A -> B (follows mode=LOG_ONLY)" "$AC" "$B_IP"
expect_reach "phase 2 B -> unlisted host" "$BC" "$GW"

expect_audit network_policy.deny_dropped "$A" "$GW" "$T2"
expect_audit network_policy.deny_logged "$A" "$B_IP" "$T2"
expect_no_audit network_policy.deny_dropped "$A" "$B_IP" "$T2"

# ---------------------------------------------------------------------------
step "B unaffected by A's policy"
# B's own policy never armed: no deny of B's was dropped at any point.
B_DROPPED=$("$CLI" audit query --resource-type network_policy --action network_policy.deny_dropped \
              --from "$T0" --limit 1000 --raw | awk -F'\t' -v t="$B" '$5 == t') \
  || fail "audit query failed (B drops)"
if [ -n "$B_DROPPED" ]; then
  printf '%s\n' "$B_DROPPED"
  fail "$B had dropped packets while only $A's policy changed"
fi
echo "ok: no dropped packet for $B since $T0"
B_ST=$(cli network-policy status "$B" --json)
printf '%s\n' "$B_ST" | jq -c '{state, effectiveMode, effectiveEgressMode}'
if printf '%s' "$B_ST" | jq -e '.effectiveMode == "NETWORK_POLICY_MODE_ENFORCE" or .effectiveEgressMode == "NETWORK_POLICY_MODE_ENFORCE"' >/dev/null; then
  fail "$B reports an ENFORCE mode although it has no stored policy"
fi
echo "ok: $B is not enforced"

echo
echo "Split egress mode proven end to end with the enforce switch on."
