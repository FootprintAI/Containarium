#!/usr/bin/env bash
#
# tenant-tenant-network-isolation-e2e.sh — proves (or disproves) the
# tenant-to-tenant boundary on a shared backend: can one tenant's container
# reach another tenant's container over the bridge (incusbr0), at the network
# layer, with no application credential involved?
#
# Companion to tenant-core-infra-network-isolation-e2e.sh (tenant -> core
# infra). That script asks whether a tenant can reach the platform; this one
# asks whether a tenant can reach a NEIGHBOUR. See
# docs/security/multi-tenant-isolation.md, "Tenant <-> tenant".
#
# THIS TEST IS EXPECTED TO FAIL (red) on a default-configured backend. The
# only mechanism that can drop tenant->tenant traffic is the eBPF
# NetworkPolicy enforcer (#315), and it drops only when ALL of these hold:
#   1. the daemon runs with CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT set,
#   2. the daemon runs with CONTAINARIUM_NETWORK_POLICY_ENFORCE=1,
#   3. the SENDING tenant has a stored policy with --mode enforce.
# A tenant with no policy is compiled as log_only (never dropped), the
# enforcer is sender-side only, and no Incus NIC key (security.port_isolation,
# security.mac_filtering, security.ipv4_filtering) or ACL is applied to tenant
# NICs. Turning this green is the acceptance criterion for the fix.
#
# Usage (run ON the backend host, as an operator with incus access — this is
# something an operator verifies FOR tenants, not something a tenant runs):
#   sudo bash scripts/tenant-tenant-network-isolation-e2e.sh <tenant-a> <tenant-b>
#
# <tenant-a> and <tenant-b> must be two already-existing, ordinary containers
# owned by DIFFERENT tenants (different user.containarium.tenant /
# cloud_org_id labels, or different <tenant>-container prefixes). Use fixture
# tenants, never real customers. The script never creates or modifies either
# container; it only uses `incus exec` in A's network namespace to attempt
# bare connections toward B's bridge address (and B toward A, because the
# enforcer is sender-side).
#
# Environment:
#   EXPECT_SAME_TENANT=1   skip the different-tenant precondition (only for
#                          exercising the mechanism with two boxes of one org
#                          on a backend that has no other tenants).

set -uo pipefail

A="${1:?usage: $0 <tenant-a> <tenant-b>}"
B="${2:?usage: $0 <tenant-a> <tenant-b>}"
FAILS=0

for c in "$A" "$B"; do
  if ! incus info "$c" >/dev/null 2>&1; then
    echo "FATAL: no such container on this host: $c"
    exit 2
  fi
  case "$c" in
    core-*|containarium-core-*)
      echo "FATAL: $c looks like a core/platform container, not a tenant — refusing."
      exit 2 ;;
  esac
done
[ "$A" = "$B" ] && { echo "FATAL: tenant-a and tenant-b must differ"; exit 2; }

tenant_of() {
  local c="$1" t
  t=$(incus config get "$c" user.containarium.tenant 2>/dev/null)
  [ -z "$t" ] && t=$(incus config get "$c" user.cloud_org_id 2>/dev/null)
  [ -z "$t" ] && case "$c" in *-container) t="${c%-container}" ;; esac
  echo "${t:-<unlabelled:$c>}"
}

TA=$(tenant_of "$A"); TB=$(tenant_of "$B")
echo "== fixtures: $A (tenant $TA)  <->  $B (tenant $TB)"
if [ "$TA" = "$TB" ] && [ "${EXPECT_SAME_TENANT:-0}" != "1" ]; then
  echo "FATAL: both containers resolve to the same tenant ($TA); this test needs two tenants. Set EXPECT_SAME_TENANT=1 to run the mechanism check anyway."
  exit 2
fi

bridge_ip() {
  local ips
  ips=$(incus list "$1" --format csv -c 4 2>/dev/null)
  echo "$ips" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ \(eth0\)" | head -1 | cut -d' ' -f1 | grep . \
    || echo "$ips" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | head -1
}

IPA=$(bridge_ip "$A"); IPB=$(bridge_ip "$B")
[ -z "$IPA" ] || [ -z "$IPB" ] && { echo "FATAL: could not resolve a bridge IPv4 for both containers"; exit 2; }

echo "== NIC isolation keys on the tenant NICs (empty = not set)"
for c in "$A" "$B"; do
  for k in security.port_isolation security.mac_filtering security.ipv4_filtering security.acls; do
    v=$(incus config device get "$c" eth0 "$k" 2>/dev/null || true)
    echo "  $c eth0 $k=${v:-<unset>}"
  done
done

# probe <from> <to-name> <to-ip>: ICMP echo, then TCP to sshd (22, present on
# every Containarium box). Either succeeding means there is no network-layer
# boundary between the two tenants.
probe() {
  local from="$1" to="$2" ip="$3" r
  # incus exec runs as root in the container, so ping has cap_net_raw; if it
  # still reports "Operation not permitted" the probe is inconclusive, not OK.
  r=$(incus exec "$from" -- bash -c "out=\$(ping -c1 -W2 $ip 2>&1); rc=\$?; case \"\$out\" in *'not permitted'*) echo inconclusive;; *) [ \$rc -eq 0 ] && echo succeeded || echo failed;; esac")
  echo "$from -> $to ($ip): ICMP echo $r"
  case "$r" in
    succeeded)
      echo "  FAIL: tenant container reached another tenant's container at the network layer"
      FAILS=$((FAILS + 1)) ;;
    inconclusive)
      echo "  SKIP: ping cannot open a raw socket here; TCP probe below is authoritative" ;;
    *)
      echo "  OK: denied at the network layer" ;;
  esac
  # A closed port answering with RST is still reachability: distinguish
  # "refused" (reachable) from a silent timeout (dropped).
  r=$(incus exec "$from" -- bash -c "timeout 3 bash -c 'echo > /dev/tcp/$ip/9' 2>&1 | grep -q 'refused' && echo refused || echo timeout")
  echo "$from -> $to ($ip:9, closed port): $r"
  if [ "$r" = "refused" ]; then
    echo "  FAIL: peer answered with RST — reachable at L3"
    FAILS=$((FAILS + 1))
  else
    echo "  OK: no answer (dropped or filtered)"
  fi
  r=$(incus exec "$from" -- bash -c "timeout 3 bash -c 'echo > /dev/tcp/$ip/22' 2>/dev/null && echo succeeded || echo failed")
  echo "$from -> $to ($ip:22): TCP connect $r"
  if [ "$r" = "succeeded" ]; then
    echo "  FAIL: tenant container opened a TCP connection to another tenant's sshd"
    FAILS=$((FAILS + 1))
  else
    echo "  OK: denied at the network layer"
  fi
}

echo "== probing A -> B"
probe "$A" "$B" "$IPB"
echo "== probing B -> A (enforcement is sender-side; both directions must hold)"
probe "$B" "$A" "$IPA"

echo
if [ "$FAILS" -eq 0 ]; then
  echo "PASS: no tenant->tenant network path found between $A and $B"
else
  echo "FAILED: $FAILS tenant->tenant network path(s) exist with no isolation boundary — see docs/security/multi-tenant-isolation.md"
  exit 1
fi
