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

# tenant_of resolves the fixture's tenant the way the daemon does (explicit
# tenant key, cloud attribution label, <tenant>-container name). A fixture
# whose tenant cannot be established is a fixture error — never a synthetic
# tenant, which would let two unattributable boxes pass the "different
# tenants" precondition without being tenant containers at all.
tenant_of() {
  local c="$1" t
  t=$(incus config get "$c" user.containarium.tenant 2>/dev/null)
  [ -z "$t" ] && t=$(incus config get "$c" user.containarium.label.cloud_org_id 2>/dev/null)
  [ -z "$t" ] && case "$c" in *-container) t="${c%-container}" ;; esac
  echo "$t"
}

TA=$(tenant_of "$A"); TB=$(tenant_of "$B")
[ -z "$TA" ] && { echo "FATAL: cannot establish a tenant for $A (no tenant key, no cloud_org_id label, not <tenant>-container)"; exit 2; }
[ -z "$TB" ] && { echo "FATAL: cannot establish a tenant for $B (no tenant key, no cloud_org_id label, not <tenant>-container)"; exit 2; }
echo "== fixtures: $A (tenant $TA)  <->  $B (tenant $TB)"
if [ "$TA" = "$TB" ] && [ "${EXPECT_SAME_TENANT:-0}" != "1" ]; then
  echo "FATAL: both containers resolve to the same tenant ($TA); this test needs two tenants. Set EXPECT_SAME_TENANT=1 to run the mechanism check anyway."
  exit 2
fi

# bridge_ip: the fixture's IPv4 on eth0 (the bridge NIC), matched by EXACT
# name — `incus list NAME` is a prefix filter, and a podman box also reports
# docker0/cni addresses, so neither "first match" nor "first address" will do.
bridge_ip() {
  incus list "^$1\$" --format csv -c 4 2>/dev/null | tr ',' '\n' \
    | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ \(eth0\)" | head -1 | cut -d' ' -f1
}

IPA=$(bridge_ip "$A"); IPB=$(bridge_ip "$B")
[ -z "$IPA" ] && { echo "FATAL: $A has no IPv4 on eth0"; exit 2; }
[ -z "$IPB" ] && { echo "FATAL: $B has no IPv4 on eth0"; exit 2; }

# The effective NIC: tenant eth0 is usually profile-inherited, so read the
# expanded config rather than instance-local devices.
nic_keys() {
  incus config show --expanded "$1" 2>/dev/null \
    | awk '/^devices:/{d=1;next} d && /^  eth0:/{e=1;next} e && /^  [^ ]/{e=0} e && /security\./{gsub(/^ +/,""); print}'
}
echo "== effective NIC security keys on the tenant NICs (nothing printed = none set)"
for c in "$A" "$B"; do
  echo "  $c eth0:"; nic_keys "$c" | sed 's/^/    /'
done

# in_box <container> <script>: run a probe inside the container and print its
# RESULT line. A probe that could not run at all (incus exec failed, no shell,
# timeout binary missing) is a FATAL probe error, never a "failed connect":
# otherwise a broken fixture would print PASS without testing anything.
in_box() {
  local out
  out=$(incus exec "$1" -- bash -c "$2" 2>&1) || true
  case "$out" in
    *RESULT:*) echo "$out" | sed -n 's/.*RESULT://p' | tail -1 ;;
    *) echo "FATAL: probe could not run in $1: ${out:-<no output>}"; exit 3 ;;
  esac
}

# probe <from> <to-name> <to-ip>: ICMP echo, then TCP to sshd (22, present on
# every Containarium box), then a closed port. Any of them succeeding means
# there is no network-layer boundary between the two tenants.
probe() {
  local from="$1" to="$2" ip="$3" r
  # incus exec runs as root in the container, so ping has cap_net_raw; if it
  # still reports "Operation not permitted" the probe is inconclusive, not OK.
  r=$(in_box "$from" "out=\$(ping -c1 -W2 $ip 2>&1); rc=\$?; case \"\$out\" in *'not permitted'*) echo RESULT:inconclusive;; *) [ \$rc -eq 0 ] && echo RESULT:succeeded || echo RESULT:failed;; esac") || exit 3
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
  r=$(in_box "$from" "command -v timeout >/dev/null || { echo no-timeout; exit 0; }; if timeout 3 bash -c 'echo > /dev/tcp/$ip/9' 2>&1 | grep -q refused; then echo RESULT:refused; else echo RESULT:timeout; fi") || exit 3
  echo "$from -> $to ($ip:9, closed port): $r"
  if [ "$r" = "refused" ]; then
    echo "  FAIL: peer answered with RST — reachable at L3"
    FAILS=$((FAILS + 1))
  else
    echo "  OK: no answer (dropped or filtered)"
  fi
  r=$(in_box "$from" "command -v timeout >/dev/null || { echo no-timeout; exit 0; }; timeout 3 bash -c 'echo > /dev/tcp/$ip/22' 2>/dev/null && echo RESULT:succeeded || echo RESULT:failed") || exit 3
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
  # Scope the claim to what was exercised: three probes (ICMP, TCP/22, a
  # closed TCP port) in each direction. A port-specific rule set could pass
  # these while leaving a service port open; the guard's acceptance gate is
  # the default-deny mechanism itself, which the keys printed above and
  # scripts/tenant-guard-legit-flows-e2e.sh assert.
  echo "PASS: no tenant->tenant network path found between $A and $B on the probed paths (ICMP, TCP/22, TCP/9, both directions)"
else
  echo "FAILED: $FAILS tenant->tenant network path(s) exist with no isolation boundary — see docs/security/multi-tenant-isolation.md"
  exit 1
fi
