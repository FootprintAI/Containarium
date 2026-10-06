#!/usr/bin/env bash
#
# tenant-guard-legit-flows-e2e.sh — the POSITIVE half of the tenant network
# guard's acceptance gate (docs/architecture/tenant-network-guard.md).
#
# scripts/tenant-tenant-network-isolation-e2e.sh proves tenants are kept
# apart. This script proves the guard did not also break what must keep
# working: a tenant's own boxes reach each other, the host reaches every
# box, Caddy reaches a box, a box reaches Caddy and the internet, and a
# guarded box still renews its DHCP lease. Every expected drop leaves a
# kernel-log line (security.acls.default.ingress.logged=true). A guard that
# breaks the platform is not a fix.
#
# Run ON the backend host as an operator with incus access, with the guard
# on (the default; CONTAINARIUM_TENANT_GUARD unset or "enforce") and the
# daemon having reconciled:
#   sudo bash scripts/tenant-guard-legit-flows-e2e.sh <a1> <a2> <b>
#
# <a1> and <a2> are two running containers of ONE tenant; <b> is a running
# container of ANOTHER tenant. Use fixture tenants, never real customers.
#
# Expected results (any deviation is a FAIL, exit 1):
#   a1 -> a2:22                       ok    (same tenant)
#   a2 -> a1:22                       ok    (same tenant, other direction)
#   host -> a1:22                     ok    (sentinel / daemon path)
#   core-caddy -> a1:22               ok    (reverse proxy to a box)   [SKIP if no caddy here]
#   a1 -> core-caddy:443              ok    (platform API in-bridge)   [SKIP if no caddy here]
#   a1 -> dhcp renew                  ok    (udhcpc/dhclient against the host)
#   a1 -> b:22                        DROP
#   b  -> a1:22                       DROP
#   each guarded NIC carries containarium-tenant-* in security.acls
#   kernel log carries one line per DROP above

set -uo pipefail

A1="${1:?usage: $0 <a1> <a2> <b>}"
A2="${2:?usage: $0 <a1> <a2> <b>}"
B="${3:?usage: $0 <a1> <a2> <b>}"
FAILS=0
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-3}"

for c in "$A1" "$A2" "$B"; do
  if ! incus info "$c" >/dev/null 2>&1; then
    echo "FATAL: no such container on this host: $c"; exit 2
  fi
  case "$c" in
    core-*|containarium-core-*) echo "FATAL: $c looks like a core/platform container, not a tenant — refusing."; exit 2 ;;
  esac
done

bridge_ip() {
  local ips
  ips=$(incus list "$1" --format csv -c 4 2>/dev/null)
  echo "$ips" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ \(eth0\)" | head -1 | cut -d' ' -f1 | grep . \
    || echo "$ips" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | head -1
}

IP_A1=$(bridge_ip "$A1"); IP_A2=$(bridge_ip "$A2"); IP_B=$(bridge_ip "$B")
[ -z "$IP_A1" ] || [ -z "$IP_A2" ] || [ -z "$IP_B" ] && { echo "FATAL: could not resolve a bridge IPv4 for all three containers"; exit 2; }
CADDY=$(incus list --format csv -c n 2>/dev/null | grep -E '^containarium-core-caddy$' || true)
IP_CADDY=""; [ -n "$CADDY" ] && IP_CADDY=$(bridge_ip "$CADDY")
SINCE=$(date '+%Y-%m-%d %H:%M:%S')

echo "== fixtures: $A1 ($IP_A1), $A2 ($IP_A2) same tenant; $B ($IP_B) other tenant; caddy=${CADDY:-<none>}"

# connect <label> <expect ok|drop> <from-container|host> <ip> <port>
connect() {
  local label="$1" expect="$2" from="$3" ip="$4" port="$5" r
  if [ "$from" = "host" ]; then
    r=$(timeout "$CONNECT_TIMEOUT" bash -c "echo > /dev/tcp/$ip/$port" 2>&1 | grep -q refused && echo refused || { timeout "$CONNECT_TIMEOUT" bash -c "echo > /dev/tcp/$ip/$port" >/dev/null 2>&1 && echo ok || echo timeout; })
  else
    r=$(incus exec "$from" -- bash -c "out=\$(timeout $CONNECT_TIMEOUT bash -c 'echo > /dev/tcp/$ip/$port' 2>&1); rc=\$?; case \"\$out\" in *refused*) echo refused;; *) [ \$rc -eq 0 ] && echo ok || echo timeout;; esac")
  fi
  # 'refused' means the peer answered with RST: reachable at L3, just no
  # listener. For an expected-ok row that still proves the path is open.
  case "$expect:$r" in
    ok:ok|ok:refused) echo "OK    $label ($r)" ;;
    drop:timeout)     echo "OK    $label (dropped)" ;;
    ok:*)             echo "FAIL  $label: expected reachable, got $r"; FAILS=$((FAILS+1)) ;;
    drop:*)           echo "FAIL  $label: expected DROP, got $r"; FAILS=$((FAILS+1)) ;;
  esac
}

echo "== flows that must work"
connect "$A1 -> $A2:22 (same tenant)" ok "$A1" "$IP_A2" 22
connect "$A2 -> $A1:22 (same tenant)" ok "$A2" "$IP_A1" 22
connect "host -> $A1:22" ok host "$IP_A1" 22
if [ -n "$IP_CADDY" ]; then
  connect "core-caddy -> $A1:22" ok "$CADDY" "$IP_A1" 22
  connect "$A1 -> core-caddy:443" ok "$A1" "$IP_CADDY" 443
else
  echo "SKIP  caddy rows: no containarium-core-caddy on this host"
fi

echo "== DHCP renew inside a guarded box (offers come from the host gateway)"
renew=$(incus exec "$A1" -- bash -c '
  if command -v dhclient >/dev/null 2>&1; then timeout 20 dhclient -1 -v eth0 >/tmp/dhcp.log 2>&1 && echo ok || echo fail;
  elif command -v udhcpc >/dev/null 2>&1; then timeout 20 udhcpc -i eth0 -n -q >/tmp/dhcp.log 2>&1 && echo ok || echo fail;
  elif command -v networkctl >/dev/null 2>&1; then networkctl renew eth0 >/dev/null 2>&1 && sleep 3 && ip -4 addr show eth0 | grep -q inet && echo ok || echo fail;
  else echo skip; fi' 2>/dev/null)
case "$renew" in
  ok)   echo "OK    $A1 renewed its lease" ;;
  skip) echo "SKIP  no DHCP client in $A1" ;;
  *)    echo "FAIL  $A1 could not renew its DHCP lease"; FAILS=$((FAILS+1)) ;;
esac

echo "== flows that must be dropped"
connect "$A1 -> $B:22 (other tenant)" drop "$A1" "$IP_B" 22
connect "$B -> $A1:22 (other tenant)" drop "$B" "$IP_A1" 22

echo "== each tenant NIC carries a tenant-guard ACL"
for c in "$A1" "$A2" "$B"; do
  acls=$(incus config device get "$c" eth0 security.acls 2>/dev/null || true)
  case "$acls" in
    *containarium-tenant-*) echo "OK    $c eth0 security.acls=$acls" ;;
    *) echo "FAIL  $c eth0 security.acls=${acls:-<unset>} (no containarium-tenant-* ACL)"; FAILS=$((FAILS+1)) ;;
  esac
done

echo "== each drop must be logged (security.acls.default.ingress.logged=true)"
if ! command -v journalctl >/dev/null 2>&1; then
  echo "SKIP  no journalctl on this host; check dmesg for SRC=$IP_A1 / SRC=$IP_B lines by hand"
else
  klog="$(journalctl -k --since "$SINCE" --no-pager 2>/dev/null || true)"
  for pair in "$IP_A1 $IP_B" "$IP_B $IP_A1"; do
    set -- $pair
    if grep -qE "SRC=$1 .*DST=$2 .*DPT=22\b" <<<"$klog"; then
      echo "OK    kernel log has a drop line for $1 -> $2"
    else
      echo "FAIL  no kernel log line for $1 -> $2 (is default.ingress.logged=true on the NIC?)"; FAILS=$((FAILS+1))
    fi
  done
fi

echo
if [ "$FAILS" -eq 0 ]; then
  echo "PASS: tenant guard keeps tenants apart without breaking legitimate flows"
else
  echo "FAILED: $FAILS check(s) — see docs/architecture/tenant-network-guard.md"
  exit 1
fi
