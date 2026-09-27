#!/usr/bin/env bash
#
# core-guard-legit-flows-e2e.sh — the POSITIVE half of the core-infra network
# guard's acceptance gate (docs/architecture/core-infra-network-guard.md).
#
# scripts/tenant-core-infra-network-isolation-e2e.sh proves tenants are kept
# OUT. This script proves the guard did not also lock the platform out of
# itself: every flow the guard's table (internal/coreguard) deliberately
# allows still works, every flow it deliberately drops is dropped, and each
# drop leaves a kernel-log line (security.acls.default.ingress.logged=true).
# A guard that breaks the platform is not a fix.
#
# Run ON the backend host as an operator with incus access, AFTER the guard
# is enabled there (CONTAINARIUM_CORE_GUARD=enforce and the daemon has
# reconciled):
#   sudo bash scripts/core-guard-legit-flows-e2e.sh <tenant-container-name>
#
# <tenant-container-name> must be a real, running, ordinary tenant container
# on this host. Only its network namespace is used, for bare TCP connects.
#
# Expected results (any deviation is a FAIL, exit 1):
#   host gateway     -> core-postgres:5432          ok    (daemon pool)
#   victoriametrics  -> core-postgres:5432          ok    (grafana datastore)
#   tenant           -> core-caddy:443              ok    (platform API in-bridge)
#   tenant           -> core-otelcollector:4318     ok    (tenant OTLP push)
#   tenant           -> core-postgres:5432          DROP
#   tenant           -> core-victoriametrics:3000   DROP  (grafana)
#   tenant           -> core-caddy:2019             DROP  (admin API)
#   kernel log carries one line per DROP above
#
# A core role that is not deployed on this host is reported SKIP for its
# rows, not FAIL — the guard only governs what exists.

set -uo pipefail

TENANT="${1:?usage: $0 <tenant-container-name>}"
FAILS=0
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-3}"

if ! incus info "$TENANT" >/dev/null 2>&1; then
  echo "FATAL: no such container on this host: $TENANT"
  exit 2
fi
case "$TENANT" in
  core-*|containarium-core-*) echo "FATAL: $TENANT looks like a core/platform container, not a tenant — refusing to use it as the fixture."; exit 2 ;;
esac

# --- discovery ---------------------------------------------------------------

core_ip() { # $1 = role suffix (postgres, caddy, ...)
  incus list "containarium-core-$1" --format csv -c 4 2>/dev/null | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | head -1
}

BRIDGE=$(incus list "$TENANT" --format yaml 2>/dev/null | awk '/^ *network: /{print $2; exit}')
if [ -z "$BRIDGE" ]; then
  BRIDGE=$(incus network list --format csv -c n,t 2>/dev/null | awk -F, '$2=="bridge"{print $1; exit}')
fi
HOST_GW=$(incus network get "$BRIDGE" ipv4.address 2>/dev/null | cut -d/ -f1)
[ -z "$HOST_GW" ] && { echo "FATAL: could not determine the host gateway on bridge '$BRIDGE'"; exit 2; }

PG=$(core_ip postgres)
VM=$(core_ip victoriametrics)
CADDY=$(core_ip caddy)
OTEL=$(core_ip otelcollector)
TENANT_IP=$(incus list "$TENANT" --format csv -c 4 2>/dev/null | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | head -1)

echo "== bridge=$BRIDGE host_gw=$HOST_GW tenant=$TENANT($TENANT_IP)"
echo "== core: postgres=${PG:-absent} victoriametrics=${VM:-absent} caddy=${CADDY:-absent} otelcollector=${OTEL:-absent}"
echo

# --- probes ------------------------------------------------------------------

# tcp_from <where> <ip> <port>: where = "host" or a container name.
# Prints "succeeded" or "failed".
tcp_from() {
  local where="$1" ip="$2" port="$3"
  local probe="timeout $CONNECT_TIMEOUT bash -c 'echo > /dev/tcp/$ip/$port' 2>/dev/null && echo succeeded || echo failed"
  if [ "$where" = "host" ]; then
    bash -c "$probe"
  else
    incus exec "$where" -- bash -c "$probe" </dev/null
  fi
}

# expect <ok|drop> <where> <label> <ip> <port>
expect() {
  local want="$1" where="$2" label="$3" ip="$4" port="$5"
  if [ -z "$ip" ]; then
    echo "SKIP  $label: target role not deployed on this host"
    return
  fi
  local got
  got=$(tcp_from "$where" "$ip" "$port")
  case "$want:$got" in
    ok:succeeded)  echo "OK    $label ($ip:$port): reachable, as intended" ;;
    drop:failed)   echo "OK    $label ($ip:$port): dropped, as intended" ;;
    ok:failed)     echo "FAIL  $label ($ip:$port): legitimate flow is BROKEN by the guard"; FAILS=$((FAILS + 1)) ;;
    drop:succeeded) echo "FAIL  $label ($ip:$port): tenant reached platform infra — guard not enforcing"; FAILS=$((FAILS + 1)) ;;
  esac
}

echo "== legitimate flows must survive"
expect ok host  "host gateway -> postgres:5432"                     "$PG"    5432
if [ -n "$VM" ]; then
  expect ok "containarium-core-victoriametrics" "victoriametrics -> postgres:5432" "$PG" 5432
else
  echo "SKIP  victoriametrics -> postgres:5432: victoriametrics not deployed"
fi
expect ok "$TENANT" "tenant -> caddy:443"                           "$CADDY" 443
expect ok "$TENANT" "tenant -> otelcollector:4318"                  "$OTEL"  4318
echo

echo "== tenant reaching the data plane must be dropped"
SINCE=$(date '+%Y-%m-%d %H:%M:%S')
expect drop "$TENANT" "tenant -> postgres:5432"                     "$PG"    5432
expect drop "$TENANT" "tenant -> victoriametrics:3000 (grafana)"    "$VM"    3000
expect drop "$TENANT" "tenant -> caddy:2019 (admin API)"            "$CADDY" 2019
echo

# --- evidence ----------------------------------------------------------------

echo "== each drop must be logged (security.acls.default.ingress.logged=true)"
if ! command -v journalctl >/dev/null 2>&1; then
  echo "SKIP  no journalctl on this host; check dmesg for SRC=$TENANT_IP lines by hand"
else
  for spec in "$PG:5432" "$VM:3000" "$CADDY:2019"; do
    ip="${spec%%:*}"; port="${spec##*:}"
    [ -z "$ip" ] && continue
    if journalctl -k --since "$SINCE" --no-pager 2>/dev/null | grep -qE "SRC=$TENANT_IP .*DST=$ip .*DPT=$port\b"; then
      echo "OK    drop logged: $TENANT_IP -> $ip:$port"
    else
      echo "FAIL  no kernel-log line for $TENANT_IP -> $ip:$port since $SINCE (is default.ingress.logged=true on that NIC?)"
      FAILS=$((FAILS + 1))
    fi
  done
fi
echo

if [ "$FAILS" -eq 0 ]; then
  echo "PASS: guard enforces the table and the platform still talks to itself"
else
  echo "FAILED: $FAILS check(s) — see lines marked FAIL above"
  exit 1
fi
