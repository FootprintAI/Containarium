#!/usr/bin/env bash
#
# tenant-core-infra-network-isolation-e2e.sh — proves (or disproves) one
# specific multi-tenant boundary: can an ordinary tenant container reach the
# platform's own core-role infrastructure (core-postgres, core-victoriametrics,
# ...) at the network layer, independent of any application-level credential?
#
# Written as part of a /security-multi-tenant assessment (2026-09-27),
# triggered by a live incident: containarium-core-postgres was found running
# with the compiled-in default password AND a pg_hba.conf rule open to the
# entire tenant bridge subnet. The password + pg_hba were fixed on every
# reachable backend (see docs/security/multi-tenant-isolation.md), but fixing
# the credential does not answer this script's question — this asks the
# NETWORK question, one layer below: could ANY tenant even attempt to
# authenticate at all, regardless of what the credential is?
#
# THIS TEST IS EXPECTED TO FAIL (red) as written, on every backend, today.
# That is not a test bug — the assessment found there is currently no
# mechanism that would make it pass: the existing per-org NetworkPolicy/eBPF
# enforcer (Containarium-cloud's network_policy_reconciler.go) is scoped to
# tenant-to-tenant cross-org isolation only and has never treated core-role
# containers as a subject at all. See the tracking issue this script's
# reproduction was filed against.
#
# Usage (run ON the backend host itself, as an operator with incus access —
# this is not something a tenant can run, only something an operator
# verifies FOR tenants):
#   sudo bash scripts/tenant-core-infra-network-isolation-e2e.sh <tenant-container-name>
#
# <tenant-container-name> must be a REAL, already-existing, ordinary tenant
# container on this host (not a core-* container) — this script never
# creates one, to avoid needing platform credit/billing access just to run a
# security check, and never touches that tenant's own data, only its network
# namespace via `incus exec` for a bare TCP connect attempt.

set -uo pipefail

TENANT="${1:?usage: $0 <tenant-container-name>}"
FAILS=0

if ! incus info "$TENANT" >/dev/null 2>&1; then
  echo "FATAL: no such container %q on this host: $TENANT"
  exit 2
fi
case "$TENANT" in
  core-*|containarium-core-*) echo "FATAL: $TENANT looks like a core/platform container, not a tenant — refusing to use it as the fixture."; exit 2 ;;
esac

echo "== discovering core-role containers on this host"
CORE_NAMES=$(incus list --format csv -c n 2>/dev/null | grep -E "^containarium-core-")
if [ -z "$CORE_NAMES" ]; then
  echo "No containarium-core-* containers found on this host — nothing to test."
  exit 0
fi

for core in $CORE_NAMES; do
  ip=$(incus list "$core" --format csv -c 4 2>/dev/null | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | head -1)
  [ -z "$ip" ] && { echo "SKIP $core: no IPv4 address found"; continue; }

  # Ports a tenant must NOT be able to reach per role — everything the
  # guard's table (internal/coreguard) reserves for the host gateway, the
  # control plane, or a named core peer. Caddy 80/443 and the OTLP receiver
  # 4317/4318 are *intended* tenant-reachable and are asserted the other
  # way round in scripts/core-guard-legit-flows-e2e.sh.
  case "$core" in
    *postgres*) ports="5432" ;;
    *victoriametrics*) ports="3000 8428 8880 9093" ;; # grafana, victoriametrics, vmalert, alertmanager
    *otelcollector*) ports="13133 8888" ;;             # health, self-metrics
    *caddy*) ports="2019" ;;                           # admin API — a tenant reaching it can rewrite routes
    *) ports="" ;;
  esac
  [ -z "$ports" ] && continue

  for port in $ports; do
    result=$(incus exec "$TENANT" -- bash -c "timeout 3 bash -c 'echo > /dev/tcp/$ip/$port' 2>&1 && echo succeeded || echo failed")
    echo "$TENANT -> $core ($ip:$port): TCP connect $result"
    if [ "$result" = "succeeded" ]; then
      echo "  FAIL: tenant container reached platform infra at the network layer — no isolation boundary exists for $core:$port"
      FAILS=$((FAILS + 1))
    else
      echo "  OK: connection denied at the network layer"
    fi
  done
done

echo
if [ "$FAILS" -eq 0 ]; then
  echo "PASS: no tenant->core-infra network path found"
else
  echo "FAILED: $FAILS tenant->core-infra network path(s) exist with no isolation boundary — see docs/security/multi-tenant-isolation.md"
  exit 1
fi
