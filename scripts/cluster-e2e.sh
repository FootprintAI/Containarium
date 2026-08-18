#!/usr/bin/env bash
#
# cluster-e2e.sh — the gated KVM e2e lane for managed Kubernetes
# clusters (#1418). Builds the CLI+daemon from this tree, starts a real
# daemon against a real Postgres on a VM-capable Incus host, and runs
# the six-step MVP journey in test/e2e/cluster/ against it.
#
# Local use:   sudo -v && bash scripts/cluster-e2e.sh
# Sabotage:    CONTAINARIUM_E2E_SABOTAGE=join-token bash scripts/cluster-e2e.sh
#              (expected to exit non-zero — that is the point; the
#              workflow's prove-can-fail job asserts it)
# CI:          .github/workflows/cluster-e2e.yml on the self-hosted
#              incus+kvm runner (nightly + release tags, not per-PR).
#
# Host requirements (the runner-provisioning half of #1418):
#   - Incus with a usable storage pool at /var/lib/incus/unix.socket
#   - KVM (/dev/kvm) — cluster nodes are VMs, not containers
#   - Go toolchain, passwordless sudo for the invoking user
#   - Postgres reachable via CONTAINARIUM_POSTGRES_URL, or Docker/Podman
#     available so the script can start a throwaway one
#   - Egress to github.com (k3s binary) and registry.k8s.io (CA, images)
#
# The Go test's exit status is the script's exit status — nothing here
# pipes it away (a green lane must be evidence the test ran).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

GRPC_PORT="${CONTAINARIUM_E2E_GRPC_PORT:-15051}"
HTTP_PORT="${CONTAINARIUM_E2E_HTTP_PORT:-18080}"
WORKDIR="$(mktemp -d)"
BIN="$WORKDIR/containarium"
DAEMON_LOG="$WORKDIR/daemon.log"
PG_CONTAINER=""
DAEMON_PID=""

# The tenant/cluster names the Go test uses; the sweep below must match.
VM_PREFIX="e2etenant-k8s-lane-"

log() { echo "==> $*"; }

fail() { echo "FATAL: $*" >&2; exit 1; }

# --- pre-flight: fail loudly, never skip silently -----------------------
[ -e /dev/kvm ] || fail "no /dev/kvm — this lane needs a KVM-capable host (nested virt on a VM runner)"
[ -S /var/lib/incus/unix.socket ] || fail "no Incus socket at /var/lib/incus/unix.socket"
command -v go >/dev/null || fail "no Go toolchain"
sudo -n true 2>/dev/null || fail "needs passwordless sudo (daemon and Incus operations run as root)"

cleanup() {
  status=$?
  set +e
  if [ -n "$DAEMON_PID" ]; then
    log "stopping daemon (pid $DAEMON_PID)"
    sudo kill "$DAEMON_PID" 2>/dev/null
    sleep 2
    sudo kill -9 "$DAEMON_PID" 2>/dev/null
  fi
  # Sweep any VMs a red run left behind, so the next nightly starts clean.
  for vm in $(sudo incus list --format csv --columns n 2>/dev/null | grep "^${VM_PREFIX}" || true); do
    log "sweeping leftover VM $vm"
    sudo incus delete --force "$vm" 2>/dev/null
  done
  if [ -n "$PG_CONTAINER" ]; then
    log "stopping throwaway postgres"
    "$CONTAINER_RUNTIME" rm -f "$PG_CONTAINER" >/dev/null 2>&1
  fi
  if [ $status -ne 0 ] && [ -f "$DAEMON_LOG" ]; then
    echo "---- daemon log (last 100 lines) ----"
    tail -100 "$DAEMON_LOG"
  fi
  rm -rf "$WORKDIR"
  exit $status
}
trap cleanup EXIT

# --- postgres: real, per the design's real-vs-faked table ---------------
if [ -z "${CONTAINARIUM_POSTGRES_URL:-}" ]; then
  CONTAINER_RUNTIME="$(command -v docker || command -v podman || true)"
  [ -n "$CONTAINER_RUNTIME" ] || fail "set CONTAINARIUM_POSTGRES_URL or install docker/podman for a throwaway postgres"
  PG_PORT="$(( (RANDOM % 1000) + 15432 ))"
  PG_CONTAINER="cluster-e2e-pg-$$"
  log "starting throwaway postgres on :$PG_PORT"
  "$CONTAINER_RUNTIME" run -d --name "$PG_CONTAINER" \
    -e POSTGRES_USER=containarium -e POSTGRES_PASSWORD=e2e -e POSTGRES_DB=containarium \
    -p "127.0.0.1:${PG_PORT}:5432" postgres:16-alpine >/dev/null
  export CONTAINARIUM_POSTGRES_URL="postgres://containarium:e2e@127.0.0.1:${PG_PORT}/containarium?sslmode=disable"
  for _ in $(seq 1 30); do
    "$CONTAINER_RUNTIME" exec "$PG_CONTAINER" pg_isready -U containarium >/dev/null 2>&1 && break
    sleep 1
  done
  "$CONTAINER_RUNTIME" exec "$PG_CONTAINER" pg_isready -U containarium >/dev/null 2>&1 \
    || fail "postgres did not become ready"
else
  CONTAINER_RUNTIME=""
fi

# --- build the system under test ----------------------------------------
log "building containarium"
go build -o "$BIN" ./cmd/containarium

# --- daemon environment --------------------------------------------------
JWT_SECRET="${CONTAINARIUM_JWT_SECRET:-$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
ADVERTISE_HOST="${CONTAINARIUM_E2E_ADVERTISE_HOST:-$(ip -4 route get 1.1.1.1 | sed -n 's/.*src \([0-9.]*\).*/\1/p')}"
[ -n "$ADVERTISE_HOST" ] || fail "could not determine the host's advertise address; set CONTAINARIUM_E2E_ADVERTISE_HOST"

log "starting daemon (grpc :$GRPC_PORT http :$HTTP_PORT advertise $ADVERTISE_HOST)"
sudo env \
  CONTAINARIUM_JWT_SECRET="$JWT_SECRET" \
  CONTAINARIUM_POSTGRES_URL="$CONTAINARIUM_POSTGRES_URL" \
  CONTAINARIUM_CLUSTER_ADVERTISE_ADDR="$ADVERTISE_HOST" \
  CONTAINARIUM_CLUSTER_CA_ADVERTISE="$ADVERTISE_HOST:36442" \
  CONTAINARIUM_CLUSTER_CA_PKI_DIR="$WORKDIR/cluster-ca" \
  "$BIN" daemon --port "$GRPC_PORT" --http-port "$HTTP_PORT" \
  >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!

# Readiness: any HTTP answer on the gateway port means the REST surface
# is up. Authenticated calls are the Go test's job — it mints its own
# tenant token from the same secret.
log "waiting for the daemon's HTTP gateway"
for i in $(seq 1 60); do
  if ! sudo kill -0 "$DAEMON_PID" 2>/dev/null; then
    fail "daemon exited during startup"
  fi
  if curl -s -o /dev/null "http://127.0.0.1:$HTTP_PORT/v1/clusters"; then
    break
  fi
  [ "$i" = 60 ] && fail "daemon HTTP gateway not answering after 120s"
  sleep 2
done

# --- run the lane --------------------------------------------------------
log "running the six-step journey (sabotage: ${CONTAINARIUM_E2E_SABOTAGE:-none})"
sudo env \
  PATH="$PATH" HOME="$HOME" GOFLAGS="${GOFLAGS:-}" GOCACHE="$(go env GOCACHE)" GOMODCACHE="$(go env GOMODCACHE)" \
  CONTAINARIUM_REQUIRE_INCUS=1 \
  CONTAINARIUM_E2E_CLI="$BIN" \
  CONTAINARIUM_E2E_SERVER="127.0.0.1:$HTTP_PORT" \
  CONTAINARIUM_E2E_ADVERTISE_HOST="$ADVERTISE_HOST" \
  CONTAINARIUM_JWT_SECRET="$JWT_SECRET" \
  CONTAINARIUM_E2E_SABOTAGE="${CONTAINARIUM_E2E_SABOTAGE:-}" \
  go test -tags 'incus cluster_e2e' -count=1 -timeout 110m -v ./test/e2e/cluster/
