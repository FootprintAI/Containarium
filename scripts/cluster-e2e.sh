#!/usr/bin/env bash
#
# cluster-e2e.sh — the gated e2e lane for managed Kubernetes clusters
# (#1418). Builds the CLI+daemon from this tree, starts a real daemon
# against a real Postgres on a real Incus host, and runs the six-step
# MVP journey in test/e2e/cluster/ against it.
#
# Local use:   sudo -v && bash scripts/cluster-e2e.sh
# Sabotage:    CONTAINARIUM_E2E_SABOTAGE=join-token bash scripts/cluster-e2e.sh
#              (expected to exit non-zero — that is the point; the
#              workflow's prove-can-fail job asserts it)
# Container:   CONTAINARIUM_E2E_ISOLATION=container \
#              CONTAINARIUM_CLUSTER_ALLOW_CONTAINER_NODES=true \
#              bash scripts/cluster-e2e.sh
# CI:          .github/workflows/cluster-e2e.yml on the self-hosted
#              incus+kvm runner (nightly + release tags, not per-PR), and
#              .github/workflows/cluster-container-e2e.yml on a
#              GitHub-hosted runner for the container class (#1430).
#
# Isolation (#1430): CONTAINARIUM_E2E_ISOLATION selects the class the
# journey runs in — unset/`vm` (default, unchanged) or `container`.
# Container mode also needs the operator opt-in
# CONTAINARIUM_CLUSTER_ALLOW_CONTAINER_NODES=true, which this script only
# passes through: whether a host may weaken the tenant boundary is the
# operator's assertion to make, never the test script's.
#
# Host requirements (the runner-provisioning half of #1418):
#   - VM mode: capacity for the journey's worst case — ~16 vCPU (CP 2 +
#     up to 3×small 2 + one large 8), ~32 GB RAM, ~500 GB free in the
#     Incus pool. On a smaller host the daemon's CPU-admission gate will
#     correctly REFUSE the larger-class scale-up and the lane goes red
#     for an environmental reason that looks like a product bug.
#   - Incus with a usable storage pool at /var/lib/incus/unix.socket
#   - VM mode only: KVM (/dev/kvm). Container-mode nodes are Incus
#     system containers, which is why that lane can run KVM-less on a
#     GitHub-hosted runner; its preconditions (nesting, cgroup v2,
#     br_netfilter, overlay) are probed by the daemon itself, which
#     refuses loudly rather than provisioning a broken node.
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
ISOLATION="${CONTAINARIUM_E2E_ISOLATION:-vm}"
# The Go-side bound. Kept a knob so a lane whose job timeout is tighter
# than the KVM lane's 150m can still let the test time out first and
# print its diagnostics; the default is the KVM lane's unchanged value.
GO_TIMEOUT="${CONTAINARIUM_E2E_GO_TIMEOUT:-110m}"
WORKDIR="$(mktemp -d)"
BIN="$WORKDIR/containarium"
DAEMON_LOG="$WORKDIR/daemon.log"
PG_CONTAINER=""
DAEMON_PID=""

# The tenant/cluster names the Go test uses; the sweep below must match.
# Instances, not VMs: in container mode the same names are Incus system
# containers, and `incus list` reports both classes (#1430).
INSTANCE_PREFIX="e2etenant-k8s-lane-"

log() { echo "==> $*"; }

fail() { echo "FATAL: $*" >&2; exit 1; }

# --- pre-flight: fail loudly, never skip silently -----------------------
case "$ISOLATION" in
  vm)
    [ -e /dev/kvm ] || fail "no /dev/kvm — VM-mode nodes need a KVM-capable host (nested virt on a VM runner)"
    ;;
  container)
    # No KVM check: container-mode nodes are system containers. The
    # host's container-node preconditions are the daemon's probe to
    # make (#1429), and it refuses the create rather than provisioning
    # a node that cannot work.
    [ -n "${CONTAINARIUM_CLUSTER_ALLOW_CONTAINER_NODES:-}" ] \
      || fail "container mode needs the operator opt-in CONTAINARIUM_CLUSTER_ALLOW_CONTAINER_NODES=true; without it the daemon refuses container creates and the lane goes red for a configuration reason"
    ;;
  *)
    fail "unknown CONTAINARIUM_E2E_ISOLATION=$ISOLATION (want vm or container)"
    ;;
esac
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
  # Sweep any instances a red run left behind, so the next run starts
  # clean. `incus list` reports containers and VMs alike, so this sweeps
  # both isolation classes.
  for inst in $(sudo incus list --format csv --columns n 2>/dev/null | grep "^${INSTANCE_PREFIX}" || true); do
    log "sweeping leftover instance $inst"
    sudo incus delete --force "$inst" 2>/dev/null
  done
  if [ -n "$PG_CONTAINER" ]; then
    log "stopping throwaway postgres"
    "$CONTAINER_RUNTIME" rm -f "$PG_CONTAINER" >/dev/null 2>&1
  fi
  if [ $status -ne 0 ] && [ -f "$DAEMON_LOG" ]; then
    # Cluster lines first, over the WHOLE log. The tail alone is not
    # enough: the daemon decides at startup whether the autoscaler and
    # the endpoint publisher are wired at all, and says so once. In run
    # 15 that verdict sat ~200 lines above the tail window, so a lane
    # that failed on a missing scale-up could not answer "was the
    # autoscaler ever enabled?" from its own log.
    echo "---- daemon log: cluster/autoscaler lines (whole run) ----"
    grep -E '\[cluster\]|autoscaler|[Pp]assthrough|Managed-cluster' "$DAEMON_LOG" || echo "(none)"
    echo "---- daemon log (last 200 lines) ----"
    tail -200 "$DAEMON_LOG"
  fi
  # The daemon runs under sudo and creates root-owned trees here (the
  # cluster CA PKI dir among them), so an unprivileged rm leaves them
  # behind and prints a permission error that looks like a real
  # failure. Remove as root, matching who created it.
  sudo rm -rf "$WORKDIR" 2>/dev/null || rm -rf "$WORKDIR"
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
  # Probe over TCP (-h 127.0.0.1), never the Unix socket (#1514).
  #
  # The postgres entrypoint starts TWO servers: a temporary one for the
  # init phase, run with listen_addresses='"'"''"'"' so it is reachable only
  # over the Unix socket, and then -- after CREATE DATABASE and any init
  # scripts -- it SHUTS THAT ONE DOWN and starts the real server, which
  # is the first to listen on TCP. A default probe answers "ready"
  # about the temporary one, so this loop broke early, the entrypoint
  # shut that server down, and the confirming check below landed in the
  # shutdown window: red seven seconds into a ninety-second bound.
  #
  # The bound was previously raised 30s -> 90s against this symptom, on
  # the reading that a cold runner'"'"'s image pull plus initdb needed
  # longer. It could not help: the loop never reached its bound. 90s is
  # kept because a cold pull genuinely is slow, but the flake was never
  # a duration problem -- it was a check that answered about the wrong
  # server.
  for _ in $(seq 1 90); do
    "$CONTAINER_RUNTIME" exec "$PG_CONTAINER" pg_isready -h 127.0.0.1 -U containarium >/dev/null 2>&1 && break
    sleep 1
  done
  if ! "$CONTAINER_RUNTIME" exec "$PG_CONTAINER" pg_isready -h 127.0.0.1 -U containarium >/dev/null 2>&1; then
    # Say why, rather than just that. Without this the failure is
    # indistinguishable between "still starting", "crashed on startup"
    # and "port already bound".
    echo "---- postgres container state ----"
    "$CONTAINER_RUNTIME" ps -a --filter "name=$PG_CONTAINER" 2>&1 || true
    echo "---- postgres container log ----"
    "$CONTAINER_RUNTIME" logs "$PG_CONTAINER" 2>&1 | tail -40 || true
    fail "postgres did not become ready"
  fi
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

log "starting daemon (grpc :$GRPC_PORT http :$HTTP_PORT advertise $ADVERTISE_HOST isolation $ISOLATION)"
sudo env \
  CONTAINARIUM_JWT_SECRET="$JWT_SECRET" \
  CONTAINARIUM_POSTGRES_URL="$CONTAINARIUM_POSTGRES_URL" \
  CONTAINARIUM_CLUSTER_ALLOW_CONTAINER_NODES="${CONTAINARIUM_CLUSTER_ALLOW_CONTAINER_NODES:-}" \
  CONTAINARIUM_CLUSTER_ADVERTISE_ADDR="$ADVERTISE_HOST" \
  CONTAINARIUM_CLUSTER_CA_ADVERTISE="$ADVERTISE_HOST:36442" \
  CONTAINARIUM_CLUSTER_CA_PKI_DIR="$WORKDIR/cluster-ca" \
  "$BIN" daemon --port "$GRPC_PORT" --http-port "$HTTP_PORT" \
  >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!

# Readiness: any HTTP answer on the gateway port means the REST surface
# is up. Authenticated calls are the Go test's job — it mints its own
# tenant token from the same secret.
#
# The bound is 6 minutes, not the 2 it used to be: on a COLD host (an
# ephemeral GitHub-hosted runner, as opposed to a warm self-hosted one)
# the daemon spends up to 2 minutes waiting for core containers that
# have never existed before proceeding without them, and the old bound
# declared that a dead daemon. A warm host still answers in seconds, so
# nothing changes for the KVM lane except how long a genuinely stuck
# daemon takes to be reported.
DAEMON_WAIT_TRIES="${CONTAINARIUM_E2E_DAEMON_WAIT_TRIES:-180}"
log "waiting for the daemon's HTTP gateway (up to $((DAEMON_WAIT_TRIES * 2))s)"
for i in $(seq 1 "$DAEMON_WAIT_TRIES"); do
  if ! sudo kill -0 "$DAEMON_PID" 2>/dev/null; then
    fail "daemon exited during startup"
  fi
  if curl -s -o /dev/null "http://127.0.0.1:$HTTP_PORT/v1/clusters"; then
    break
  fi
  [ "$i" = "$DAEMON_WAIT_TRIES" ] && fail "daemon HTTP gateway not answering after $((DAEMON_WAIT_TRIES * 2))s"
  sleep 2
done

# --- run the lane --------------------------------------------------------
log "running the six-step journey (isolation: $ISOLATION, sabotage: ${CONTAINARIUM_E2E_SABOTAGE:-none})"
sudo env \
  PATH="$PATH" HOME="$HOME" GOFLAGS="${GOFLAGS:-}" GOCACHE="$(go env GOCACHE)" GOMODCACHE="$(go env GOMODCACHE)" \
  CONTAINARIUM_REQUIRE_INCUS=1 \
  CONTAINARIUM_E2E_CLI="$BIN" \
  CONTAINARIUM_E2E_SERVER="127.0.0.1:$HTTP_PORT" \
  CONTAINARIUM_E2E_ADVERTISE_HOST="$ADVERTISE_HOST" \
  CONTAINARIUM_JWT_SECRET="$JWT_SECRET" \
  CONTAINARIUM_E2E_SABOTAGE="${CONTAINARIUM_E2E_SABOTAGE:-}" \
  CONTAINARIUM_E2E_ISOLATION="$ISOLATION" \
  CONTAINARIUM_E2E_OFFHOST_PROBE="${CONTAINARIUM_E2E_OFFHOST_PROBE:-}" \
  CONTAINARIUM_E2E_READY_TIMEOUT="${CONTAINARIUM_E2E_READY_TIMEOUT:-}" \
  CONTAINARIUM_E2E_SCALEUP_TIMEOUT="${CONTAINARIUM_E2E_SCALEUP_TIMEOUT:-}" \
  CONTAINARIUM_E2E_VPA_TIMEOUT="${CONTAINARIUM_E2E_VPA_TIMEOUT:-}" \
  CONTAINARIUM_E2E_SCALEDOWN_TIMEOUT="${CONTAINARIUM_E2E_SCALEDOWN_TIMEOUT:-}" \
  CONTAINARIUM_E2E_DELETE_TIMEOUT="${CONTAINARIUM_E2E_DELETE_TIMEOUT:-}" \
  go test -tags 'incus cluster_e2e' -count=1 -timeout "$GO_TIMEOUT" -v ./test/e2e/cluster/
