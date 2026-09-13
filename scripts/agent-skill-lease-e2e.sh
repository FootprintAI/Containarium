#!/usr/bin/env bash
#
# agent-skill-lease-e2e.sh — the executable proof of the run-lease property
# (#1819): a skill run's credentials die with the run.
#
# Design: docs/architecture/execution-scoped-authorization.md (cloud repo),
# "End-to-end for the daemon" under Test strategy. That design's headline
# metric is a duration — "the run's gateway token is 401 within 5 s of the
# run returning" — and a duration cannot be asserted by a unit test with a
# fake clock and a fake revocation store. This script is what makes the
# metric MEASURED rather than reasoned about: real daemon, real Postgres,
# real Incus box, real model-gateway, real wall clock.
#
# What it asserts, in order (each prints OK with what it observed; the first
# miss exits non-zero):
#
#   1. during the run   — the run's gateway token, read out of the box's
#                         /etc/containarium/agent/gateway.env WHILE the run is
#                         still executing, is ACCEPTED by /v1/model/<provider>:
#                         the answer is anything except the gateway's own
#                         credential rejections.
#   2. after the run    — the same token, same call, is exactly 401
#                         "gateway token revoked", observed within
#                         CONTAINARIUM_E2E_LEASE_REVOKE_BUDGET_MS of the RPC
#                         returning.
#   3. seed files gone  — `ls /etc/containarium/agent/` in the box shows
#                         neither `token` nor `gateway.env`.
#   4. audit trail      — `containarium audit query --run-id <id>` returns both
#                         the agent.run_lease_issue and agent.run_lease_end
#                         rows.
#
# HOW ASSERTION 1 IS POSSIBLE AT ALL. RunAgentSkill is synchronous: it returns
# only after the in-box agent exec finishes, and the deferred endRunLease has
# already revoked and wiped by the time the HTTP response is written. So there
# is no window to observe "accepted" after the call. The script therefore issues
# the RPC in the BACKGROUND and reads gateway.env out of the box while the call
# is in flight — which needs the run to last long enough to be observed. That is
# what the stub agent-runtime is for: the box's /usr/local/bin/agent-runtime is
# replaced with `sleep <n>`, so the run's duration is a knob this script owns
# rather than a race it hopes to win. The design's phrase "read from gateway.env
# during the run" is exactly this.
#
# WHY A WARM-UP RUN FIRST. The stub can only be installed into a box that
# exists, and the box is created by the first run of the skill. So the script
# runs the skill once (its own run id, its own lease, fully revoked and wiped on
# exit like any other run), installs the stub into the resulting box, and then
# does the MEASURED run — which takes provisionSkillBox's idempotent reuse path,
# re-mints, re-seeds, and execs the stub. Nothing about the credential lifecycle
# differs between the two; only the run's duration does.
#
# WHY A DUMMY PROVIDER KEY IS ENOUGH. The gateway's credential checks —
# signature, provider binding, and the revocation kill-switch — all run BEFORE
# the provider key is looked up (internal/modelgateway/gateway.go: "Deliberately
# ahead of the key lookup and the Director, so a revoked token never causes the
# real provider key to be touched"). The assertions here only ever distinguish
# "the gateway rejected this credential" from "the gateway accepted it and went
# upstream", so whatever the upstream says — a provider auth error, a 502
# because the runner has no egress — is equally good evidence of acceptance. No
# real key, no real model response, no provider spend.
#
# Local use:
#   sudo -v && bash scripts/agent-skill-lease-e2e.sh
#
# Prove-it-can-fail (the #1819 acceptance criterion, and the #1418 guardrail
# this repo applies to every e2e lane):
#   CONTAINARIUM_E2E_SABOTAGE=no-revoke bash scripts/agent-skill-lease-e2e.sh
# Expected to exit NON-ZERO on assertion 2. The sabotage deletes the run_exit
# rows the daemon just wrote to jwt_revocations, which leaves the system in
# exactly the state a missing revoke call produces — the gateway's lookup finds
# no row and answers the way it did before #1817. Assertions 1, 3 and 4 stay
# green, so the red is attributable to the revoke and nothing else. The
# workflow's prove-lease-lane-can-fail job asserts the non-zero exit.
#
# Host requirements:
#   - Incus with a usable storage pool at /var/lib/incus/unix.socket. No KVM:
#     a skill box is an Incus system container, which is why this lane runs on
#     a stock GitHub-hosted runner (see scripts/ci-incus-container-host.sh).
#   - Go toolchain, passwordless sudo, curl, jq
#   - Postgres via CONTAINARIUM_POSTGRES_URL, or docker/podman so this script
#     can start a throwaway one. Postgres is NOT optional here: the revocation
#     store and the audit rows are both Postgres-backed, and they are the
#     property under test.
#   - Egress for the skill box's first provision (the agent-runtime recipe's
#     post_start installs Node). Egress to the model provider is NOT required.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Ports deliberately off cluster-e2e.sh's (15051/18080) so the two lanes can
# share a runner without fighting over a listener.
GRPC_PORT="${CONTAINARIUM_E2E_LEASE_GRPC_PORT:-15071}"
HTTP_PORT="${CONTAINARIUM_E2E_LEASE_HTTP_PORT:-18090}"

# The skill under test. hello-agent is the catalog's neutral reference skill
# (pkg/core/skills/skills.yaml) — deliberately reused rather than inventing a
# fixture, since the credential lifecycle is identical for every skill.
SKILL_ID="${CONTAINARIUM_E2E_LEASE_SKILL:-hello-agent}"

# How long the stub agent-runtime sleeps, i.e. how long the measured run lasts.
# The design says `sleep 2`; the default here is longer because assertion 1 has
# to fit inside this window on a cold runner — an exec into the box plus a
# proxied HTTP call that may sit on a connect timeout to a provider the runner
# cannot reach. 2s is a coin flip; 20s is not, and a longer run cannot make a
# revocation look faster than it is.
RUN_SECONDS="${CONTAINARIUM_E2E_LEASE_RUN_SECONDS:-20}"

# The PRD's headline metric, in milliseconds. Assertion 2 fails if the token is
# still accepted after this long past the RPC returning.
REVOKE_BUDGET_MS="${CONTAINARIUM_E2E_LEASE_REVOKE_BUDGET_MS:-5000}"

SABOTAGE="${CONTAINARIUM_E2E_SABOTAGE:-}"

# The gateway provider the daemon provisions skill boxes for. Set by the dummy
# key below; kept a variable because the /v1/model/<provider> path and the
# gateway.env variable names are both per-provider.
PROVIDER="anthropic"
GW_TOKEN_VAR="ANTHROPIC_AUTH_TOKEN"

SEED_DIR="/etc/containarium/agent"
BOX="agent-${SKILL_ID}-container"

WORKDIR="$(mktemp -d)"
BIN="$WORKDIR/containariumd"
DAEMON_LOG="$WORKDIR/daemon.log"
PG_CONTAINER=""
CONTAINER_RUNTIME=""
DAEMON_PID=""

log() { echo "==> $*"; }
ok() { echo "OK   $*"; }
fail() { echo "FATAL: $*" >&2; exit 1; }

# now_ms is the clock every duration in this script is measured on. GNU date;
# the lane runs on Linux only.
now_ms() { date +%s%3N; }

# --- pre-flight: fail loudly, never skip silently -----------------------
[ -S /var/lib/incus/unix.socket ] || fail "no Incus socket at /var/lib/incus/unix.socket"
command -v go >/dev/null || fail "no Go toolchain"
command -v curl >/dev/null || fail "no curl"
command -v jq >/dev/null || fail "no jq (the RPC response is JSON and this script asserts on its fields)"
sudo -n true 2>/dev/null || fail "needs passwordless sudo (daemon and Incus operations run as root)"
case "$SABOTAGE" in
  ''|no-revoke) ;;
  *) fail "unknown CONTAINARIUM_E2E_SABOTAGE=$SABOTAGE (want empty or 'no-revoke')" ;;
esac

cleanup() {
  status=$?
  set +e
  if [ -n "$DAEMON_PID" ]; then
    log "stopping daemon (pid $DAEMON_PID)"
    sudo kill "$DAEMON_PID" 2>/dev/null
    sleep 2
    sudo kill -9 "$DAEMON_PID" 2>/dev/null
  fi
  # The skill box is named deterministically from the skill id, so a red run
  # would otherwise hand its box to the next run — which then takes the REUSE
  # path with a stale stub and never exercises a first provision.
  if sudo incus info "$BOX" >/dev/null 2>&1; then
    log "sweeping skill box $BOX"
    sudo incus delete --force "$BOX" 2>/dev/null
  fi
  if [ -n "$PG_CONTAINER" ]; then
    log "stopping throwaway postgres"
    "$CONTAINER_RUNTIME" rm -f "$PG_CONTAINER" >/dev/null 2>&1
  fi
  if [ $status -ne 0 ] && [ -f "$DAEMON_LOG" ]; then
    # The lease lines first, over the WHOLE log: whether the gateway was
    # enabled at all, and whether a credential went unrevoked, are both
    # decided in one line the daemon prints once. A tail alone cannot answer
    # "was there a revocation store?", which is the first question every red
    # run in this lane raises.
    echo "---- daemon log: gateway / run-lease lines (whole run) ----"
    grep -E 'model-gateway|agent-skill|Model-gateway|revocation' "$DAEMON_LOG" || echo "(none)"
    echo "---- daemon log (last 120 lines) ----"
    tail -120 "$DAEMON_LOG"
  fi
  # The daemon runs under sudo and leaves root-owned trees here.
  sudo rm -rf "$WORKDIR" 2>/dev/null || rm -rf "$WORKDIR"
  exit $status
}
trap cleanup EXIT

# --- postgres: real, and not optional in this lane ----------------------
# Same shape as scripts/cluster-e2e.sh, including the TCP (-h 127.0.0.1)
# readiness probe: the postgres entrypoint runs a temporary Unix-socket-only
# server during init and then shuts it down, so a default probe answers
# "ready" about the wrong server (#1514).
if [ -z "${CONTAINARIUM_POSTGRES_URL:-}" ]; then
  # Pick a runtime that ANSWERS, not merely one that is on PATH. A host can
  # carry a docker shim whose real binary is gone (a nested-container wrapper
  # left behind, say), and `command -v` cannot tell the difference — the lane
  # would then fail minutes later on `docker run` with a shell error that
  # reads like a bug in this script.
  for rt in docker podman; do
    rt_path="$(command -v "$rt" || true)"
    [ -n "$rt_path" ] || continue
    if "$rt_path" info >/dev/null 2>&1; then
      CONTAINER_RUNTIME="$rt_path"
      break
    fi
    log "$rt is on PATH but not usable; trying the next runtime"
  done
  [ -n "$CONTAINER_RUNTIME" ] || fail "set CONTAINARIUM_POSTGRES_URL or install a working docker/podman for a throwaway postgres"
  PG_PORT="$(( (RANDOM % 1000) + 16432 ))"
  PG_CONTAINER="lease-e2e-pg-$$"
  log "starting throwaway postgres on :$PG_PORT"
  "$CONTAINER_RUNTIME" run -d --name "$PG_CONTAINER" \
    -e POSTGRES_USER=containarium -e POSTGRES_PASSWORD=e2e -e POSTGRES_DB=containarium \
    -p "127.0.0.1:${PG_PORT}:5432" postgres:16-alpine >/dev/null
  export CONTAINARIUM_POSTGRES_URL="postgres://containarium:e2e@127.0.0.1:${PG_PORT}/containarium?sslmode=disable"
  for _ in $(seq 1 90); do
    "$CONTAINER_RUNTIME" exec "$PG_CONTAINER" pg_isready -h 127.0.0.1 -U containarium >/dev/null 2>&1 && break
    sleep 1
  done
  if ! "$CONTAINER_RUNTIME" exec "$PG_CONTAINER" pg_isready -h 127.0.0.1 -U containarium >/dev/null 2>&1; then
    echo "---- postgres container state ----"
    "$CONTAINER_RUNTIME" ps -a --filter "name=$PG_CONTAINER" 2>&1 || true
    echo "---- postgres container log ----"
    "$CONTAINER_RUNTIME" logs "$PG_CONTAINER" 2>&1 | tail -40 || true
    fail "postgres did not become ready"
  fi
elif [ "$SABOTAGE" = no-revoke ]; then
  fail "CONTAINARIUM_E2E_SABOTAGE=no-revoke needs the throwaway postgres this script starts (it deletes revocation rows through it); unset CONTAINARIUM_POSTGRES_URL"
fi

# psql_in_pg runs SQL against the throwaway postgres. Only the sabotage path
# uses it — the assertions themselves go through the product's own surfaces
# (the gateway, `incus exec`, `containarium audit query`), never SQL.
psql_in_pg() {
  "$CONTAINER_RUNTIME" exec "$PG_CONTAINER" \
    psql -q -At -U containarium -d containarium -c "$1"
}

# --- build the system under test ----------------------------------------
# cmd/containariumd is the full daemon AND the operator CLI (`audit query`
# lives there too, untagged) — one binary serves both halves of this lane.
log "building containariumd"
go build -o "$BIN" ./cmd/containariumd

# --- daemon ---------------------------------------------------------------
JWT_SECRET="${CONTAINARIUM_JWT_SECRET:-$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')}"

# A PLACEHOLDER provider key, not a secret: its only job is to make
# gatewayProviderKeysFromEnv() non-empty so the daemon serves the model gateway
# and provisions skill boxes through it. Nothing here ever reaches a provider
# successfully, by construction — see the header.
GATEWAY_KEY="not-a-real-key-e2e-placeholder"

log "starting daemon (grpc :$GRPC_PORT http :$HTTP_PORT, model gateway provider $PROVIDER)"
# SC2024 (sudo doesn't affect redirects) is the intent, not a bug: the log file
# is created by THIS shell inside our own mktemp workdir, so the diagnostics in
# cleanup() can read it without sudo. Same shape as scripts/cluster-e2e.sh.
# shellcheck disable=SC2024
sudo env \
  CONTAINARIUM_JWT_SECRET="$JWT_SECRET" \
  CONTAINARIUM_POSTGRES_URL="$CONTAINARIUM_POSTGRES_URL" \
  ANTHROPIC_API_KEY="$GATEWAY_KEY" \
  "$BIN" daemon --port "$GRPC_PORT" --http-port "$HTTP_PORT" \
  >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!

DAEMON_WAIT_TRIES="${CONTAINARIUM_E2E_LEASE_DAEMON_WAIT_TRIES:-180}"
log "waiting for the daemon's HTTP gateway (up to $((DAEMON_WAIT_TRIES * 2))s)"
for i in $(seq 1 "$DAEMON_WAIT_TRIES"); do
  if ! sudo kill -0 "$DAEMON_PID" 2>/dev/null; then
    fail "daemon exited during startup"
  fi
  if curl -s -o /dev/null "http://127.0.0.1:$HTTP_PORT/v1/agent-skills"; then
    break
  fi
  [ "$i" = "$DAEMON_WAIT_TRIES" ] && fail "daemon HTTP gateway not answering after $((DAEMON_WAIT_TRIES * 2))s"
  sleep 2
done

# The model gateway is only mounted when the daemon holds a provider key. If it
# is absent, gateway.env is never seeded, every later assertion is about a
# credential that was never issued, and the lane would go GREEN having tested
# nothing. Check it before anything else.
gw_health="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$HTTP_PORT/__gateway/healthz")"
[ "$gw_health" = "200" ] || fail "model gateway is not mounted (/__gateway/healthz -> $gw_health); the provider key was not picked up, so there would be no gateway token to revoke"
ok "model gateway mounted (/__gateway/healthz -> 200)"

# The revocation store is the other half of the property. A daemon without
# Postgres says so in one startup line and then wipes seed files without
# revoking anything — which would make assertion 2 impossible for a reason
# that has nothing to do with the code under test.
if grep -q 'model-gateway has no revocation store' "$DAEMON_LOG"; then
  fail "daemon came up with no revocation store — Postgres is not reachable, so no credential can be killed before its expiry"
fi
ok "daemon has a revocation store (Postgres reachable)"

# --- caller credentials ---------------------------------------------------
# admin role: provisionSkillBox calls AuthorizeTenant on the box's tenant name
# ("agent-<skill>"), which only the tenant itself or an admin passes. Wildcard
# scopes: the skill's in-box token is the intersection of the caller's scopes
# and the manifest's, and this caller must not be the thing that narrows it.
TOKEN="$("$BIN" token generate --username lease-e2e --roles admin --scopes '*' \
  --expiry 1h --secret "$JWT_SECRET" --raw)"
[ -n "$TOKEN" ] || fail "could not mint a caller token"

# run_skill POSTs RunAgentSkill with an explicit run id and writes the HTTP
# status to <out>.code and the body to <out>.body. Synchronous by nature — the
# caller decides whether to background it.
run_skill() {
  local run_id="$1" out="$2"
  curl -sS -o "$out.body" -w '%{http_code}' \
    -X POST "http://127.0.0.1:$HTTP_PORT/v1/agent-skills/$SKILL_ID/run" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d "{\"run_id\":\"$run_id\",\"input_json\":\"{}\"}" \
    >"$out.code" 2>"$out.err" || true
}

# model_call presents a gateway token to /v1/model/<provider> and writes the
# status to <out>.code, the body to <out>.body. The request is a real
# provider-shaped call so nothing short-circuits before the revocation check.
model_call() {
  local token="$1" out="$2"
  curl -sS -o "$out.body" -w '%{http_code}' --max-time 15 \
    -X POST "http://127.0.0.1:$HTTP_PORT/v1/model/$PROVIDER/v1/messages" \
    -H "Authorization: Bearer $token" \
    -H 'Content-Type: application/json' \
    -d '{"model":"claude-3-5-haiku-latest","max_tokens":1,"messages":[{"role":"user","content":"ping"}]}' \
    >"$out.code" 2>"$out.err" || true
}

# --- warm-up run: create the box, then install the stub agent-runtime -----
# The warm-up is a real run with a real lease: it provisions, mints, seeds,
# execs (there is no agent-runtime in the box yet, so the exec fails fast and
# best-effort as designed), revokes and wipes. Its only purpose here is to
# bring the box into existence so the stub can be installed into it.
log "warm-up run (provisions the box; the agent-runtime recipe installs Node, this is the slow part)"
WARM_RUN_ID="lease-e2e-warmup-$$"
run_skill "$WARM_RUN_ID" "$WORKDIR/warm"
warm_code="$(cat "$WORKDIR/warm.code")"
if [ "$warm_code" != "200" ]; then
  echo "---- warm-up response ----"; cat "$WORKDIR/warm.body"; echo
  fail "warm-up RunAgentSkill returned $warm_code (want 200); the box never came up, so there is nothing to measure"
fi
sudo incus info "$BOX" >/dev/null 2>&1 || fail "skill box $BOX does not exist after a successful run"
ok "skill box $BOX provisioned (warm-up run $WARM_RUN_ID)"

# The stub. /usr/local/bin comes first on the box's PATH, so this is the
# agent-runtime the daemon's `bash -lc ... agent-runtime` resolves — whether or
# not the recipe's best-effort assembly installed a real one.
log "installing the stub agent-runtime (sleep ${RUN_SECONDS}s) into $BOX"
sudo incus exec "$BOX" -- bash -c \
  "printf '#!/bin/sh\nexec sleep %s\n' '$RUN_SECONDS' > /usr/local/bin/agent-runtime && chmod 0755 /usr/local/bin/agent-runtime"
sudo incus exec "$BOX" -- test -x /usr/local/bin/agent-runtime \
  || fail "stub agent-runtime was not installed into $BOX"
ok "stub agent-runtime installed (the measured run will last ~${RUN_SECONDS}s)"

# The warm-up's own lease must already be gone; if the seed files are still
# there, the measured run's "these files appeared" poll below would latch onto
# a stale credential and assertion 1 would be about the wrong token.
sudo incus exec "$BOX" -- rm -f "$SEED_DIR/token" "$SEED_DIR/gateway.env"

# --- the measured run -----------------------------------------------------
RUN_ID="lease-e2e-$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
log "measured run $RUN_ID (RPC in the background so the run can be observed while it lasts)"
run_skill "$RUN_ID" "$WORKDIR/run" &
RUN_PID=$!

# Read the run's gateway token out of the box while the run is in flight. The
# file is written by provisionSkillBox before the agent exec starts and removed
# by endRunLease after it returns, so its PRESENCE is the run's own liveness
# signal — no sleep-and-hope.
log "reading $SEED_DIR/gateway.env from the box during the run"
GW_TOKEN=""
gw_env=""
for _ in $(seq 1 300); do
  gw_env="$(sudo incus exec "$BOX" -- cat "$SEED_DIR/gateway.env" 2>/dev/null || true)"
  if [ -n "$gw_env" ]; then
    GW_TOKEN="$(printf '%s\n' "$gw_env" | sed -n "s/^export $GW_TOKEN_VAR=//p" | head -1)"
    [ -n "$GW_TOKEN" ] && break
  fi
  if ! kill -0 "$RUN_PID" 2>/dev/null; then
    fail "the run finished before gateway.env could be read; raise CONTAINARIUM_E2E_LEASE_RUN_SECONDS (currently ${RUN_SECONDS}s)"
  fi
  sleep 0.2
done
[ -n "$GW_TOKEN" ] || fail "never saw $GW_TOKEN_VAR in $SEED_DIR/gateway.env during the run"
ok "read the run's gateway token from $SEED_DIR/gateway.env during the run (${#GW_TOKEN} bytes)"

# --- assertion 1: accepted during the run --------------------------------
model_call "$GW_TOKEN" "$WORKDIR/during"
during_code="$(cat "$WORKDIR/during.code")"
during_body="$(cat "$WORKDIR/during.body")"
case "$during_body" in
  *"gateway token revoked"*)
    fail "assertion 1: the gateway rejected the run's own token DURING the run as revoked — the lease was ended too early" ;;
  *"invalid gateway token"*|*"missing gateway token"*|*"token not valid for provider"*|*"unknown provider"*|*"missing provider in path"*)
    fail "assertion 1: the gateway refused the credential for a reason unrelated to revocation ($during_code: $during_body) — the later 401 would prove nothing" ;;
esac
ok "assertion 1: token ACCEPTED during the run — /v1/model/$PROVIDER answered $during_code, not a gateway credential rejection"
echo "     (upstream said: $(printf '%s' "$during_body" | head -c 160 | tr '\n' ' '))"

# --- wait for the run to return ------------------------------------------
wait "$RUN_PID" || true
EXIT_MS="$(now_ms)"
run_code="$(cat "$WORKDIR/run.code")"
if [ "$run_code" != "200" ]; then
  echo "---- run response ----"; cat "$WORKDIR/run.body"; echo
  fail "measured RunAgentSkill returned $run_code (want 200)"
fi
echoed_run_id="$(jq -r '.runId // empty' <"$WORKDIR/run.body")"
[ "$echoed_run_id" = "$RUN_ID" ] \
  || fail "RunAgentSkillResponse.run_id was '$echoed_run_id', want '$RUN_ID' — the run this script measures is not the run the daemon leased"
ok "run $RUN_ID returned 200 and echoed its run id"

if [ "$SABOTAGE" = no-revoke ]; then
  # Put the system in the state a missing revoke call produces: the rows the
  # run just wrote are removed, so the gateway's lookup finds nothing. Exactly
  # what #1817 added, undone at the only place it is observable.
  deleted="$(psql_in_pg "DELETE FROM jwt_revocations WHERE reason = 'run_exit' RETURNING jti;" | wc -l)"
  echo "SABOTAGE: deleted $deleted run_exit revocation row(s) — assertion 2 must now go RED"
fi

# --- assertion 2: dead within the budget ---------------------------------
log "polling /v1/model/$PROVIDER with the run's token until it is refused as revoked (budget ${REVOKE_BUDGET_MS}ms from run exit)"
revoked_at_ms=""
last_code=""
last_body=""
while :; do
  model_call "$GW_TOKEN" "$WORKDIR/after"
  last_code="$(cat "$WORKDIR/after.code")"
  last_body="$(cat "$WORKDIR/after.body")"
  case "$last_body" in
    *"gateway token revoked"*)
      revoked_at_ms="$(now_ms)"
      break ;;
  esac
  if [ "$(( $(now_ms) - EXIT_MS ))" -ge "$REVOKE_BUDGET_MS" ]; then
    break
  fi
  sleep 0.2
done

if [ -z "$revoked_at_ms" ]; then
  fail "assertion 2: ${REVOKE_BUDGET_MS}ms after the run returned, the run's gateway token is STILL accepted (last answer $last_code: $(printf '%s' "$last_body" | head -c 160 | tr '\n' ' ')) — the credential outlived its run"
fi
[ "$last_code" = "401" ] \
  || fail "assertion 2: the body says 'gateway token revoked' but the status was $last_code, want 401"
ok "assertion 2: token DEAD $(( revoked_at_ms - EXIT_MS ))ms after the run returned — 401 'gateway token revoked' (budget ${REVOKE_BUDGET_MS}ms)"

# --- assertion 3: the seed files are gone --------------------------------
seed_ls="$(sudo incus exec "$BOX" -- ls -A "$SEED_DIR" 2>/dev/null || true)"
for leftover in token gateway.env; do
  if printf '%s\n' "$seed_ls" | grep -qx "$leftover"; then
    fail "assertion 3: $SEED_DIR/$leftover survived the run — the box is reused, so a readable credential file is a live credential
$SEED_DIR now holds: $(printf '%s' "$seed_ls" | tr '\n' ' ')"
  fi
done
ok "assertion 3: neither token nor gateway.env is left in $SEED_DIR (it holds: $(printf '%s' "$seed_ls" | tr '\n' ' '))"

# --- assertion 4: both lease rows are queryable by run id ----------------
# Through the operator's own CLI, not SQL: `audit query --run-id` is the
# interface an operator answering "what was this run given, and was it taken
# back" actually has (#1825).
audit_out="$(sudo env CONTAINARIUM_POSTGRES_URL="$CONTAINARIUM_POSTGRES_URL" \
  "$BIN" audit query --run-id "$RUN_ID" --raw 2>&1)" || {
  echo "$audit_out"
  fail "assertion 4: containarium audit query --run-id $RUN_ID failed"
}
for action in agent.run_lease_issue agent.run_lease_end; do
  printf '%s\n' "$audit_out" | grep -q "$action" \
    || fail "assertion 4: no $action row for run $RUN_ID
audit query --run-id $RUN_ID --raw returned:
$audit_out"
done
ok "assertion 4: audit query --run-id $RUN_ID returns both agent.run_lease_issue and agent.run_lease_end"
printf '%s\n' "$audit_out" | sed 's/^/     /'

echo
echo "PASS: a skill run's credentials died with the run."
echo "      gateway token accepted during run $RUN_ID, 401 'gateway token revoked'"
echo "      $(( revoked_at_ms - EXIT_MS ))ms after it returned (budget ${REVOKE_BUDGET_MS}ms), seed files wiped,"
echo "      both lease rows queryable by run id."
