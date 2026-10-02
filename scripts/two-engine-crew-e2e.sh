#!/usr/bin/env bash
#
# two-engine-crew-e2e.sh — the executable proof of the agent-router PRD's
# Story 4 and north-star metric (share of runs whose recorded engine matches
# the manifest: 100%): several agent engines running on ONE daemon at once,
# each skill routed to the engine its own manifest names (#2222/#2223).
#
# WHAT THIS SCRIPT IS, AND ISN'T. It runs the two-engine-crew fixture
# (pkg/core/crews/crews.yaml): hello-agent-claude (engine: claude) then
# hello-agent-codex (engine: codex), pipeline topology, against ONE daemon
# holding BOTH ANTHROPIC_API_KEY and OPENAI_API_KEY but deliberately NOT
# GEMINI_API_KEY — so the same run also proves the NOT_READY half of the
# readiness report (#2223) against a provider this daemon genuinely lacks.
#
# --- WHAT IT ASSERTS, in order (each prints OK with what it observed) ----
#
#   1. engine readiness report  — BEFORE any spend: `containarium agent
#                                  engines --json` on this daemon reports
#                                  claude READY, codex READY, gemini
#                                  NOT_READY, and the assertion is on the
#                                  `reason` string (#2225 AC2), not just the
#                                  readiness enum.
#   2. member gateway tokens    — each member box's own gateway.env token
#                                  (minted when RunCrew provisions it, before
#                                  driveCrew runs a single hop) decodes to a
#                                  DIFFERENT `provider` claim: hello-agent-
#                                  claude's -> anthropic, hello-agent-codex's
#                                  -> openai. This is the per-member proof
#                                  that #2225 AC1 asks for.
#   3. run COMPLETED             — RunCrew returns 200 with
#                                  CREW_RUN_STATE_COMPLETED.
#
# --- WHY NOT "EACH MEMBER'S ARTIFACT.JSON RECORDS ITS OWN ENGINE" (#2225's
# literal AC1 wording) -----------------------------------------------------
# artifact.json (agent-runtime/src/artifact.ts, written by run.ts's ONE-SHOT
# `runOnce()`) is real, and DOES carry an `engine` field — but a crew hop
# never goes through that path. RunCrew's provisionMemberBox starts each
# member in SERVE mode (CONTAINARIUM_AGENT_MODE=serve), whose A2A handler
# (agent-runtime/src/a2a.ts runTask) returns the artifact straight over HTTP
# and never calls writeArtifact. Nor does the daemon's own runlease registry
# help: internal/runlease/registry.go keys Info by run_id ALONE, and both
# crew members share one run_id, so the second member's Register() call
# overwrites the first's — there is no way to read back member 1's recorded
# engine once member 2 has registered.
#
# Decision (interactive, 2026-10-02, on #2225): assert per-member engine via
# the gateway token's `provider` claim instead (assertion 2 above, already
# named in the issue's AC1 as the second check) plus the readiness report
# (assertion 1). No product code changed to make the literal artifact.json
# wording true — that would be new engine-serve-mode or registry behavior,
# out of scope for a test script. If a future issue wants per-member engine
# observable from artifact.json on the crew path too, it is product work for
# agent-runtime / internal/runlease, not this script.
#
# --- CREDENTIAL CONTRACT ---------------------------------------------------
# Reads the SAME provider-key env vars the daemon itself reads
# (internal/server/agent_gateway.go gatewayProviderKeysFromEnv):
#
#     ANTHROPIC_API_KEY   (engine: claude)
#     OPENAI_API_KEY      (engine: codex)
#
# BOTH must be set and look like real keys, or this script SKIPS, exit 0,
# naming whichever is missing. Per the sprint's Q5 decision on #2225/#2230:
# the live CI job and the dev environment are NOT assumed to hold both —
# this is a skip, never a silent pass on one key. GEMINI_API_KEY must stay
# UNSET for this run: assertion 1 needs a provider this daemon genuinely has
# no key for, to prove the NOT_READY half of the report. If it is set in
# your shell, unset it before running this script.
#
# A skip is NOT a pass. It prints SKIP, never "PASS".
#
# --- COST ------------------------------------------------------------------
# ONE crew run, two tiny hello-agent turns (not engineer-crew's real
# issue-sized task): CONTAINARIUM_AGENT_MAX_TURNS caps each member's loop,
# and the claude member's model is pinned to a cheap one
# (claude-3-5-haiku-latest) via the same /etc/profile.d seam
# scripts/engineer-crew-e2e.sh uses; the codex member's model is left unset
# (its own CLI default decides — codex has no hard-coded default in
# agent-runtime, see agent-runtime/src/index.ts).
#
# --- Local use --------------------------------------------------------------
#   # skip path (no spend), proves the gate:
#   bash scripts/two-engine-crew-e2e.sh
#
#   # real path (needs sudo for Incus and both provider keys):
#   sudo -v && unset GEMINI_API_KEY && \
#     ANTHROPIC_API_KEY=sk-... OPENAI_API_KEY=sk-... bash scripts/two-engine-crew-e2e.sh
#
# --- Prove-it-can-fail (the #1418 guardrail every e2e lane in this repo
# applies; a green lane that has never failed proves nothing) -------------
#   CONTAINARIUM_E2E_SABOTAGE=swap-expected-providers
# Swaps which provider the harness EXPECTS from which member right before
# assertion 2 compares them, so the real tokens (correct, unchanged) now
# read as wrong — assertion 2 must go RED. Proves AC1's per-member check
# discriminates: it corrupts the HARNESS's own expectation, exactly the
# shape an implementer's real mistake (wiring a member to the wrong engine)
# would produce, rather than trying to make a model misbehave on demand.
# Costs one real run, so this is workflow_dispatch-only (see the workflow).
#
# --- Host requirements (the real path only; the skip path needs none) ----
#   - Incus with a usable storage pool at /var/lib/incus/unix.socket.
#   - Go toolchain, passwordless sudo, curl, jq, git.
#   - Postgres via CONTAINARIUM_POSTGRES_URL, or docker/podman so this script
#     can start a throwaway one.
#   - Egress to github.com (the agent-runtime release artifacts the box's
#     post_start pulls) AND to both model providers.
set -euo pipefail

# ========================================================================
# THE SKIP GATE. First, before everything — see "credential contract".
# ========================================================================
missing=""
[ -n "${ANTHROPIC_API_KEY:-}" ] || missing="$missing ANTHROPIC_API_KEY"
[ -n "${OPENAI_API_KEY:-}" ] || missing="$missing OPENAI_API_KEY"

if [ -n "$missing" ]; then
  cat <<SKIPEOF
SKIP: two-engine-crew e2e needs REAL claude AND codex credentials; missing:$missing

This lane proves #2225 (agent-router PRD Story 4): several engines on one
daemon at once. Half the point is BOTH providers configured simultaneously,
so it declines to run on just one — that would only re-prove what
scripts/engineer-crew-e2e.sh already proves for a single engine.

To run it, set BOTH of these (the same vars the daemon's own model gateway
reads, internal/server/agent_gateway.go gatewayProviderKeysFromEnv):

    ANTHROPIC_API_KEY   -> engine claude
    OPENAI_API_KEY      -> engine codex

In CI: this needs an OPENAI_API_KEY secret that, as of this script landing,
does NOT exist on this repository (only ANTHROPIC_API_KEY / GEMINI_API_KEY
do, for scripts/engineer-crew-e2e.sh) — a human with repository admin has to
add it. Until then the real half of this lane has never run; the scaffolding
is green (see two-engine-crew-skip-gate on every PR).

This is a SKIP, not a PASS. Nothing about engine routing was proved here.
SKIPEOF
  exit 0
fi

for cand in "ANTHROPIC_API_KEY:$ANTHROPIC_API_KEY" "OPENAI_API_KEY:$OPENAI_API_KEY"; do
  cand_env="${cand%%:*}"
  cand_val="${cand#*:}"
  case "$cand_val" in
    not-a-real-key-e2e-placeholder|*e2e-placeholder*|*not-a-real*)
      echo "FATAL: $cand_env looks like a placeholder, not a real provider key." >&2
      echo "       This lane needs keys the providers will actually accept." >&2
      exit 1 ;;
  esac
done

if [ -n "${GEMINI_API_KEY:-}" ]; then
  echo "FATAL: GEMINI_API_KEY is set, but assertion 1 needs gemini to be a provider this daemon has NO key for." >&2
  echo "       Unset it before running this script." >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# ========================================================================
# Configuration
# ========================================================================

# Ports off every other e2e lane's (cluster-e2e 15051/18080, agent-skill-
# lease 15071/18090, engineer-crew 15081/18100) so all four can share a
# runner without fighting over a listener.
GRPC_PORT="${CONTAINARIUM_E2E_TWOENGINE_GRPC_PORT:-15091}"
HTTP_PORT="${CONTAINARIUM_E2E_TWOENGINE_HTTP_PORT:-18110}"

CREW_ID="${CONTAINARIUM_E2E_TWOENGINE_CREW_ID:-two-engine-crew}"
# Members in pipeline order (pkg/core/crews/crews.yaml), engine each one
# NAMES on its manifest (pkg/core/skills/skills.yaml) and the provider that
# engine resolves to (internal/agentengine.Provider). Kept here, not read
# from the catalog, so a manifest that silently drops its `engine:` field
# fails this lane loudly instead of quietly checking fewer engines than #2225
# asks for.
declare -A MEMBER_ENGINE=( [hello-agent-claude]=claude [hello-agent-codex]=codex )
declare -A MEMBER_PROVIDER=( [hello-agent-claude]=anthropic [hello-agent-codex]=openai )
CREW_MEMBERS="hello-agent-claude hello-agent-codex"

# The release whose published agent-runtime bundle the member boxes install —
# same reasoning as scripts/engineer-crew-e2e.sh: a locally built daemon has a
# dev version whose artifacts were never published, so this must be a real
# published tag.
RELEASE="${CONTAINARIUM_E2E_TWOENGINE_RELEASE:-$(git tag --list 'v*' --sort=-v:refname | head -1)}"

# Cost ceilings. hello-agent's task is tiny ("do the smallest useful thing"),
# so a low turn cap is correct here, not just cheap.
AGENT_MAX_TURNS="${CONTAINARIUM_E2E_TWOENGINE_MAX_TURNS:-6}"
# claude's engine default (claude-opus-4-8, agent-runtime/src/index.ts) is a
# frontier model this lane does not need; codex's default is already empty
# (its own CLI default decides) so it is left alone.
CLAUDE_MODEL="${CONTAINARIUM_E2E_TWOENGINE_CLAUDE_MODEL:-claude-3-5-haiku-latest}"

RUN_TIMEOUT_S="${CONTAINARIUM_E2E_TWOENGINE_RUN_TIMEOUT:-600}"

SABOTAGE="${CONTAINARIUM_E2E_SABOTAGE:-}"

# Matches the daemon's agentSeedRoot (internal/server/agent_server.go).
AGENT_SEED_ROOT="/etc/containarium/agent/runs"

WORKDIR="$(mktemp -d)"
BIN="$WORKDIR/containariumd"
DAEMON_LOG="$WORKDIR/daemon.log"
PG_CONTAINER=""
CONTAINER_RUNTIME=""
DAEMON_PID=""

log() { echo "==> $*"; }
ok() { echo "OK   $*"; }
fail() { echo "FATAL: $*" >&2; exit 1; }

# ========================================================================
# Pre-flight: fail loudly, never skip silently. (The ONE legitimate skip is
# the credential gate above, and it already happened.)
# ========================================================================
[ -S /var/lib/incus/unix.socket ] || fail "no Incus socket at /var/lib/incus/unix.socket"
command -v go >/dev/null || fail "no Go toolchain"
command -v curl >/dev/null || fail "no curl"
command -v jq >/dev/null || fail "no jq (the RPC response and gateway tokens are JSON and this script asserts on their fields)"
sudo -n true 2>/dev/null || fail "needs passwordless sudo (daemon and Incus operations run as root)"
[ -n "$RELEASE" ] || fail "no release tag: set CONTAINARIUM_E2E_TWOENGINE_RELEASE to a PUBLISHED v-tag whose agent-runtime bundle exists, or fetch tags so 'git tag --list v*' is non-empty"
case "$RELEASE" in v*) ;; *) fail "CONTAINARIUM_E2E_TWOENGINE_RELEASE='$RELEASE' must be v-prefixed (install-agent-runtime.sh builds the artifact URL from it)" ;; esac
case "$SABOTAGE" in
  ''|swap-expected-providers) ;;
  *) fail "unknown CONTAINARIUM_E2E_SABOTAGE=$SABOTAGE (want empty or 'swap-expected-providers')" ;;
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
  for m in $CREW_MEMBERS; do
    if sudo incus info "agent-$m-container" >/dev/null 2>&1; then
      log "sweeping member box agent-$m-container"
      sudo incus delete --force "agent-$m-container" 2>/dev/null
    fi
  done
  if [ -n "$PG_CONTAINER" ]; then
    log "stopping throwaway postgres"
    "$CONTAINER_RUNTIME" rm -f "$PG_CONTAINER" >/dev/null 2>&1
  fi
  if [ $status -ne 0 ] && [ -f "$DAEMON_LOG" ]; then
    echo "---- daemon log: gateway / crew / agent-skill lines (whole run) ----"
    grep -E 'model-gateway|Model-gateway|\[crew\]|\[agent-skill\]|quota' "$DAEMON_LOG" || echo "(none)"
    echo "---- daemon log (last 120 lines) ----"
    tail -120 "$DAEMON_LOG"
    for m in $CREW_MEMBERS; do
      echo "---- agent-runtime.log in agent-$m-container (last 60 lines) ----"
      sudo incus exec "agent-$m-container" -- tail -60 /var/log/agent-runtime.log 2>/dev/null || echo "(unavailable)"
    done
  fi
  sudo rm -rf "$WORKDIR" 2>/dev/null || rm -rf "$WORKDIR"
  exit $status
}
trap cleanup EXIT

# Published-bundle check, polled for the same release-race reason
# scripts/engineer-crew-e2e.sh documents: on a tag push, release.yml may
# still be publishing it.
BUNDLE_URL="https://github.com/FootprintAI/Containarium/releases/download/$RELEASE/agent-runtime-bundle.tar.gz"
BUNDLE_WAIT_S="${CONTAINARIUM_E2E_TWOENGINE_BUNDLE_WAIT:-1200}"
log "waiting for the agent-runtime bundle for $RELEASE to be published (up to ${BUNDLE_WAIT_S}s)"
bundle_code=""
bundle_deadline=$(( $(date +%s) + BUNDLE_WAIT_S ))
while :; do
  bundle_code="$(curl -sSL -o /dev/null -w '%{http_code}' --max-time 60 -I "$BUNDLE_URL" || true)"
  [ "$bundle_code" = "200" ] && break
  [ "$(date +%s)" -ge "$bundle_deadline" ] && break
  sleep 15
done
[ "$bundle_code" = "200" ] \
  || fail "agent-runtime bundle for $RELEASE is still not downloadable after ${BUNDLE_WAIT_S}s ($BUNDLE_URL -> $bundle_code)."
ok "agent-runtime bundle for $RELEASE is published"

# ========================================================================
# Postgres: real. The crew-run store is Postgres-backed.
# ========================================================================
if [ -z "${CONTAINARIUM_POSTGRES_URL:-}" ]; then
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
  PG_PORT="$(( (RANDOM % 1000) + 17532 ))"
  PG_CONTAINER="two-engine-e2e-pg-$$"
  log "starting throwaway postgres on :$PG_PORT"
  "$CONTAINER_RUNTIME" run -d --name "$PG_CONTAINER" \
    -e POSTGRES_USER=containarium -e POSTGRES_PASSWORD=e2e -e POSTGRES_DB=containarium \
    -p "127.0.0.1:${PG_PORT}:5432" postgres:16-alpine >/dev/null
  export CONTAINARIUM_POSTGRES_URL="postgres://containarium:e2e@127.0.0.1:${PG_PORT}/containarium?sslmode=disable"
  for _ in $(seq 1 90); do
    "$CONTAINER_RUNTIME" exec "$PG_CONTAINER" pg_isready -h 127.0.0.1 -U containarium >/dev/null 2>&1 && break
    sleep 1
  done
  "$CONTAINER_RUNTIME" exec "$PG_CONTAINER" pg_isready -h 127.0.0.1 -U containarium >/dev/null 2>&1 \
    || fail "postgres did not become ready"
fi

# ========================================================================
# Build the system under test, stamped with the published release tag.
# `containariumd` doubles as the CLI in this script (token generate, agent
# engines) — internal/cmd is shared by both binaries (cmd/containariumd and
# the containarium_client-tagged cmd/containarium), so a second build buys
# nothing here.
# ========================================================================
log "building containariumd stamped as $RELEASE"
go build -ldflags "-X github.com/footprintai/containarium/pkg/version.Version=$RELEASE" \
  -o "$BIN" ./cmd/containariumd

JWT_SECRET="${CONTAINARIUM_JWT_SECRET:-$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')}"

log "starting daemon (grpc :$GRPC_PORT http :$HTTP_PORT, providers anthropic+openai, deliberately no gemini key)"
# shellcheck disable=SC2024
sudo env \
  CONTAINARIUM_JWT_SECRET="$JWT_SECRET" \
  CONTAINARIUM_POSTGRES_URL="$CONTAINARIUM_POSTGRES_URL" \
  ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
  OPENAI_API_KEY="$OPENAI_API_KEY" \
  "$BIN" daemon --port "$GRPC_PORT" --http-port "$HTTP_PORT" \
  >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!

DAEMON_WAIT_TRIES="${CONTAINARIUM_E2E_TWOENGINE_DAEMON_WAIT_TRIES:-300}"
log "waiting for the daemon's HTTP gateway (up to $((DAEMON_WAIT_TRIES * 2))s)"
for i in $(seq 1 "$DAEMON_WAIT_TRIES"); do
  sudo kill -0 "$DAEMON_PID" 2>/dev/null || fail "daemon exited during startup"
  if curl -s -o /dev/null "http://127.0.0.1:$HTTP_PORT/v1/crews"; then
    break
  fi
  [ "$i" = "$DAEMON_WAIT_TRIES" ] && fail "daemon HTTP gateway not answering after $((DAEMON_WAIT_TRIES * 2))s"
  sleep 2
done

gw_health="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$HTTP_PORT/__gateway/healthz")"
[ "$gw_health" = "200" ] \
  || fail "model gateway is not mounted (/__gateway/healthz -> $gw_health); neither provider key was picked up"
ok "model gateway mounted for anthropic + openai (/__gateway/healthz -> 200)"

TOKEN="$("$BIN" token generate --username two-engine-e2e --roles admin --scopes '*' \
  --expiry 2h --secret "$JWT_SECRET" --raw)"
[ -n "$TOKEN" ] || fail "could not mint a caller token"

CLI() { "$BIN" --server "http://127.0.0.1:$HTTP_PORT" --http --token "$TOKEN" "$@"; }

read_out() { cat "$1" 2>/dev/null || true; }
read_code() {
  local c
  c="$(read_out "$1")"
  [ -n "$c" ] || c="000"
  printf '%s' "$c"
}

# ========================================================================
# assertion 1: the engine readiness report, BEFORE any spend (#2225 AC2).
# ========================================================================
log "checking 'containarium agent engines --json' before running anything"
engines_json="$(CLI agent engines --json)"
printf '%s\n' "$engines_json" | jq -e . >/dev/null 2>&1 \
  || fail "assertion 1: 'agent engines --json' did not print valid JSON: $engines_json"

claude_readiness="$(printf '%s' "$engines_json" | jq -r '.engines[] | select(.engine=="AGENT_ENGINE_CLAUDE") | .readiness')"
codex_readiness="$(printf '%s' "$engines_json" | jq -r '.engines[] | select(.engine=="AGENT_ENGINE_CODEX") | .readiness')"
gemini_readiness="$(printf '%s' "$engines_json" | jq -r '.engines[] | select(.engine=="AGENT_ENGINE_GEMINI") | .readiness')"
gemini_reason="$(printf '%s' "$engines_json" | jq -r '.engines[] | select(.engine=="AGENT_ENGINE_GEMINI") | .reason')"

[ "$claude_readiness" = "AGENT_ENGINE_READINESS_READY" ] \
  || fail "assertion 1: claude readiness = '$claude_readiness', want READY (ANTHROPIC_API_KEY was set) -- full report: $engines_json"
[ "$codex_readiness" = "AGENT_ENGINE_READINESS_READY" ] \
  || fail "assertion 1: codex readiness = '$codex_readiness', want READY (OPENAI_API_KEY was set) -- full report: $engines_json"
[ "$gemini_readiness" = "AGENT_ENGINE_READINESS_NOT_READY" ] \
  || fail "assertion 1: gemini readiness = '$gemini_readiness', want NOT_READY (no GEMINI_API_KEY was set) -- full report: $engines_json"
case "$gemini_reason" in
  *"no key for provider gemini"*) ;;
  *) fail "assertion 1: gemini reason = '$gemini_reason', want it to say 'no key for provider gemini' -- the assertion is on the REASON STRING (#2225 AC2), not just the readiness enum" ;;
esac
ok "assertion 1: claude + codex READY, gemini NOT_READY (reason: \"$gemini_reason\")"

# ========================================================================
# Pre-provision both member boxes and verify the in-box loop EXISTS, before
# committing any spend — same reasoning as scripts/engineer-crew-e2e.sh.
# ========================================================================
for m in $CREW_MEMBERS; do
  log "pre-provisioning member box agent-$m (recipe agent-runtime, release $RELEASE)"
  : >"$WORKDIR/deploy-$m.body"
  deploy_code="$(curl -sS -o "$WORKDIR/deploy-$m.body" -w '%{http_code}' \
    -X POST "http://127.0.0.1:$HTTP_PORT/v1/recipes/agent-runtime/deploy" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg name "agent-$m" --arg rel "$RELEASE" '{name: $name, parameters: {release: $rel}}')" || true)"
  if [ "$deploy_code" != "200" ]; then
    echo "---- deploy response ----"; read_out "$WORKDIR/deploy-$m.body"; echo
    fail "deploying agent-$m returned $deploy_code (want 200)"
  fi
  sudo incus exec "agent-$m-container" -- test -x /usr/local/bin/agent-runtime \
    || fail "agent-$m-container has no /usr/local/bin/agent-runtime after deploying release $RELEASE"
  sudo incus exec "agent-$m-container" -- test -x /usr/local/bin/agent-box \
    || fail "agent-$m-container has no /usr/local/bin/agent-box"
  ok "member box agent-$m-container has agent-runtime and agent-box on PATH"

  profile_src="$WORKDIR/99-e2e-model-$m.sh"
  {
    echo "# installed by scripts/two-engine-crew-e2e.sh — cost ceilings for this lane"
    echo "export CONTAINARIUM_AGENT_MAX_TURNS=$AGENT_MAX_TURNS"
    if [ "${MEMBER_ENGINE[$m]}" = "claude" ]; then
      echo "export CONTAINARIUM_AGENT_MODEL=$CLAUDE_MODEL"
    fi
  } >"$profile_src"
  sudo incus file push --mode 0644 "$profile_src" "agent-$m-container/etc/profile.d/99-e2e-model.sh"
  sudo incus exec "agent-$m-container" -- test -f /etc/profile.d/99-e2e-model.sh \
    || fail "could not install the cost-ceiling profile into agent-$m-container"
  ok "cost ceilings installed in agent-$m-container (max_turns=$AGENT_MAX_TURNS model=${MEMBER_ENGINE[$m]:+$([ "${MEMBER_ENGINE[$m]}" = claude ] && echo "$CLAUDE_MODEL" || echo "<engine default>")})"
done

# ========================================================================
# THE MEASURED RUN — the only model spend in this script.
# ========================================================================
RUN_ID="two-engine-e2e-$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
RUN_SEED_DIR="$AGENT_SEED_ROOT/$RUN_ID"
TASK_JSON='{"task":"Reply with a short JSON object containing a one-sentence greeting."}'

run_crew() {
  local out="$1" body
  body="$(jq -nc --arg crew "$CREW_ID" --arg run_id "$RUN_ID" --arg input "$TASK_JSON" \
    '{crew_id: $crew, run_id: $run_id, input_json: $input}')"
  : >"$out.body"
  curl -sS -o "$out.body" -w '%{http_code}' --max-time "$RUN_TIMEOUT_S" \
    -X POST "http://127.0.0.1:$HTTP_PORT/v1/crews/$CREW_ID/run" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d "$body" >"$out.code" 2>"$out.err" || true
}

log "running $CREW_ID as $RUN_ID (REAL models: claude then codex) — RPC in the background so the run can be observed while it lasts"
run_crew "$WORKDIR/run" &
RUN_PID=$!

# --- assertion 2: each member's gateway token names its own provider -----
# Both members are provisioned (and their gateway.env seeded) BEFORE
# driveCrew runs a single hop — runCrew's own provisioning loop runs to
# completion first (internal/server/crew_server.go) — so both tokens are
# available early, not one-at-a-time as each hop executes.
declare -A GW_TOKEN
declare -A GW_TOKEN_VAR=( [hello-agent-claude]=ANTHROPIC_AUTH_TOKEN [hello-agent-codex]=OPENAI_API_KEY )
pending="$CREW_MEMBERS"
log "reading $RUN_SEED_DIR/gateway.env from each member box during the run"
for _ in $(seq 1 600); do
  still_pending=""
  for m in $pending; do
    gw_env="$(sudo incus exec "agent-$m-container" -- cat "$RUN_SEED_DIR/gateway.env" 2>/dev/null || true)"
    if [ -n "$gw_env" ]; then
      tok="$(printf '%s\n' "$gw_env" | sed -n "s/^export ${GW_TOKEN_VAR[$m]}=//p" | head -1)"
      if [ -n "$tok" ]; then
        GW_TOKEN[$m]="$tok"
        continue
      fi
    fi
    still_pending="$still_pending $m"
  done
  pending="$still_pending"
  [ -z "$pending" ] && break
  if ! kill -0 "$RUN_PID" 2>/dev/null; then
    wait "$RUN_PID" || true
    echo "---- run response (code $(read_code "$WORKDIR/run.code")) ----"; read_out "$WORKDIR/run.body"; echo
    fail "the crew run finished before gateway.env could be read for:$pending — read the response above; a fast failure here usually means provisioning, not the model"
  fi
  sleep 0.5
done
[ -z "$pending" ] || fail "never saw a gateway token for:$pending in $RUN_SEED_DIR"
for m in $CREW_MEMBERS; do
  ok "read $m's gateway token from $RUN_SEED_DIR/gateway.env during the run (${#GW_TOKEN[$m]} bytes)"
done

# Decode each JWT's `provider` claim (internal/modelgateway.GatewayClaims)
# straight from the token body: header.payload.signature, base64url, no
# padding — appending "====" and truncating to the correctly-padded length
# gives `base64 -d` a valid input regardless of the original padding.
decode_provider_claim() {
  local payload="$1" padded_len
  padded_len=$(( ((${#payload} + 3) / 4) * 4 ))
  printf '%s' "$payload" | tr '_-' '/+' | { cat; printf '%s' "===="; } | head -c "$padded_len" \
    | base64 -d 2>/dev/null | jq -r '.provider // empty'
}
declare -A GW_PROVIDER
for m in $CREW_MEMBERS; do
  payload="$(printf '%s' "${GW_TOKEN[$m]}" | cut -d. -f2)"
  GW_PROVIDER[$m]="$(decode_provider_claim "$payload")"
  [ -n "${GW_PROVIDER[$m]}" ] \
    || fail "assertion 2: could not decode a 'provider' claim out of $m's gateway token"
done

EXPECT_PROVIDER_CLAUDE="${MEMBER_PROVIDER[hello-agent-claude]}"
EXPECT_PROVIDER_CODEX="${MEMBER_PROVIDER[hello-agent-codex]}"
case "$SABOTAGE" in
  swap-expected-providers)
    echo "SABOTAGE: swapping which provider the harness expects from which member — assertion 2 must now go RED"
    EXPECT_PROVIDER_CLAUDE="${MEMBER_PROVIDER[hello-agent-codex]}"
    EXPECT_PROVIDER_CODEX="${MEMBER_PROVIDER[hello-agent-claude]}"
    ;;
esac

[ "${GW_PROVIDER[hello-agent-claude]}" = "$EXPECT_PROVIDER_CLAUDE" ] \
  || fail "assertion 2: hello-agent-claude's gateway token names provider '${GW_PROVIDER[hello-agent-claude]}', want '$EXPECT_PROVIDER_CLAUDE'"
[ "${GW_PROVIDER[hello-agent-codex]}" = "$EXPECT_PROVIDER_CODEX" ] \
  || fail "assertion 2: hello-agent-codex's gateway token names provider '${GW_PROVIDER[hello-agent-codex]}', want '$EXPECT_PROVIDER_CODEX'"
[ "${GW_PROVIDER[hello-agent-claude]}" != "${GW_PROVIDER[hello-agent-codex]}" ] \
  || fail "assertion 2: both members' gateway tokens name the SAME provider (${GW_PROVIDER[hello-agent-claude]}) — they are not actually running on different engines"
ok "assertion 2: hello-agent-claude -> provider ${GW_PROVIDER[hello-agent-claude]}, hello-agent-codex -> provider ${GW_PROVIDER[hello-agent-codex]} (different, each matching its manifest's engine)"

# --- wait for the crew run, assertion 3: COMPLETED ------------------------
log "waiting for the crew run to return (up to ${RUN_TIMEOUT_S}s; two real model conversations)"
wait "$RUN_PID" || true
run_code="$(read_code "$WORKDIR/run.code")"
run_body="$(read_out "$WORKDIR/run.body")"

if [ "$run_code" != "200" ]; then
  echo "---- run response ----"; printf '%s\n' "$run_body"
  fail "RunCrew returned $run_code (want 200)"
fi
echoed_run_id="$(printf '%s' "$run_body" | jq -r '.run.id // empty')"
[ "$echoed_run_id" = "$RUN_ID" ] \
  || fail "assertion 3: CrewRun.id was '$echoed_run_id', want '$RUN_ID'"
run_state="$(printf '%s' "$run_body" | jq -r '.run.state // empty')"
if [ "$run_state" != "CREW_RUN_STATE_COMPLETED" ]; then
  echo "---- run error ----"; printf '%s' "$run_body" | jq -r '.run.error // "(none)"'
  fail "assertion 3: CrewRun.state = '$run_state', want CREW_RUN_STATE_COMPLETED"
fi
ok "assertion 3: run $RUN_ID is CREW_RUN_STATE_COMPLETED"

echo
echo "PASS: two-engine-crew ran hello-agent-claude then hello-agent-codex on ONE daemon,"
echo "      each on its own engine (claude -> anthropic, codex -> openai), and"
echo "      'containarium agent engines' correctly reported gemini NOT_READY by reason"
echo "      while reporting both running engines READY."
