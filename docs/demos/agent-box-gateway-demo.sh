#!/usr/bin/env bash
# =============================================================================
# Containarium — DEMO: an AI agent in a throwaway, isolated box,
#                       talking to models through YOUR own gateway.
#
#   Self-hosted · Apache-2.0 · your compute · your key · your audit log
#   Target length when recorded: ~90 seconds.
#
# THE WEDGE (what this demo proves in one minute):
#   1. A skill = a packaged agent (a box recipe + a typed manifest).
#   2. `agent run` spins a disposable, network-isolated box, mints a token
#      scoped to EXACTLY that skill's permissions, and runs the agent.
#   3. The agent's model calls are brokered by the daemon's model-gateway:
#      the provider API key lives on the HOST and NEVER enters the box —
#      the box only ever holds a short-lived, revocable token. Every call
#      is metered per tenant/skill/model.
#   4. It's a box: tear it down, zero blast radius.
#
# -----------------------------------------------------------------------------
# PREREQUISITES (operator, one-time — do this BEFORE recording):
#
#   * A reachable Containarium daemon ($SERVER below). Self-host:
#       curl -fsSL https://containarium.dev/install.sh | sh   # (or build OSS)
#
#   * Turn on the gateway by giving the DAEMON one provider key in its env,
#     then (re)start it. The key turns the model-gateway on automatically:
#       # /etc/containarium/daemon.env
#       GEMINI_API_KEY=...            # or ANTHROPIC_API_KEY / OPENAI_API_KEY
#     The daemon logs on boot:
#       "Model-gateway enabled (providers=[gemini ...]) — provider keys never leave the host"
#
#   The `code-review` skill below ships in OSS, so no extra pack is needed.
#   (Opinionated/domain skills — PM, compliance — load from a pack via
#    CONTAINARIUM_SKILLS_DIR; `hello-agent` is the zero-config smoke test.)
#
SERVER="${SERVER:-https://YOUR-DAEMON:8080}"
SKILL="${SKILL:-code-review}"
INPUT="${INPUT:-{\"brief\":\"Review this Go handler for bugs and security issues: func GetUser(w http.ResponseWriter, r *http.Request) { id := r.URL.Query().Get(\\\"id\\\"); row := db.QueryRow(\\\"SELECT name FROM users WHERE id = \\\" + id); ... }\"}}"
# =============================================================================

set -euo pipefail
say() { printf '\n\033[1;36m# %s\033[0m\n' "$*"; sleep 1; }
run() { printf '\033[1;32m$ %s\033[0m\n' "$*"; eval "$*"; }

clear
say "Containarium: run an AI agent in a disposable, isolated box — on your own model gateway."
sleep 1

# ---------------------------------------------------------------------------
say "1/4  Skills are packaged agents: a box recipe + a typed manifest"
say "      (system prompt, the scopes it's allowed, the peers it may call)."
run "containarium agent list --server $SERVER"

# ---------------------------------------------------------------------------
say "2/4  Run one — ONE command. Notice: we never type an API key."
run "containarium agent run $SKILL --input '$INPUT' --server $SERVER"
say "      Containarium just: created an isolated LXC box, minted a JWT scoped to"
say "      exactly this skill's permissions, ran the agent, and printed its review."

# ---------------------------------------------------------------------------
say "3/4  Custody + metering. The model call was brokered by YOUR gateway."
say "      The provider key stayed on the host; the box held only a revocable token."
say "      On the daemon host, every call is logged + metered:"
printf '\033[1;32m$ journalctl -u containarium-daemon -n 20 | grep model-gateway\033[0m\n'
printf '  model-gateway: tenant=agent-%s provider=gemini model=gemini-2.5-flash in=… out=…\n' "$SKILL"
say "      (metering also streams to your metrics backend for per-tenant billing)."

# ---------------------------------------------------------------------------
say "4/4  It's a box. Disposable, isolated — tear it down, zero blast radius."
run "containarium list --server $SERVER"
say "      Remove the agent box (name shown above, e.g. agent-$SKILL):"
printf '\033[1;32m$ containarium delete agent-%s --server %s\033[0m\n' "$SKILL" "$SERVER"

# ---------------------------------------------------------------------------
say "Self-hosted. Apache-2.0. Your compute, your key, your audit log."
say "  github.com/FootprintAI/Containarium"
