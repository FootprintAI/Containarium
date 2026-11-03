#!/usr/bin/env bash
#
# slides-agent image entrypoint: refuse to start without auth material, seed
# the deck tree on the bind-mounted workspace, then run the open-slide dev
# server on loopback, the login helper (slides-wsauth, loopback only) and the
# auth proxy in front of them. Any one of them exiting ends the container (the
# recipe runs it with --restart=always); a restarted helper starts with no
# session, so every browser signs in again.
# See images/slides-agent/Dockerfile.
set -euo pipefail

WORKSPACE="${SLIDES_WORKSPACE:-/workspace}"
TEMPLATE="${SLIDES_TEMPLATE:-/opt/open-slide/template}"
APP="${SLIDES_APP:-/opt/open-slide/app}"

# Fail closed: the proxy must never come up with a degenerate auth config, and
# the dev server must never come up without the proxy.
for v in SLIDES_AUTH_USER SLIDES_AUTH_HASH; do
  if [ -z "${!v:-}" ]; then
    echo "[slides-agent] $v is empty; refusing to start without auth material" >&2
    exit 1
  fi
done

# The container runs as the box user (an arbitrary uid): make sure HOME is
# writable for Vite, Chromium and npm caches.
if ! mkdir -p "${HOME:-/nonexistent}" 2>/dev/null || [ ! -w "$HOME" ]; then
  HOME="$(mktemp -d)"
  export HOME
fi

# Seed the workspace from the template: only entries that do not exist yet,
# so a resumed box keeps every deck and edit while a removed piece (themes/,
# the agent files) is filled back in. Symlinks are kept relative (the
# template's .claude/skills point into .agents/skills).
mkdir -p "$WORKSPACE"
for entry in "$TEMPLATE"/* "$TEMPLATE"/.[!.]*; do
  [ -e "$entry" ] || [ -L "$entry" ] || continue
  name="$(basename "$entry")"
  if [ ! -e "$WORKSPACE/$name" ] && [ ! -L "$WORKSPACE/$name" ]; then
    cp -a "$entry" "$WORKSPACE/$name"
  fi
done
mkdir -p "$WORKSPACE/slides" "$WORKSPACE/themes" "$WORKSPACE/assets"
# Slides import @open-slide/core and react; Node resolution walks up from
# /workspace/slides, so the image's node_modules is linked there (gitignored
# by the seeded .gitignore; dangling when read from the box itself).
if [ ! -e "$WORKSPACE/node_modules" ] && [ ! -L "$WORKSPACE/node_modules" ]; then
  ln -s "$APP/node_modules" "$WORKSPACE/node_modules"
fi

if [ "${SLIDES_SEED_ONLY:-0}" = "1" ]; then
  exit 0
fi

cd "$APP"
# --host 127.0.0.1: loopback only, and the IPv4 address the proxy dials (a
# bare `localhost` can resolve to ::1 alone inside the container).
node node_modules/@open-slide/core/bin.js dev --host 127.0.0.1 --port 5173 --no-skills-check &
DEV_PID=$!
slides-wsauth &
AUTH_PID=$!
caddy run --config /etc/caddy/Caddyfile --adapter caddyfile &
CADDY_PID=$!

shutdown() {
  kill -TERM "$DEV_PID" "$AUTH_PID" "$CADDY_PID" 2>/dev/null || true
  wait "$DEV_PID" "$AUTH_PID" "$CADDY_PID" 2>/dev/null || true
}
trap shutdown TERM INT

# The first of the three to exit takes the container down with it.
wait -n "$DEV_PID" "$AUTH_PID" "$CADDY_PID" || true
echo "[slides-agent] dev server, login helper or proxy exited; stopping" >&2
shutdown
exit 1
