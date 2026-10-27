#!/usr/bin/env bash
# Release gate (#2469): run the tunnel CLIENT and the SENTINEL from the same
# build against each other and prove they interoperate.
#
# Every in-process tunnel test builds both halves from one source tree, so it
# only proves the halves agree at one commit — not that the shipped client can
# reach the shipped sentinel with what the sentinel actually provides (a client
# that requires a pin the sentinel could not yet supply passed every gate in
# v0.101.0/.1). This script starts the real sentinel, reads the pin the way an
# operator does (`sentinel tunnel-identity`), starts the real `tunnel` client
# with that pin, and asserts the client registers over TLS and that a request
# round-trips through the tunnel.
#
# Usage: scripts/ci/tunnel-smoke.sh <containariumd-binary> [<client-binary>]
#   <containariumd-binary>  runs `sentinel` (and `tunnel`, unless a client
#                           binary is given)
#   <client-binary>         optional: a different build to act as the tunnel
#                           client, e.g. the previous release's containariumd,
#                           to prove it still registers
# Loopback only. Registering a tunnel makes the sentinel add a 127.x loopback
# alias with `ip addr add`, which needs root: the sentinel runs under sudo -n
# (a CI runner has passwordless sudo) unless the script is already root.
set -euo pipefail

SENTINEL_BIN="${1:?usage: tunnel-smoke.sh <containariumd-binary> [<client-binary>]}"
CLIENT_BIN="${2:-$SENTINEL_BIN}"
TOKEN="smoke-token-$$"
work="$(mktemp -d)"
pids=()

SUDO=""
[ "$(id -u)" -eq 0 ] || SUDO="sudo -n"

cleanup() {
  for p in "${pids[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
  # The sentinel runs as root; its path under $work is unique to this run.
  $SUDO pkill -f -- "$work/sentinel-bin" 2>/dev/null || true
  wait 2>/dev/null || true
  $SUDO rm -rf "$work"
}
trap cleanup EXIT

fail() {
  echo "::error::tunnel smoke test: $*"
  for f in sentinel.log client.log backend.log; do
    echo "--- $f"; tail -n 40 "$work/$f" 2>/dev/null || true
  done
  exit 1
}

freeport() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }

SENTINEL_PORT="$(freeport)"; HTTP_PORT="$(freeport)"; BACKEND_PORT="$(freeport)"

# A tunnel backend with a recognisable body to round-trip.
mkdir "$work/www"; echo "tunnel-smoke-ok" > "$work/www/index.html"
python3 -m http.server "$BACKEND_PORT" --bind 127.0.0.1 --directory "$work/www" >"$work/backend.log" 2>&1 &
pids+=($!)

cp "$SENTINEL_BIN" "$work/sentinel-bin"

# Flags newer sentinels have and older ones reject, so an older build can be
# put under test too (e.g. to prove the gate fails on a known-bad release).
extra=()
if "$work/sentinel-bin" sentinel --help 2>&1 | grep -q -- '--ssh-authz-socket'; then
  extra+=(--ssh-authz-socket "")
fi

$SUDO "$work/sentinel-bin" sentinel --provider tunnel \
  --http-port "$HTTP_PORT" --https-port "$SENTINEL_PORT" --binary-port 0 \
  --forwarded-ports "$SENTINEL_PORT" \
  --tunnel-token "$TOKEN" --tunnel-tls-identity "$work/identity.pem" \
  "${extra[@]}" >"$work/sentinel.log" 2>&1 &
pids+=($!)

for _ in $(seq 1 50); do
  grep -q 'multiplexing on' "$work/sentinel.log" 2>/dev/null && break
  sleep 0.2
done
grep -q 'multiplexing on' "$work/sentinel.log" || fail "sentinel did not start"

# The pin, read the way an operator reads it. A sentinel with no tunnel
# identity has none to print; the client still gets whatever was printed, so
# the gate fails with the client's own error, as an operator's upgrade would
# (the v0.101.0/.1 failure). scripts/ci/test-tunnel-smoke.sh proves this.
PIN="$($SUDO "$work/sentinel-bin" sentinel tunnel-identity --tunnel-tls-identity "$work/identity.pem" 2>>"$work/sentinel.log" | tail -n 1 || true)"
[[ "$PIN" =~ ^sha256:[0-9a-f]{64}$ ]] \
  || echo "::warning::sentinel tunnel-identity printed no usable pin: '$PIN'; starting the client with it anyway"

# The env fallback is cleared so only the pin the sentinel supplied counts.
env -u CONTAINARIUM_TUNNEL_SENTINEL_PIN \
  "$CLIENT_BIN" tunnel --sentinel-addr "127.0.0.1:$SENTINEL_PORT" --sentinel-pin "$PIN" \
  --token "$TOKEN" --spot-id smoke-spot --ports "$BACKEND_PORT" >"$work/client.log" 2>&1 &
pids+=($!)
client_pid=$!

# (a) the sentinel registered the spot over TLS. Asserted on the sentinel's
# log: it is the side that decides the transport.
for _ in $(seq 1 100); do
  grep -q 'registered spot "smoke-spot".*transport=tls' "$work/sentinel.log" 2>/dev/null && break
  kill -0 "$client_pid" 2>/dev/null || break
  sleep 0.2
done
if ! grep -q 'registered spot "smoke-spot".*transport=tls' "$work/sentinel.log" \
  && ! kill -0 "$client_pid" 2>/dev/null; then
  fail "the tunnel client exited before registering: $(grep -m1 -E '^Error:' "$work/client.log" || tail -n 1 "$work/client.log")"
fi
grep -q 'registered spot "smoke-spot".*transport=tls' "$work/sentinel.log" \
  || fail "the tunnel client did not register with the sentinel over TLS"

# (b) a request round-trips: the sentinel opens a proxy for the advertised port
# on the spot's assigned loopback address and forwards it through the tunnel.
ADDR="$(sed -n 's/.*proxy listening on \([0-9.]*\):'"$BACKEND_PORT"' .*/\1/p' "$work/sentinel.log" | head -n 1)"
[ -n "$ADDR" ] || fail "the sentinel opened no proxy for port $BACKEND_PORT"
body=""
for _ in $(seq 1 25); do
  body="$(curl -fsS --max-time 3 "http://$ADDR:$BACKEND_PORT/" 2>/dev/null || true)"
  [ "$body" = "tunnel-smoke-ok" ] && break
  sleep 0.2
done
[ "$body" = "tunnel-smoke-ok" ] || fail "request through the tunnel returned '$body', want 'tunnel-smoke-ok'"

echo "tunnel smoke test passed: registered over TLS, request round-tripped via $ADDR:$BACKEND_PORT"
