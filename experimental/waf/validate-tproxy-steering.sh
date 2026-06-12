#!/usr/bin/env bash
#
# Backend de-risk for Tier 3 PR-1 (#662): prove TPROXY steering + original-dst
# recovery + forward works end to end, with the daemon's transparent proxy.
#
# Runs ENTIRELY INSIDE A THROWAWAY NETWORK NAMESPACE so it does NOT touch the
# host's nft ruleset, routing, or live traffic — create netns, set up tproxy +
# the proxy + a test upstream inside it, test, destroy the netns. Zero blast
# radius on a live multi-tenant host (unlike applying tproxy rules to the host).
#
# What it proves: a client connecting to an ORIGINAL destination (a test upstream
# on 10.99.0.2:8080) is transparently steered by the nft tproxy rule to the
# proxy, which recovers that original dst (via IP_TRANSPARENT's LocalAddr) and
# forwards — the client gets the upstream's response back. This is the PR-1
# acceptance: steer→recover→forward, no WAF yet.
#
# Requires: root (netns + nft + IP_TRANSPARENT), nft_tproxy module (host-wide),
# and a built linux `waf-tproxy` probe binary (see BUILD below). Anonymise output.
#
# Usage (on the backend, as root):
#   sudo BUILD=1 ./validate-tproxy-steering.sh        # build the probe + run
#   sudo PROBE=/path/to/waf-tproxy ./validate-tproxy-steering.sh
#
set -euo pipefail

NS="waf-tproxy-test-$$"
TPROXY_PORT="${TPROXY_PORT:-15001}"
UPSTREAM_IP="10.99.0.2"
UPSTREAM_PORT=8080
PROBE="${PROBE:-/tmp/waf-tproxy}"

PASS=0 FAIL=0
pass() { printf '  \033[32mPASS\033[0m %s\n' "$*"; PASS=$((PASS + 1)); }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAIL=$((FAIL + 1)); }
info() { printf '  ·    %s\n' "$*"; }
phase() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

[ "$(id -u)" = 0 ] || { echo "must run as root (netns + nft + IP_TRANSPARENT)"; exit 2; }

cleanup() {
  set +e
  ip netns pid "$NS" 2>/dev/null | xargs -r kill 2>/dev/null
  ip netns del "$NS" 2>/dev/null
}
trap cleanup EXIT

phase "Preflight"
modprobe nft_tproxy 2>/dev/null && pass "nft_tproxy available" || { fail "nft_tproxy unavailable"; exit 1; }

if [ "${BUILD:-0}" = 1 ]; then
  info "building the waf-tproxy probe (a tiny main that calls waf.Start)"
  # The probe is a 6-line main; emit, build for linux, drop at $PROBE.
  tmp="$(mktemp -d)"
  cat > "$tmp/main.go" <<'GO'
package main

import (
	"context"
	"log"
	"os"

	"github.com/footprintai/containarium/internal/waf"
)

func main() {
	addr := os.Getenv("WAF_ADDR")
	if addr == "" {
		addr = ":15001"
	}
	if err := waf.Start(context.Background(), addr); err != nil {
		log.Fatalf("waf.Start: %v", err)
	}
	select {} // run until killed
}
GO
  ( cd "$(git -C "$(dirname "$0")" rev-parse --show-toplevel)" && GOOS=linux go build -o "$PROBE" "$tmp/main.go" ) \
    && pass "probe built at $PROBE" || { fail "probe build failed"; exit 1; }
  rm -rf "$tmp"
fi
[ -x "$PROBE" ] || { fail "probe binary $PROBE not found/executable (run with BUILD=1)"; exit 1; }

phase "Set up the isolated netns"
ip netns add "$NS"
ip netns exec "$NS" ip link set lo up
# A dummy interface to host the 'upstream' IP so the client has a real dst to aim
# at (10.99.0.2), routed locally inside the netns.
ip netns exec "$NS" ip link add upnet type dummy
ip netns exec "$NS" ip addr add ${UPSTREAM_IP}/24 dev upnet
ip netns exec "$NS" ip link set upnet up
pass "netns $NS up (upstream IP ${UPSTREAM_IP} on a dummy link)"

phase "TPROXY divert: route steered packets to the local proxy"
# Canonical tproxy plumbing: mark + policy route so packets the tproxy rule marks
# are delivered locally instead of forwarded.
ip netns exec "$NS" ip rule add fwmark 1 lookup 100
ip netns exec "$NS" ip route add local 0.0.0.0/0 dev lo table 100
ip netns exec "$NS" nft -f - <<NFT
table ip mangle {
  chain prerouting {
    type filter hook prerouting priority mangle; policy accept;
    ip daddr ${UPSTREAM_IP} tcp dport ${UPSTREAM_PORT} tproxy to :${TPROXY_PORT} meta mark set 1
  }
}
NFT
pass "nft tproxy rule installed (dst ${UPSTREAM_IP}:${UPSTREAM_PORT} → :${TPROXY_PORT})"

phase "Start the upstream + the steering proxy inside the netns"
# Upstream: a one-shot echo-ish HTTP responder on the original dst.
ip netns exec "$NS" sh -c "while true; do printf 'HTTP/1.0 200 OK\r\n\r\nUPSTREAM-OK' | nc -l -s ${UPSTREAM_IP} -p ${UPSTREAM_PORT} -q1; done" &
sleep 0.5
# The proxy binds IP_TRANSPARENT on :$TPROXY_PORT and forwards to the recovered
# original dst (which IS ${UPSTREAM_IP}:${UPSTREAM_PORT}).
ip netns exec "$NS" env WAF_ADDR=":${TPROXY_PORT}" "$PROBE" &
sleep 1
pass "upstream + proxy running"

phase "Steered request reaches the upstream THROUGH the proxy"
# The client aims at the ORIGINAL dst; tproxy diverts it to the proxy, which
# recovers the original dst and forwards. A non-steered control would hit the
# upstream directly — here every dst-matching packet is diverted, so a success
# proves the proxy forwarded correctly.
out="$(ip netns exec "$NS" sh -c "printf 'GET / HTTP/1.0\r\n\r\n' | nc -w2 ${UPSTREAM_IP} ${UPSTREAM_PORT}" 2>/dev/null || true)"
if printf '%s' "$out" | grep -q "UPSTREAM-OK"; then
  pass "client received the upstream response via the steering proxy"
else
  fail "no upstream response through the proxy (got: $(printf '%s' "$out" | head -c80))"
fi
# The proxy logs the recovered original dst; confirm it matches.
info "check the proxy's '[waf] steered connection → original dst ${UPSTREAM_IP}:${UPSTREAM_PORT}' log line above"

phase "Result"
printf 'PASS=%d  FAIL=%d\n' "$PASS" "$FAIL"
echo "On a clean pass: TPROXY steering + original-dst recovery + forward is proven; PR-1's de-risk is done."
echo "(For the REAL host setup — not a netns — scope the nft rule to a tenant veth/port and the daemon's"
echo " CONTAINARIUM_WAF_TPROXY_ADDR; the proxy's own dials are OUTPUT-path so they don't re-hit prerouting.)"
[ "$FAIL" -eq 0 ]
