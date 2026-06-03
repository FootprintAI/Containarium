#!/usr/bin/env bash
# Phase 0.5 — per-container veth-attach validation.
#
# Phase 0 (validate.sh) found that tc-bpf on the BRIDGE MASTER (incusbr0) only
# sees one direction of container↔container traffic: the bridge forwards frames
# between ports without them traversing the master's tc-egress hook, so the
# egress counter stayed 0. (#315)
#
# This re-tests the corrected attach point the Phase A design needs: attach to a
# container's HOST-SIDE VETH instead of the bridge. On the host veth:
#   - tc ingress = frames arriving from the container  (its OUTBOUND traffic)
#   - tc egress  = frames the host delivers to the container (its INBOUND)
# so a single A→B ping must bump BOTH counters on A's veth. If it does, the
# per-veth attach point observes both directions and Phase A can build on it.
#
# THROWAWAY — observation only (TC_ACT_OK, no drops); cleanup trap on EXIT.
# Run on a Linux+Incus backend as root, kernel ≥ 6.6.
#
# Usage: sudo ./validate-veth.sh [--keep]
#
set -euo pipefail

KEEP=0
CT_A="phase0-veth-a"
CT_B="phase0-veth-b"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

while [ $# -gt 0 ]; do
    case "$1" in
        --keep) KEEP=1; shift ;;
        --help|-h) sed -n '2,/^$/p' "$0" | sed 's|^# \{0,1\}||'; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

[ "$(id -u)" -eq 0 ] || { echo "must run as root (need tc, bpftool, incus)" >&2; exit 2; }
[ "$(uname -s)" = "Linux" ] || { echo "Linux only" >&2; exit 2; }
for cmd in clang tc bpftool incus; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "missing required command: $cmd" >&2; exit 2; }
done

VETH_A=""
VETH_B=""
cleanup() {
    set +e
    if [ "$KEEP" -eq 0 ]; then
        echo "==> cleanup"
        [ -n "$VETH_A" ] && tc qdisc del dev "$VETH_A" clsact 2>/dev/null
        [ -n "$VETH_B" ] && tc qdisc del dev "$VETH_B" clsact 2>/dev/null
        rm -f /sys/fs/bpf/phase0_pkt_counter 2>/dev/null
        incus delete --force "$CT_A" </dev/null 2>/dev/null
        incus delete --force "$CT_B" </dev/null 2>/dev/null
        rm -f "$SCRIPT_DIR/counter.bpf.o"
    else
        echo "==> --keep set; leaving veth=$VETH_A attached + containers up"
    fi
}
trap cleanup EXIT

# resolve_host_veth <container> — the host-side veth name for the default nic.
# Prefer Incus' volatile.eth0.host_name; fall back to mapping eth0's iflink to a
# host interface (works regardless of the nic's volatile key name).
resolve_host_veth() {
    ct="$1"
    veth="$(incus config get "$ct" volatile.eth0.host_name </dev/null 2>/dev/null)"
    if [ -n "$veth" ] && ip link show "$veth" >/dev/null 2>&1; then
        echo "$veth"; return 0
    fi
    iflink="$(incus exec "$ct" -- cat /sys/class/net/eth0/iflink </dev/null 2>/dev/null | tr -d '[:space:]')"
    [ -n "$iflink" ] || return 1
    ip -o link 2>/dev/null | awk -F': ' -v i="$iflink" '$1==i {split($2,a,"@"); print a[1]; exit}'
}

echo "==> 1/5: building BPF object"
cd "$SCRIPT_DIR"
MULTIARCH_INC="/usr/include/$(uname -m)-linux-gnu"
clang -O2 -g -target bpf -I"$MULTIARCH_INC" -c counter.bpf.c -o counter.bpf.o
echo "    OK: counter.bpf.o ($(stat -c%s counter.bpf.o) bytes)"

echo "==> 2/5: spawning two throwaway containers"
incus launch images:ubuntu/24.04 "$CT_A" --quiet </dev/null
incus launch images:ubuntu/24.04 "$CT_B" --quiet </dev/null
for i in $(seq 30); do
    IP_A=$(incus list "$CT_A" -c4 --format csv </dev/null | awk '{print $1}')
    IP_B=$(incus list "$CT_B" -c4 --format csv </dev/null | awk '{print $1}')
    [ -n "$IP_A" ] && [ -n "$IP_B" ] && break
    sleep 1
done
[ -n "${IP_A:-}" ] && [ -n "${IP_B:-}" ] || { echo "    FAIL: containers didn't get IPs" >&2; exit 1; }
echo "    OK: $CT_A=$IP_A  $CT_B=$IP_B"

echo "==> 3/5: resolving + attaching counters"
VETH_A="$(resolve_host_veth "$CT_A")"
VETH_B="$(resolve_host_veth "$CT_B")"
[ -n "$VETH_A" ] && [ -n "$VETH_B" ] || { echo "    FAIL: could not resolve host veths ($CT_A=$VETH_A $CT_B=$VETH_B)" >&2; exit 1; }
echo "    $CT_A veth=$VETH_A   $CT_B veth=$VETH_B"
# A's veth: ingress (A-out) → index 0, egress (A-in) → index 1.
tc qdisc add dev "$VETH_A" clsact 2>/dev/null || true
tc filter add dev "$VETH_A" ingress bpf da obj counter.bpf.o sec classifier/ingress
tc filter add dev "$VETH_A" egress  bpf da obj counter.bpf.o sec classifier/egress
# B's veth: ingress (B-out, i.e. the replies to A) also → index 0. So index 0 is
# the union of both containers' OUTBOUND; if it jumps far past A's own outbound,
# B genuinely sent replies — letting us tell "no connectivity" from "veth-egress
# doesn't observe inbound".
tc qdisc add dev "$VETH_B" clsact 2>/dev/null || true
tc filter add dev "$VETH_B" ingress bpf da obj counter.bpf.o sec classifier/ingress
echo "    OK: A veth ingress+egress, B veth ingress"

echo "==> 4/5: snapshotting counters, pinging A→B, re-reading"
MAP_ID=$(bpftool map show | awk '/name pkt_counter/ {print $1}' | tr -d ':' | head -1)
[ -n "$MAP_ID" ] || { echo "    FAIL: pkt_counter map not visible" >&2; exit 1; }
read_counter() {
    bpftool map lookup id "$MAP_ID" key hex 0$1 00 00 00 \
        | awk '/value/ {for (i=NF; i>1; i--) printf "%s", $i; print ""}' \
        | sed 's/[^0-9a-f]//g' | xargs -I{} printf "%d\n" "0x{}"
}
BEFORE_VETHIN=$(read_counter 0); BEFORE_AEG=$(read_counter 1)
echo "    before: veth-ingress(A-out+B-out)=$BEFORE_VETHIN  A-veth-egress(A-in)=$BEFORE_AEG"
PING_OUT="$(incus exec "$CT_A" -- ping -c 5 -W 2 "$IP_B" </dev/null 2>&1 || true)"
RECV="$(printf '%s' "$PING_OUT" | grep -oE '[0-9]+ (packets )?received' | grep -oE '^[0-9]+' | head -1)"
AFTER_VETHIN=$(read_counter 0); AFTER_AEG=$(read_counter 1)
echo "    ping:   ${RECV:-0}/5 replies received"
echo "    after:  veth-ingress(A-out+B-out)=$AFTER_VETHIN  A-veth-egress(A-in)=$AFTER_AEG"

echo "==> 5/5: interpretation"
echo "    veth-ingress delta = $((AFTER_VETHIN - BEFORE_VETHIN))   A-veth-egress delta = $((AFTER_AEG - BEFORE_AEG))"
if [ "${RECV:-0}" -gt 0 ] && [ "$((AFTER_AEG - BEFORE_AEG))" -eq 0 ]; then
    echo ""
    echo "  ✗ FINDING: replies flowed (${RECV}/5) and were counted at the SENDER's veth"
    echo "    ingress, but A's veth-EGRESS never fired — bridge-forwarded inbound bypasses"
    echo "    the destination veth's tc-egress too. Phase A must observe/enforce at each"
    echo "    container's veth INGRESS (captures that container's outbound = every flow's"
    echo "    sender side); tc-egress on bridge/veth is not a reliable hook."
    exit 1
elif [ "${RECV:-0}" -eq 0 ]; then
    echo ""
    echo "  ⚠ INCONCLUSIVE: ping got 0 replies — intra-bridge connectivity issue, not a"
    echo "    hook result. Fix connectivity (default profile / firewall) and re-run." >&2
    exit 2
else
    echo ""
    echo "  ✓ A's veth-egress DID observe inbound (delta>0) — per-veth attach sees both"
    echo "    directions; Phase A can attach ingress+egress at the container veth."
fi
