#!/usr/bin/env bash
#
# validate-gpu-passthrough.sh — does GPU passthrough actually work from inside
# an Incus LXC on this host?
#
# Standalone (no Containarium daemon needed). The migration gate for
# docs/CONTAINARIUM-HOST-TO-VM-MIGRATION.md (#316): run it before committing to
# a host→VM move, and after any VFIO bind or NVIDIA driver upgrade.
#
# What it does:
#   1. launches a throwaway LXC (nvidia.runtime=true + a gpu device, the
#      standard Incus NVIDIA recipe — libnvidia-container injects the host
#      driver libs + nvidia-smi into the container; no in-container install)
#   2. runs `nvidia-smi` inside and parses the GPU model + driver version
#   3. tears the LXC down (always, via trap)
#   4. prints `✓ GPU PASSTHROUGH OK: <model> (driver <ver>)` or
#      `✗ GPU PASSTHROUGH FAILED: <reason>` and exits 0 / 1 accordingly.
#
# Usage:
#   sudo ./scripts/validate-gpu-passthrough.sh [--pci <addr>] [--image <img>]
#                                              [--json] [--keep-on-fail]
#
#   --pci <addr>     Pass a specific GPU by PCI address (e.g. 0000:01:00.0).
#                    Default: pass all GPUs (Incus `gpu` device with no filter).
#   --image <img>    Base image. Default images:ubuntu/24.04.
#   --json           Emit a single JSON object instead of human text.
#   --keep-on-fail   Don't delete the throwaway LXC if validation fails
#                    (for debugging). It's always deleted on success.
#
set -euo pipefail

PCI=""
IMAGE="images:ubuntu/24.04"
JSON=false
KEEP_ON_FAIL=false

while [ $# -gt 0 ]; do
    case "$1" in
        --pci) PCI="$2"; shift 2 ;;
        --image) IMAGE="$2"; shift 2 ;;
        --json) JSON=true; shift ;;
        --keep-on-fail) KEEP_ON_FAIL=true; shift ;;
        -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

# A fixed-but-unique-enough name without Date/RANDOM dependencies in odd shells.
CT="gpuval-$$"
STATUS="failed"
MODEL=""
DRIVER=""
REASON=""
LAUNCHED=false

emit() {
    if [ "$JSON" = true ]; then
        # Hand-rolled JSON (no jq dependency on a minimal host).
        printf '{"gpu_status":"%s","gpu_model":"%s","driver_version":"%s","reason":"%s"}\n' \
            "$STATUS" "$MODEL" "$DRIVER" "$REASON"
    elif [ "$STATUS" = "ok" ]; then
        echo "✓ GPU PASSTHROUGH OK: $MODEL (driver $DRIVER)"
    else
        echo "✗ GPU PASSTHROUGH FAILED: $REASON"
    fi
}

cleanup() {
    code=$?
    if [ "$LAUNCHED" = true ]; then
        if [ "$STATUS" = "ok" ] || [ "$KEEP_ON_FAIL" != true ]; then
            incus delete --force "$CT" >/dev/null 2>&1 </dev/null || true
        else
            echo "  (kept $CT for debugging — 'incus delete --force $CT' to remove)" >&2
        fi
    fi
    emit
    # Preserve an explicit failure exit set before normal completion.
    if [ "$STATUS" = "ok" ]; then exit 0; fi
    [ "$code" -ne 0 ] && exit "$code"
    exit 1
}
trap cleanup EXIT

fail() { REASON="$1"; exit 1; }

# --- preflight --------------------------------------------------------------
# Every `incus` call below redirects stdin from /dev/null. `incus exec` (and,
# observed, `incus launch`) inherit this process's stdin and forward/consume it;
# if the script itself was piped in (`bash -s < script` / `curl ... | bash`),
# that drains the bytes the shell still needs and the run breaks. </dev/null
# makes the script behave identically whether run as a file or piped.
command -v incus >/dev/null 2>&1 || fail "incus not found on host"
incus info >/dev/null 2>&1 </dev/null || fail "cannot talk to incus (run as root / in the incus group?)"

# --- launch throwaway LXC with NVIDIA passthrough ---------------------------
# nvidia.runtime=true makes Incus inject the host's NVIDIA driver + nvidia-smi.
if ! incus launch "$IMAGE" "$CT" -c nvidia.runtime=true >/dev/null 2>&1 </dev/null; then
    fail "incus launch failed (image $IMAGE, nvidia.runtime=true)"
fi
LAUNCHED=true

# Attach the GPU device — a specific PCI address if given, else all GPUs.
if [ -n "$PCI" ]; then
    incus config device add "$CT" gpu gpu "pci=$PCI" >/dev/null 2>&1 </dev/null \
        || fail "could not attach GPU device pci=$PCI"
else
    incus config device add "$CT" gpu gpu >/dev/null 2>&1 </dev/null \
        || fail "could not attach GPU device"
fi

# Give the container a moment to finish booting before exec.
for _ in $(seq 1 15); do
    if incus exec "$CT" -- true >/dev/null 2>&1 </dev/null; then break; fi
    sleep 1
done

# --- run nvidia-smi inside --------------------------------------------------
if ! incus exec "$CT" -- sh -c 'command -v nvidia-smi >/dev/null 2>&1' </dev/null; then
    fail "nvidia-smi not present in the container (nvidia.runtime injection failed — check host driver + libnvidia-container)"
fi

OUT="$(incus exec "$CT" -- nvidia-smi --query-gpu=name,driver_version --format=csv,noheader 2>/dev/null </dev/null | head -1 || true)"
if [ -z "$OUT" ]; then
    fail "nvidia-smi ran but returned no GPU (passthrough not visible inside the LXC)"
fi

# OUT looks like: "NVIDIA GeForce RTX 4090, 570.86.15"
MODEL="$(printf '%s' "$OUT" | cut -d, -f1 | sed 's/^ *//;s/ *$//')"
DRIVER="$(printf '%s' "$OUT" | cut -d, -f2 | sed 's/^ *//;s/ *$//')"
[ -n "$MODEL" ] || fail "could not parse GPU model from nvidia-smi output: $OUT"

STATUS="ok"
# cleanup() runs on EXIT: tears down the LXC, emits the result, exits 0.
