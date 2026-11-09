#!/usr/bin/env bash
# Gate: the built linux agent-box must be statically linked (#3582). agent-box
# runs as root inside boxes whose libc it does not control (the audit setup
# copies it into a root-owned directory and runs the hooks from there), so a
# glibc-dynamic build is a deployment and trust hazard. Reads the binary's own
# build info (CGO_ENABLED) and, where available, `ldd`/`file`.
#
# Usage: scripts/test-agent-box-static.sh [BINARY]   (default: bin/agent-box-linux-amd64)
set -uo pipefail

f="${1:-bin/agent-box-linux-amd64}"
fail=0
bad() { echo "FAIL: $*" >&2; fail=1; }

[ -f "$f" ] || { echo "FAIL: $f does not exist" >&2; exit 1; }

cgo="$(go version -m "$f" 2>/dev/null | awk '$1=="build" && $2 ~ /^CGO_ENABLED=/ {sub("CGO_ENABLED=","",$2); print $2}')"
[ "$cgo" = "0" ] || bad "$f was built with CGO_ENABLED='$cgo', want 0"

if command -v file >/dev/null 2>&1; then
  desc="$(file -L "$f")"
  case "$desc" in
    *"dynamically linked"*) bad "$f is dynamically linked: $desc" ;;
  esac
fi
if command -v ldd >/dev/null 2>&1; then
  out="$(ldd "$f" 2>&1 || true)"
  case "$out" in
    *"not a dynamic executable"*|*"statically linked"*) ;;
    *) bad "ldd reports shared libraries for $f: $out" ;;
  esac
fi

[ "$fail" = 0 ] && echo "ok: $f is statically linked (CGO_ENABLED=0)"
exit "$fail"
