#!/usr/bin/env bash
# Self-test for the tunnel smoke release gate (#2469): proves the gate goes
# RED on the failure it exists to catch.
#
# v0.101.0/.1 shipped a tunnel client that requires --sentinel-pin while the
# sentinel could not yet provide a tunnel identity, so no pin existed to give
# it. This test reproduces that pairing without rebuilding an old tag: a stub
# sentinel that starts but provides no tunnel identity, against the REAL
# tunnel client from the build under test. scripts/ci/tunnel-smoke.sh must
# fail, and it must fail with the client's mandatory-pin error, not some
# unrelated harness error.
#
# Usage: scripts/ci/test-tunnel-smoke.sh <containariumd-binary>
#   <containariumd-binary>  the build whose `tunnel` client is under test
# Runs locally as well as in CI; the smoke script needs passwordless sudo
# (or root), as in CI.
set -euo pipefail

CLIENT_BIN="${1:?usage: test-tunnel-smoke.sh <containariumd-binary>}"
CLIENT_BIN="$(cd "$(dirname "$CLIENT_BIN")" && pwd)/$(basename "$CLIENT_BIN")"
[ -x "$CLIENT_BIN" ] || { echo "::error::not an executable: $CLIENT_BIN"; exit 1; }
here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The stub: `sentinel` starts and logs what the real one logs once it is
# listening, but has no tunnel identity, so `sentinel tunnel-identity` has
# no pin to print. Anything else (the `tunnel` client) is the real binary.
cat >"$work/stub-sentinel" <<EOF
#!/usr/bin/env bash
if [ "\${1:-}" = sentinel ]; then
  case " \$* " in
    *" tunnel-identity "*)
      echo "Error: this sentinel provides no tunnel identity" >&2; exit 1 ;;
    *" --help "*) exit 0 ;;
  esac
  echo "[sentinel] stub: no tunnel identity; multiplexing on"
  while :; do sleep 1; done
fi
exec "$CLIENT_BIN" "\$@"
EOF
chmod +x "$work/stub-sentinel"

want='--sentinel-pin or CONTAINARIUM_TUNNEL_SENTINEL_PIN is required'

set +e
"$here/tunnel-smoke.sh" "$work/stub-sentinel" "$CLIENT_BIN" >"$work/out.log" 2>&1
rc=$?
set -e

if [ "$rc" -eq 0 ]; then
  cat "$work/out.log"
  echo "::error::tunnel smoke gate PASSED against a sentinel with no tunnel identity; it must fail"
  exit 1
fi
if ! grep -qF -- "$want" "$work/out.log"; then
  cat "$work/out.log"
  echo "::error::tunnel smoke gate failed (rc=$rc) but not with the client's mandatory-pin error ('$want')"
  exit 1
fi
echo "tunnel smoke self-test passed: the gate fails against a sentinel with no tunnel identity, with the client's mandatory-pin error"
