#!/usr/bin/env bash
# Exercise the verify_remote helper extracted from deploy-binary.sh.
set -uo pipefail
BINARY="/tmp/fakebin"
EXPECTED_SHA="aaaa1111"

# --- helper copied verbatim from scripts/deploy-binary.sh ---
verify_remote() {
    local label="$1"; shift
    local got
    got="$("$@" "sha256sum /tmp/containarium 2>/dev/null | cut -d' ' -f1" 2>/dev/null || true)"
    got="$(printf '%s' "$got" | tr -d '[:space:]')"
    if [ -z "$got" ]; then
        echo "  ERROR: could not read the uploaded binary's checksum on $label" >&2
        return 1
    fi
    if [ "$got" != "$EXPECTED_SHA" ]; then
        echo "  ERROR: checksum mismatch on $label — refusing to install." >&2
        return 1
    fi
    echo "  checksum OK on $label"
}
# --- end helper ---

runner_match()    { echo "aaaa1111"; }
runner_mismatch() { echo "bbbb2222"; }
runner_empty()    { echo ""; }
runner_fails()    { return 1; }
runner_spaces()   { echo "  aaaa1111  "; }

pass=0; fail=0
check() { # name expected_rc runner
  local name="$1" want="$2"; shift 2
  verify_remote "$name" "$@" >/dev/null 2>&1; local rc=$?
  if [ "$rc" = "$want" ]; then echo "  PASS  $name (rc=$rc)"; pass=$((pass+1));
  else echo "  FAIL  $name (rc=$rc want=$want)"; fail=$((fail+1)); fi
}
echo "=== verify_remote behaviour ==="
check "matching checksum -> accept"        0 runner_match
check "mismatched checksum -> REFUSE"      1 runner_mismatch
check "empty response -> REFUSE"           1 runner_empty
check "ssh failure -> REFUSE"              1 runner_fails
check "whitespace tolerated -> accept"     0 runner_spaces
echo "passed=$pass failed=$fail"
[ "$fail" = "0" ]
