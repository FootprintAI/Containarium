#!/usr/bin/env bash
# Fail on the workflow security rules the supply-chain gate enforces (#2904,
# follow-up to #2793 / #2649), using zizmor.
#
# Usage:
#   scripts/ci/check-workflow-security.sh [path ...]   # default: .github/workflows .github/actions
#   scripts/ci/check-workflow-security.sh --self-test
#
# Enforced rules (zizmor audit ids), at severity and confidence >= medium:
#   dangerous-triggers     pull_request_target / workflow_run (the way a PR head
#                          gets checked out with a write token and secrets)
#   template-injection     ${{ }} event data expanded inside a run:/script block
#   excessive-permissions  missing permissions:, write-all, or a write scope
#                          granted at workflow level where a job can hold it
# The auditor persona is used so these rules report everything they can; every
# other zizmor audit is reported by zizmor but does not fail the lane (the
# filter below). Adding a rule to the gate = adding its id to RULES and a
# bad-*.yml fixture under scripts/ci/testdata/zizmor/.
#
# Per-finding suppression goes in .github/zizmor.yml (`rules.<id>.ignore`),
# each with a reason comment; there is no blanket disable.
#
# zizmor runs offline: the lane has no extra token and the three rules need no
# network. Set ZIZMOR=/path/to/zizmor to choose the binary.
set -euo pipefail

ZIZMOR="${ZIZMOR:-zizmor}"
RULES="dangerous-triggers template-injection excessive-permissions"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="$HERE/../../.github/zizmor.yml"

# Reads zizmor's JSON on stdin; prints each enforced finding and exits 1 if any.
FILTER=$(cat <<'PY'
import json, os, sys
rules = set(os.environ["RULES"].split())
rank = {"Unknown": 0, "Low": 1, "Medium": 2, "High": 3}
bad = 0
for f in json.load(sys.stdin):
    d = f["determinations"]
    if f.get("ignored") or f["ident"] not in rules:
        continue
    if rank.get(d["severity"], 0) < 2 or rank.get(d["confidence"], 0) < 2:
        continue
    loc = f["locations"][0]
    path = loc["symbolic"]["key"].get("Local", {}).get("verbatim_path", "?")
    row = loc["concrete"]["location"]["start_point"]["row"] + 1
    note = loc["symbolic"]["annotation"]
    print(path + ":" + str(row) + ": " + f["ident"] + " (" + d["severity"] + "): " + note)
    bad = 1
sys.exit(bad)
PY
)

# run [--no-config] path... : zizmor over the paths, filtered to $RULES.
run() {
  local out rc=0 cfg=(--config "$CONFIG")
  if [[ "$1" == "--no-config" ]]; then cfg=(--no-config); shift; fi
  out=$("$ZIZMOR" --offline --quiet --format json --persona auditor "${cfg[@]}" "$@") || rc=$?
  # zizmor exits 10-14 when it has findings; anything else non-zero is an error.
  if [[ $rc -ne 0 && ( $rc -lt 10 || $rc -gt 14 ) ]]; then
    echo "zizmor failed (exit $rc)" >&2; return 2
  fi
  RULES="$RULES" python3 -I -c "$FILTER" <<<"$out"
}

self_test() {
  local dir="$HERE/testdata/zizmor" f bad=0 n=0
  [[ -d "$dir" ]] || { echo "missing $dir" >&2; return 1; }
  run --no-config "$dir/good.yml" >/dev/null || { echo "self-test FAIL: good.yml rejected"; run --no-config "$dir/good.yml"; bad=1; }
  for f in "$dir"/bad-*.yml; do
    n=$((n + 1))
    if run --no-config "$f" >/dev/null; then echo "self-test FAIL: $(basename "$f") was accepted"; bad=1; fi
  done
  [[ $bad -eq 0 ]] || return 1
  echo "self-test ok: good.yml accepted, $n seeded violations rejected"
}

if [[ "${1:-}" == "--self-test" ]]; then self_test; exit; fi
[[ $# -gt 0 ]] || set -- .github/workflows .github/actions
if run "$@"; then echo "workflow security rules ($RULES): no findings"; else
  echo "Fix the finding(s) above. A justified exception goes in .github/zizmor.yml with a reason." >&2
  exit 1
fi
