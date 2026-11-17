#!/usr/bin/env bash
# Refuse to cut a release while a release hold is open (#3689).
#
# A hold is a file release-holds/<issue>.md that says what must be true on the
# machines that will RUN this release before it is published. It exists for
# changes that are safe to merge but unsafe to ship until an operator has checked
# live state, such as refusing a credential format that older clusters still use.
# Removing the file is the act of clearing the hold, and it is done in a PR whose
# description records the evidence (counts only, no host or tenant names).
#
# Usage: scripts/ci/check-release-holds.sh [HOLDS_DIR]   (default: release-holds)
# Exit 0 when no hold is open, 1 (with the holds listed) when one is.
set -euo pipefail

dir=${1:-release-holds}
[ -d "$dir" ] || exit 0

shopt -s nullglob
open=()
for f in "$dir"/*.md; do
  case "$(basename "$f")" in README.md) continue ;; esac
  open+=("$f")
done

if [ "${#open[@]}" -eq 0 ]; then
  echo "no open release holds"
  exit 0
fi

echo "::error::${#open[@]} open release hold(s): clear each (delete the file in a PR that records the gate evidence) or do not cut this release" >&2
for f in "${open[@]}"; do
  title=$(grep -m1 '^# ' "$f" | sed 's/^# //')
  echo "  - $f: ${title:-"(no title)"}" >&2
done
exit 1
