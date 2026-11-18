#!/usr/bin/env bash
# Tests for check-release-holds.sh. Run: scripts/ci/test-check-release-holds.sh
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
script=$here/check-release-holds.sh
t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
fail=0
expect() { # name want_exit dir
  "$script" "$3" >/dev/null 2>&1; got=$?
  if [ "$got" != "$2" ]; then echo "FAIL $1: exit $got, want $2"; fail=1; else echo "ok   $1"; fi
}
expect "missing dir passes" 0 "$t/none"
mkdir "$t/empty"; expect "empty dir passes" 0 "$t/empty"
mkdir "$t/readme"; echo "# about" > "$t/readme/README.md"; expect "README alone passes" 0 "$t/readme"
mkdir "$t/other"; echo "x" > "$t/other/notes.txt"; expect "non-md file ignored" 0 "$t/other"
mkdir "$t/one"; printf '# Gate for X\n' > "$t/one/1.md"; expect "one hold blocks" 1 "$t/one"
mkdir "$t/mix"; echo "# a" > "$t/mix/README.md"; printf '# Gate\n' > "$t/mix/2.md"; expect "README plus hold blocks" 1 "$t/mix"
mkdir "$t/two"; printf '# A\n' > "$t/two/1.md"; printf '# B\n' > "$t/two/2.md"
out=$("$script" "$t/two" 2>&1 >/dev/null); echo "$out" | grep -q "2 open release hold" && echo "ok   counts holds" || { echo "FAIL counts holds"; fail=1; }
exit $fail
