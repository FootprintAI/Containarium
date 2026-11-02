#!/usr/bin/env bash
# Tests for scripts/ci/validate-release-version.sh (#3344): accepted versions
# pass, and shell/sed/newline injection payloads are refused.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
script=${VALIDATOR:-$here/validate-release-version.sh}
fail=0

ok()  { "$script" "$1" >/dev/null 2>&1 || { echo "FAIL: should accept: $(printf %q "$1")"; fail=1; }; }
bad() { if "$script" "$1" >/dev/null 2>&1; then echo "FAIL: should refuse: $(printf %q "$1")"; fail=1; fi; }

ok 0.61.0
ok 1.2.3
ok 0.101.0-rc.1
ok 0.0.0-dryrun
ok 10.20.30-alpha-1.2

bad ''
bad v0.61.0
bad 1.0
bad 1.0.0.0
bad 01.0.0
bad '1.0.0; echo x'
# shellcheck disable=SC2016
bad '1.0.0$(id)'
# shellcheck disable=SC2016
bad '1.0.0`id`'
bad '1.0.0/../x'
bad '1.0.0"/;s/a/b/'
bad '1.0.0 '
bad '1.0.0+build'
bad '1.0.0-'
bad $'1.0.0\nVERSION=evil'
bad $'1.0.0\r\nx=y'
bad $'1.0.0\n'
bad $'evil\n1.0.0'

[ "$fail" = 0 ] && echo "ok: release version validation"
exit "$fail"
