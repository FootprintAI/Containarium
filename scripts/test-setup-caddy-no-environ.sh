#!/usr/bin/env bash
# #3631: setup-caddy.sh must not run Caddy with --environ (it prints the
# credential-bearing environment to the journal) and must not build in the
# predictable /tmp/caddy-build path.
set -u
f="$(dirname "$0")/setup-caddy.sh"
rc=0
if grep -n -- '--environ' "$f"; then echo "FAIL: --environ present in $f"; rc=1; fi
if grep -n '/tmp/caddy-build"' "$f"; then echo "FAIL: predictable /tmp/caddy-build in $f"; rc=1; fi
[ $rc -eq 0 ] && echo "PASS: no --environ, no predictable build dir"
exit $rc
