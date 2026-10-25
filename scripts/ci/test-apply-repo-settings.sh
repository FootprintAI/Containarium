#!/usr/bin/env bash
# Tests for scripts/admin/apply-repo-settings.sh against a fake gh:
#   - dry run (the default) performs no write call;
#   - --apply keeps the required status-check contexts, app ids, strict and
#     enforce_admins in the protection body it sends;
#   - --apply fails when the read-back does not match (seeded negative);
#   - the allow-list check fails on a seeded unlisted action.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
script=$here/../admin/apply-repo-settings.sh
fix=$here/testdata/repo-settings
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
fail=0
t() { echo "FAIL: $*"; fail=1; }

run() { # run NAME FIXDIR args...
  local name=$1 dir=$2; shift 2
  rm -f "$tmp/$name.log" "$tmp/$name.log.body" "$tmp/$name.log.wrote"
  FAKE_DIR=$dir FAKE_LOG=$tmp/$name.log GH=$here/fake-gh-repo-settings.sh \
    "$script" "$@" >"$tmp/$name.out" 2>&1
}

# 1. dry run: exit 0, no write calls, says so
run dry "$fix" || t "dry run exited non-zero"
if grep -qE '^(PUT|PATCH|POST|DELETE) ' "$tmp/dry.log"; then t "dry run wrote"; fi
grep -q 'DRY RUN' "$tmp/dry.out" || t "dry run did not say so"

# 2. --apply: succeeds, protection body preserves contexts/app ids/strict/enforce_admins
run apply "$fix" --apply || { t "--apply failed"; cat "$tmp/apply.out"; }
body=$(awk '/^== PUT .*branches\/main\/protection/{f=1;next} /^== /{f=0} f' "$tmp/apply.log.body")
for want in '"context":"Unit + default e2e"' '"context":"Trivy"' '"app_id":15368' '"app_id":57789' \
            '"strict":true' '"enforce_admins":true' '"require_code_owner_reviews":true' \
            '"dismiss_stale_reviews":true' '"required_conversation_resolution":true'; do
  grep -qF "$want" <<<"$(jq -c . <<<"$body")" || t "protection body lacks $want"
done
grep -q 'PUT repos/.*/actions/permissions/workflow' "$tmp/apply.log" || t "no token-permission write"
grep -q 'PUT repos/.*/automated-security-fixes' "$tmp/apply.log" || t "no dependabot write"

# 3. seeded negative: read-back that does not match must fail --apply
neg=$tmp/neg; cp -r "$fix" "$neg"; cp "$neg/before/workflow.json" "$neg/after/workflow.json"
if run negative "$neg" --apply; then t "mismatching read-back was accepted"; fi
grep -q MISMATCH "$tmp/negative.out" || t "mismatch not reported"

# 4. seeded negative: a dropped required context must fail --apply
neg2=$tmp/neg2; cp -r "$fix" "$neg2"
jq 'del(.required_status_checks.checks[1])' "$fix/after/protection.json" >"$neg2/after/protection.json"
if run dropped "$neg2" --apply; then t "dropped required context was accepted"; fi

# 5. allow-list check: seeded unlisted action fails, listed one passes
mkdir -p "$tmp/gh/workflows"
printf 'jobs:\n  a:\n    steps:\n      - uses: docker/login-action@%040d # v1\n      - uses: actions/checkout@%040d\n' 1 2 >"$tmp/gh/workflows/ok.yml"
"$script" --check-allow-list "$tmp/gh" >/dev/null || t "listed actions rejected"
printf 'jobs:\n  a:\n    steps:\n      - uses: evil/thing@%040d\n' 3 >"$tmp/gh/workflows/bad.yml"
if "$script" --check-allow-list "$tmp/gh" >/dev/null; then t "unlisted action accepted"; fi
"$script" --check-allow-list "$here/../../.github" || t "real .github not covered by allow-list"

[[ $fail -eq 0 ]] && echo "all repo-settings script tests passed"
exit "$fail"
