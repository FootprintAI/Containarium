#!/usr/bin/env bash
# Dependency-change gate (#2794, story 3 of #2649).
#
# Usage:
#   scripts/ci/deps-guard.sh [--base <git-ref>] [--report <file>]
#   scripts/ci/deps-guard.sh --self-test
#
# Default mode fails on:
#   - a Go environment that bypasses the checksum database (GONOSUMDB,
#     GOPRIVATE, GONOPROXY or GOINSECURE set; GOSUMDB not sum.golang.org;
#     GOFLAGS without -mod=readonly);
#   - a new or changed `replace` in go.mod compared with the base (an
#     existing, unchanged replace passes);
#   - a new or re-versioned module that sum.golang.org has no record of, or
#     whose go.sum hash disagrees with it.
# The base defaults to HEAD^1: on a pull_request checkout HEAD is GitHub's
# merge commit, whose first parent is the base branch tip; on a push to main
# it is the previous main commit. Hard fail, no label; the only override is a
# code-owner approval of the PR (decision 4 on #2649).
#
# --self-test proves the gate can fail: every fixture under
# internal/depsguard/testdata is run against the live sum.golang.org and
# must exit with the status its `expect` file names, failing fixtures for
# the named rule only; seeded unsafe environments must fail and the pinned
# one must pass.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
fixtures="$repo_root/internal/depsguard/testdata"

build() {
  local out=$1
  (cd "$repo_root" && go build -o "$out" ./cmd/deps-guard)
}

# expect_exit <want> <log> <cmd...>: run cmd, require exit status <want>.
expect_exit() {
  local want=$1 log=$2 rc
  shift 2
  set +e
  "$@" >"$log" 2>&1
  rc=$?
  set -e
  if [[ $rc -ne $want ]]; then
    echo "self-test FAIL: '$*' exited $rc, want $want" >&2
    sed 's/^/    /' "$log" >&2
    return 1
  fi
}

self_test() {
  local d=$work bin dir name want log
  bin="$d/deps-guard"
  build "$bin"

  # Environment rule: one seeded violation per variable, then the pinned env.
  local -a bad_envs=(
    "GOFLAGS=-mod=mod"
    "GOSUMDB=off"
    "GONOSUMDB=example.com"
    "GOPRIVATE=example.com/*"
    "GONOPROXY=example.com"
    "GOINSECURE=example.com"
  )
  # Hermetic: GOENV=off ignores a developer's `go env -w` file, and running
  # from an empty directory with GOTOOLCHAIN=local stops `go env` trying to
  # download a toolchain (which GOSUMDB=off would itself refuse).
  local e
  local -a clean=(env -C "$d" GOENV=off GOTOOLCHAIN=local GOFLAGS=-mod=readonly
    GOSUMDB=sum.golang.org GONOSUMDB= GOPRIVATE= GONOPROXY= GOINSECURE=)
  for e in "${bad_envs[@]}"; do
    expect_exit 1 "$d/env.log" "${clean[@]}" "$e" "$bin" env
    grep -q "^FAIL unsafe-env ${e%%=*}:" "$d/env.log" || {
      echo "self-test FAIL: $e failed, but not on ${e%%=*}" >&2; cat "$d/env.log" >&2; return 1; }
  done
  expect_exit 0 "$d/env.log" "${clean[@]}" "$bin" env

  # go.mod rules, against the live checksum database.
  local pass=0 fail=0
  for dir in "$fixtures"/*/; do
    name=$(basename "$dir")
    want=$(tr -d '[:space:]' <"$dir/expect")
    log="$d/$name.log"
    if [[ $want == pass ]]; then
      expect_exit 0 "$log" "$bin" diff -base "$dir/base.go.mod" -head "$dir/head.go.mod" -gosum "$dir/head.go.sum"
      pass=$((pass + 1))
    else
      expect_exit 1 "$log" "$bin" diff -base "$dir/base.go.mod" -head "$dir/head.go.mod" -gosum "$dir/head.go.sum"
      if grep '^FAIL ' "$log" | grep -qv "^FAIL $want "; then
        echo "self-test FAIL: $name failed on another rule than $want" >&2; cat "$log" >&2; return 1
      fi
      grep -q "^FAIL $want " "$log" || {
        echo "self-test FAIL: $name did not fail on $want" >&2; cat "$log" >&2; return 1; }
      fail=$((fail + 1))
    fi
    echo "  $name: $want ok"
  done
  if [[ $pass -lt 1 || $fail -lt 4 ]]; then
    echo "self-test FAIL: want >= 1 passing and >= 4 failing fixtures, got $pass and $fail" >&2
    return 1
  fi
  echo "self-test ok: ${#bad_envs[@]} unsafe envs and $fail failing fixtures rejected, pinned env and $pass passing fixture accepted"
}

main() {
  local base=HEAD^1 report="" d=$work bin rc_env rc_diff
  while [[ $# -gt 0 ]]; do
    case $1 in
      --self-test) self_test; return ;;
      --base) base=$2; shift 2 ;;
      --report) report=$2; shift 2 ;;
      *) echo "deps-guard.sh: unknown argument $1" >&2; return 2 ;;
    esac
  done
  bin="$d/deps-guard"
  build "$bin"
  if [[ -n $report ]]; then mkdir -p "$(dirname "$report")"; fi

  # A base without go.mod (or an unreadable ref) is an error, not an empty
  # baseline: an empty baseline would pass a replace that is actually new
  # only if the head had none, and fail every existing one otherwise.
  git -C "$repo_root" show "$base:go.mod" >"$d/base.go.mod"

  set +e
  "$bin" env
  rc_env=$?
  (cd "$repo_root" && "$bin" diff -base "$d/base.go.mod" -head go.mod -gosum go.sum ${report:+-report "$report"})
  rc_diff=$?
  set -e
  if [[ $rc_env -eq 2 || $rc_diff -eq 2 ]]; then return 2; fi
  if [[ $rc_env -ne 0 || $rc_diff -ne 0 ]]; then return 1; fi
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
main "$@"
