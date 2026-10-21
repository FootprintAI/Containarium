#!/usr/bin/env bash
# Prints "true" when the diff BASE..HEAD is a release cut and nothing else,
# "false" otherwise. Reasons go to stderr.
#
#   scripts/ci/release-only-diff.sh <base> <head>
#   scripts/ci/release-only-diff.sh --self-test
#
# A release cut (docs/RELEASE-PROCESS.md) changes exactly two files:
# CHANGELOG.md, and the `Version = "..."` constant in pkg/version/version.go.
# Such a diff cannot change what the test, lint and SAST jobs measure, so
# those jobs may skip on it — but only when BASE itself already passed them,
# which the caller (.github/actions/release-only-diff) checks separately.
#
# Deliberately narrow. Anything else, including the sdlc-skills lock that a
# cut sometimes bumps, any other line in version.go, a rename or an empty
# diff, prints "false" and the caller runs the full suite.
set -euo pipefail

release_only() {
  local base="$1" head="$2" files f other

  files="$(git diff --no-renames --name-only "$base" "$head")"
  if [ -z "$files" ]; then
    echo "empty diff" >&2
    echo false
    return
  fi

  while IFS= read -r f; do
    case "$f" in
      CHANGELOG.md | pkg/version/version.go) ;;
      *)
        echo "touches $f" >&2
        echo false
        return
        ;;
    esac
  done <<<"$files"

  # Every changed line in version.go must be the Version constant.
  other="$(git diff --no-renames -U0 "$base" "$head" -- pkg/version/version.go \
    | grep -E '^[+-]' \
    | grep -vE '^(\+\+\+|---) ' \
    | grep -vE '^[+-][[:space:]]*Version[[:space:]]*=[[:space:]]*"[^"]*"[[:space:]]*$' || true)"
  if [ -n "$other" ]; then
    echo "pkg/version/version.go changes more than the Version constant" >&2
    echo false
    return
  fi

  echo "release-only diff: $(tr '\n' ' ' <<<"$files")" >&2
  echo true
}

self_test() {
  local dir fails=0 base
  dir="$(mktemp -d)"
  trap 'rm -rf "$dir"' RETURN
  git -C "$dir" init -q
  git -C "$dir" config user.email t@example.com
  git -C "$dir" config user.name t
  mkdir -p "$dir/pkg/version" "$dir/internal"
  printf '# Changelog\n\n## [Unreleased]\n' >"$dir/CHANGELOG.md"
  printf 'package version\n\nvar (\n\tVersion = "0.1.0"\n\tGitCommit = "unknown"\n)\n' >"$dir/pkg/version/version.go"
  printf 'package internal\n' >"$dir/internal/x.go"
  git -C "$dir" add -A && git -C "$dir" commit -qm base
  base="$(git -C "$dir" rev-parse HEAD)"

  # expect <want> <name> <mutation>: applies the mutation on top of base.
  expect() {
    local want="$1" name="$2" got
    git -C "$dir" checkout -q --detach "$base"
    (cd "$dir" && eval "$3")
    git -C "$dir" add -A
    git -C "$dir" commit -qm "$name" --allow-empty
    got="$(cd "$dir" && release_only "$base" HEAD 2>/dev/null)"
    if [ "$got" = "$want" ]; then
      echo "ok   $name"
    else
      echo "FAIL $name: want $want, got $got"
      fails=$((fails + 1))
    fi
  }

  expect true  "changelog only"          "printf '\n## [0.2.0]\n- x\n' >>CHANGELOG.md"
  expect true  "changelog + version"     "printf '\n## [0.2.0]\n' >>CHANGELOG.md; sed -i.bak 's/0.1.0/0.2.0/' pkg/version/version.go; rm pkg/version/version.go.bak"
  expect false "empty diff"              ":"
  expect false "other file"              "printf '// y\n' >>internal/x.go; printf 'x\n' >>CHANGELOG.md"
  expect false "other version.go line"   "sed -i.bak 's/\"unknown\"/\"abc\"/' pkg/version/version.go; rm pkg/version/version.go.bak"
  expect false "version + other line"    "sed -i.bak 's/0.1.0/0.2.0/; s/\"unknown\"/\"abc\"/' pkg/version/version.go; rm pkg/version/version.go.bak"
  expect false "new line beside Version" "printf 'package version\n\nvar (\n\tVersion = \"0.1.0\"\n\tExtra = 1\n\tGitCommit = \"unknown\"\n)\n' >pkg/version/version.go"
  expect false "rename into allowlist"   "git rm -q --cached internal/x.go; mv internal/x.go CHANGELOG.md"

  [ "$fails" = 0 ] || { echo "$fails self-test case(s) failed" >&2; return 1; }
  echo "all self-test cases passed"
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
elif [ "$#" -eq 2 ]; then
  release_only "$1" "$2"
else
  echo "usage: $0 <base> <head> | --self-test" >&2
  exit 2
fi
