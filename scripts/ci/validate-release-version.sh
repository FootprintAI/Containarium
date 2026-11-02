#!/usr/bin/env bash
# Validate a release version before any workflow uses it (#3344, regression
# class of #1602). The release workflows take the version from a tag name or a
# workflow_dispatch input, then write it to GITHUB_OUTPUT and hand it to sed,
# helm, docker tags and the like. An unvalidated value with a newline or shell
# or sed metacharacters can forge extra GITHUB_OUTPUT keys or alter those
# commands, so the first step of each workflow runs this and fails otherwise.
#
# Accepted: MAJOR.MINOR.PATCH with an optional pre-release suffix, no "v"
# prefix and no build metadata (0.61.0, 0.101.0-rc.1, 0.0.0-dryrun).
#
# Usage:
#   scripts/ci/validate-release-version.sh VERSION   # exit 0 if valid, 1 if not
#   source scripts/ci/validate-release-version.sh    # defines is_release_version
is_release_version() {
  local v=${1-}
  # A newline would pass a line-oriented check; refuse it explicitly.
  case "$v" in *$'\n'*|*$'\r'*) return 1 ;; esac
  [[ "$v" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$ ]]
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  if is_release_version "${1-}"; then
    exit 0
  fi
  echo "::error::release version is not MAJOR.MINOR.PATCH[-prerelease] (no v prefix): refusing to use it" >&2
  exit 1
fi
