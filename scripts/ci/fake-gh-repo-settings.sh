#!/usr/bin/env bash
# Fake `gh` for scripts/ci/test-apply-repo-settings.sh. Serves canned JSON from
# $FAKE_DIR/before until a write arrives, then from $FAKE_DIR/after, and logs
# every call to $FAKE_LOG as "METHOD path" (bodies to $FAKE_LOG.body).
set -euo pipefail
[[ "$1" == api ]] || exit 2
shift
method=GET
if [[ "$1" == -X ]]; then method=$2; shift 2; fi
path=$1
if [[ "$method" != GET ]]; then
  echo "$method $path" >>"$FAKE_LOG"
  if [[ "${2:-}" == --input ]]; then
    { echo "== $method $path"; cat; echo; } >>"$FAKE_LOG.body"
  fi
  touch "$FAKE_LOG.wrote"
  exit 0
fi
echo "GET $path" >>"$FAKE_LOG"
state=before; [[ -e "$FAKE_LOG.wrote" ]] && state=after
d=$FAKE_DIR/$state
case "$path" in
  */branches/*/protection) cat "$d/protection.json" ;;
  */actions/permissions/selected-actions) cat "$d/selected.json" ;;
  */actions/permissions/workflow) cat "$d/workflow.json" ;;
  */actions/permissions) cat "$d/permissions.json" ;;
  */automated-security-fixes) cat "$d/automated.json" ;;
  */vulnerability-alerts) [[ $state == after ]] || exit 1 ;;
  repos/*) cat "$d/repo.json" ;;
  *) echo "fake gh: unexpected $path" >&2; exit 2 ;;
esac
