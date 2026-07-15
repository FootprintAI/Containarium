#!/bin/sh
# containarium-sshpiper entrypoint: run sshpiperd with the plugin named by
# $PLUGIN (default kubernetes — the K8s backend's Pipe-CRD routing).
# Mirrors the upstream image's contract so deployments written against
# farmer1992/sshpiperd (PLUGIN env + SSHPIPERD_* env) work unchanged.
set -eu

PLUGIN="${PLUGIN:-kubernetes}"
PLUGIN_BIN="/sshpiperd/plugins/${PLUGIN}"
if [ ! -x "$PLUGIN_BIN" ]; then
  echo "unknown sshpiper plugin '${PLUGIN}'; available:" >&2
  ls /sshpiperd/plugins >&2
  exit 1
fi

exec /sshpiperd/sshpiperd "$PLUGIN_BIN" "$@"
