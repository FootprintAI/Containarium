#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/buf-version.env"
binary="${BUF:-buf}"
if ! actual="$("$binary" --version 2>/dev/null)" || [[ "$actual" != "$BUF_VERSION" ]]; then
  echo "This repository requires buf $BUF_VERSION; install with scripts/install-buf.sh <path-to-buf>, then set BUF=<path-to-buf>." >&2
  exit 1
fi
exec "$binary" "$@"
