#!/usr/bin/env bash
# verify-agent-runtime-bundle.sh — guard the release bundle's contract (#748).
#
# Asserts the packaged agent-runtime-bundle ships:
#   1. a compiled dist/engines/<name>.js for EVERY engine in src/engines/<name>.ts
#      (so an engine can't silently drop from a release — e.g. gemini was missing
#      from v0.33.0 because that tag predated the engine; this fails the build if
#      tsc/packaging ever skips one), and
#   2. each runtime SDK as a package.json *dependency* (not devDependency), so the
#      box's `npm ci --omit=dev` actually installs it.
#
# Run by `make bundle-agent-runtime` after packaging, and in the release workflow.
#
# Usage: verify-agent-runtime-bundle.sh <bundle.tar.gz> [src-engines-dir]
set -euo pipefail

BUNDLE="${1:?usage: verify-agent-runtime-bundle.sh <bundle.tar.gz> [src-engines-dir]}"
SRC_ENGINES_DIR="${2:-agent-runtime/src/engines}"
# Runtime SDKs the engines import; each must be a (non-dev) dependency.
REQUIRED_DEPS=(@anthropic-ai/claude-agent-sdk @openai/codex-sdk @google/genai @modelcontextprotocol/sdk)

[ -f "$BUNDLE" ] || { echo "verify-bundle: no such bundle: $BUNDLE" >&2; exit 2; }
[ -d "$SRC_ENGINES_DIR" ] || { echo "verify-bundle: no src engines dir: $SRC_ENGINES_DIR" >&2; exit 2; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
tar -xzf "$BUNDLE" -C "$tmp"

fail=0

# 1. Every source engine has a compiled engine in the bundle.
for ts in "$SRC_ENGINES_DIR"/*.ts; do
  name="$(basename "$ts" .ts)"
  if [ ! -f "$tmp/dist/engines/$name.js" ]; then
    echo "MISSING ENGINE: src has $name.ts but the bundle has no dist/engines/$name.js" >&2
    fail=1
  fi
done

# 2. Every runtime SDK is a (non-dev) dependency, so `npm ci --omit=dev` keeps it.
for dep in "${REQUIRED_DEPS[@]}"; do
  if ! node -e 'const p=require(process.argv[1]); process.exit(((p.dependencies)||{})[process.argv[2]]?0:1)' \
       "$tmp/package.json" "$dep" 2>/dev/null; then
    echo "MISSING DEP: $dep is not in package.json \"dependencies\" (npm ci --omit=dev would skip it)" >&2
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "verify-bundle: FAILED — the agent-runtime bundle is missing an engine or a runtime dep" >&2
  exit 1
fi
echo "verify-bundle: OK — engines: $(cd "$tmp/dist/engines" && ls *.js | tr '\n' ' ')"
