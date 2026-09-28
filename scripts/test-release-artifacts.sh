#!/usr/bin/env bash
# Release-artifact gate for the CLI client/server split, Rollout Phase 2
# (#1784, docs/architecture/cli-client-server-split.md).
#
# Inspects the BUILT release binaries, not the Makefile text: a recipe that
# says `-tags containarium_client` but builds the wrong package, or a
# regression back to "copy the daemon under the client's name", fails here.
#
#   containarium-{linux-amd64,darwin-amd64,darwin-arm64,windows-amd64.exe}
#     must be the CLIENT build: built with -tags=containarium_client and
#     CGO_ENABLED=0 (both read back from the binary's own build info via
#     `go version -m`), and must contain no symbols from the daemon-only
#     packages that scripts/test-cli-split-deps.sh forbids.
#   containariumd-{linux-amd64,darwin-amd64,darwin-arm64}
#     must be the SERVER build: not client-tagged, and must still contain
#     internal/server symbols. This is the positive control: if the symbol
#     check could not see anything (stripped binary, broken `go tool nm`),
#     the daemon check fails instead of the client check passing vacuously.
#   No containariumd-windows-* artifact: the daemon never ships there.
#   containarium-<plat> and containariumd-<plat> must differ (sha256). This
#   replaces #1798's Phase 1 byte-equality check, which is false by design
#   once containarium-* is the client.
#
# Usage: scripts/test-release-artifacts.sh [BUILD_DIR]   (default: bin)
set -uo pipefail

BUILD_DIR="${1:-bin}"
CLIENT=containarium
DAEMON=containariumd

# Same list as scripts/test-cli-split-deps.sh, matched as symbol prefixes.
FORBIDDEN=(
  "github.com/footprintai/containarium/pkg/core/container"
  "github.com/footprintai/containarium/internal/server"
  "github.com/footprintai/containarium/internal/sentinel"
  "github.com/footprintai/containarium/internal/hosting"
  "github.com/footprintai/containarium/internal/hypervisor"
  "github.com/jackc/pgx"
)
SERVER_MARKER="github.com/footprintai/containarium/internal/server"

CLIENT_ARTIFACTS=(
  "$CLIENT-linux-amd64"
  "$CLIENT-darwin-amd64"
  "$CLIENT-darwin-arm64"
  "$CLIENT-windows-amd64.exe"
)
DAEMON_PLATFORMS=(linux-amd64 darwin-amd64 darwin-arm64)

fail=0
pass() { echo "PASS  $*"; }
bad()  { echo "FAIL  $*"; fail=1; }

# build_setting FILE KEY -> value of "build KEY=value" from `go version -m`.
build_setting() {
  go version -m "$1" 2>/dev/null | awk -v k="$2" '$1 == "build" { split($2, kv, "="); if (kv[1] == k) { sub(/^[^=]*=/, "", $2); print $2 } }'
}

# symbols_file FILE -> path to a temp file holding `go tool nm` output.
symbols_file() {
  local out
  out="$(mktemp)"
  go tool nm "$1" >"$out" 2>/dev/null || true
  echo "$out"
}

# has_pkg_symbols SYMFILE PKG -> 0 if any symbol belongs to PKG or a subpackage.
has_pkg_symbols() {
  grep -qE "[[:space:]]$(printf '%s' "$2" | sed 's/[.]/\\./g')[./]" "$1"
}

tmpfiles=()
cleanup() { rm -f "${tmpfiles[@]}"; }
trap cleanup EXIT

for a in "${CLIENT_ARTIFACTS[@]}"; do
  f="$BUILD_DIR/$a"
  if [ ! -f "$f" ]; then bad "$a missing from $BUILD_DIR"; continue; fi

  tags="$(build_setting "$f" -tags)"
  case ",$tags," in
    *,containarium_client,*) pass "$a built with -tags=$tags" ;;
    *) bad "$a is not the client build (-tags='$tags', want containarium_client)" ;;
  esac

  cgo="$(build_setting "$f" CGO_ENABLED)"
  if [ "$cgo" = "0" ]; then pass "$a CGO_ENABLED=0 (static)"; else bad "$a CGO_ENABLED='$cgo', want 0"; fi

  syms="$(symbols_file "$f")"; tmpfiles+=("$syms")
  if [ ! -s "$syms" ]; then bad "$a: 'go tool nm' returned no symbols"; continue; fi
  for pkg in "${FORBIDDEN[@]}"; do
    if has_pkg_symbols "$syms" "$pkg"; then bad "$a links $pkg"; fi
  done
done

for p in "${DAEMON_PLATFORMS[@]}"; do
  f="$BUILD_DIR/$DAEMON-$p"
  if [ ! -f "$f" ]; then bad "$DAEMON-$p missing from $BUILD_DIR"; continue; fi

  tags="$(build_setting "$f" -tags)"
  case ",$tags," in
    *,containarium_client,*) bad "$DAEMON-$p was built with the client tag (-tags=$tags)" ;;
    *) pass "$DAEMON-$p is not client-tagged (-tags='$tags')" ;;
  esac

  syms="$(symbols_file "$f")"; tmpfiles+=("$syms")
  if has_pkg_symbols "$syms" "$SERVER_MARKER"; then
    pass "$DAEMON-$p links $SERVER_MARKER (symbol check is live)"
  else
    bad "$DAEMON-$p has no $SERVER_MARKER symbols — not the server build, or the symbol check is blind"
  fi

  c="$BUILD_DIR/$CLIENT-$p"
  if [ -f "$c" ]; then
    a_sum="$(sha256sum "$c" 2>/dev/null || shasum -a 256 "$c")"; a_sum="${a_sum%% *}"
    b_sum="$(sha256sum "$f" 2>/dev/null || shasum -a 256 "$f")"; b_sum="${b_sum%% *}"
    if [ "$a_sum" = "$b_sum" ]; then
      bad "$CLIENT-$p is byte-identical to $DAEMON-$p ($a_sum) — still the Phase 1 mirror"
    else
      pass "$CLIENT-$p differs from $DAEMON-$p"
    fi
  fi
done

for f in "$BUILD_DIR/$DAEMON"-windows-*; do
  [ -e "$f" ] && bad "$(basename "$f") exists — the daemon never ships for windows"
done

if [ "$fail" -eq 0 ]; then
  echo "PASS  release artifacts: containarium-* is the client build, containariumd-* is the server build"
fi
exit $fail
