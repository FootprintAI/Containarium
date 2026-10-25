#!/usr/bin/env bash
# check-bundle-content.sh — assert what a built air-gapped bundle tarball
# contains, from its `tar tzf` listing (#3061). The release workflow runs it
# after build-bundle.sh and before anything is uploaded; a release once
# shipped an empty apt/ and an empty images/ from a green job.
#
# Usage: scripts/bundle/check-bundle-content.sh <bundle.tar.gz>
#
# Fails unless the tarball has exactly one top-level directory holding:
#   bin/{containariumd,mcp-server,agent-box}, offline-install.sh, VERSION,
#   CHECKSUMS.sha256, toolchains/go*.tar.gz, and apt/<pkg>_*.deb for every
#   package in REQUIRED_DEBS;
# and no images/ entry (nothing produces the base image yet, see
# scripts/bundle/README.md).
#
# Env: REQUIRED_DEBS  space-separated package names (default when unset: the
#                     packages behind the installer's critical commands; set
#                     it empty to require only "at least one .deb").
set -euo pipefail

REQUIRED_DEBS="${REQUIRED_DEBS-incus incus-client incus-extra zfsutils-linux jq curl}"

tarball="${1:?usage: check-bundle-content.sh <bundle.tar.gz>}"
if [ ! -f "$tarball" ]; then
  echo "check-bundle-content: no such file: $tarball" >&2
  exit 1
fi

listing="$(mktemp)"
trap 'rm -f "$listing"' EXIT
if ! tar tzf "$tarball" >"$listing"; then
  echo "check-bundle-content: tar tzf failed on $tarball" >&2
  exit 1
fi

errors=0
err() { echo "check-bundle-content: $*" >&2; errors=$((errors + 1)); }

mapfile -t tops < <(sed -e 's|^\./||' -e 's|/.*||' "$listing" | grep -v '^$' | sort -u)
if [ "${#tops[@]}" -ne 1 ]; then
  err "want one top-level directory, got ${#tops[@]}: ${tops[*]}"
  exit 1
fi
top="${tops[0]}"
# Paths relative to the top-level directory, without a trailing slash.
mapfile -t paths < <(sed -e 's|^\./||' -e "s|^$top/||" -e 's|/$||' "$listing")

has() { printf '%s\n' "${paths[@]}" | grep -qE "$1"; }

for f in bin/containariumd bin/mcp-server bin/agent-box offline-install.sh VERSION CHECKSUMS.sha256; do
  has "^${f//./\\.}\$" || err "missing $f"
done
has '^toolchains/go[^/]*\.tar\.gz$' || err "missing toolchains/go*.tar.gz"

ndebs="$(printf '%s\n' "${paths[@]}" | grep -cE '^apt/[^/]+\.deb$' || true)"
if [ "$ndebs" -eq 0 ]; then
  err "apt/ holds no .deb"
fi
for pkg in $REQUIRED_DEBS; do
  has "^apt/${pkg//./\\.}_[^/]+\\.deb\$" || err "missing apt/${pkg}_*.deb"
done

if has '^images(/|$)'; then
  err "ships images/, which nothing populates"
fi

if [ "$errors" -gt 0 ]; then
  echo "check-bundle-content: $tarball FAILED ($errors problem(s))" >&2
  exit 1
fi
echo "check-bundle-content: $tarball OK ($top: $ndebs .deb files)"
