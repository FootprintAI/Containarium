#!/usr/bin/env bash
# add-zabbly-repo.sh — configure the Zabbly Incus stable apt repo on an
# Ubuntu bundle builder, so download-deps.sh can bundle incus, incus-client
# and incus-extra: the packages a connected install gets (hacks/install.sh).
# Ubuntu has no incus-extra, and a stock runner has no Zabbly repo (#3061).
#
# The signing key is pinned by fingerprint: a downloaded key whose only
# primary key is not ZABBLY_KEY_FPR is refused before anything is written.
# Bump the pin only after checking the new fingerprint out of band.
#
# Usage: scripts/bundle/add-zabbly-repo.sh   (uses sudo when not root)
set -euo pipefail

# Zabbly Kernel Builds <info@zabbly.com>, rsa3072, expires 2030-08-17.
ZABBLY_KEY_FPR=4EFC590696CB15B87C73A3AD82CC8797C838DCFD
KEYRING=/usr/share/keyrings/zabbly-incus.gpg
SOURCES=/etc/apt/sources.list.d/zabbly-incus-stable.list

SUDO=""
[ "$(id -u)" -eq 0 ] || SUDO=sudo

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -m 700 "$work/gnupg"

curl -fsSL --retry 3 -o "$work/key.asc" https://pkgs.zabbly.com/key.asc

fprs="$(GNUPGHOME="$work/gnupg" gpg --batch --show-keys --with-colons "$work/key.asc" \
  | awk -F: '$1 == "pub" { want = 1; next } want && $1 == "fpr" { print $10; want = 0 }')"
if [ "$fprs" != "$ZABBLY_KEY_FPR" ]; then
  echo "add-zabbly-repo: key fingerprint mismatch" >&2
  echo "  want: $ZABBLY_KEY_FPR" >&2
  echo "  got:  ${fprs:-<none>}" >&2
  exit 1
fi

GNUPGHOME="$work/gnupg" gpg --batch --dearmor -o "$work/zabbly-incus.gpg" "$work/key.asc"
codename="$(. /etc/os-release && echo "$VERSION_CODENAME")"
$SUDO install -m 0644 "$work/zabbly-incus.gpg" "$KEYRING"
echo "deb [signed-by=$KEYRING] https://pkgs.zabbly.com/incus/stable $codename main" \
  | $SUDO tee "$SOURCES" >/dev/null
$SUDO apt-get update
echo "add-zabbly-repo: Zabbly Incus stable configured for $codename (key $ZABBLY_KEY_FPR)"
