#!/usr/bin/env bash
# Published release verification on a fresh Ubuntu 24.04 VM with no NIC.
# Host needs QEMU, genisoimage, curl, git and sha256sum. No root required
# when /dev/kvm is readable/writable; otherwise use sudo or QEMU TCG.
# Evidence is retained in OUTPUT_DIR; only its scratch disks are ephemeral.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
tag=${RELEASE_TAG:-v0.121.0}
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Invalid RELEASE_TAG' >&2; exit 1; }
out=${OUTPUT_DIR:?Set OUTPUT_DIR to an empty evidence directory}
mkdir -p "$out"
out=$(cd "$out" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fetch() { curl -fsSL --retry 3 --connect-timeout 30 --max-time 300 "$1" -o "$2"; }

git -C "$here" fetch --depth=1 --no-tags https://github.com/FootprintAI/Containarium "refs/tags/$tag"
commit=$(git -C "$here" rev-parse 'FETCH_HEAD^{commit}')
file="containarium-bundle-${tag}-linux-amd64.tar.gz"
release="https://github.com/FootprintAI/Containarium/releases/download/$tag"
mkdir "$work/payload" "$work/seed"
echo "Downloading published bundle: $release/$file"
fetch "$release/$file" "$work/payload/$file"
fetch "$release/$file.sha256" "$out/bundle.sha256"
(cd "$work/payload" && sha256sum -c "$out/bundle.sha256")
bundle_sha=$(sha256sum "$work/payload/$file" | cut -d ' ' -f1)

# Dated official image; checksum and URL are saved alongside the VM log.
image=ubuntu-24.04-minimal-cloudimg-amd64.img
image_url=https://cloud-images.ubuntu.com/minimal/releases/noble/release-20261027
echo "Downloading official Ubuntu image: $image_url/$image"
fetch "$image_url/$image" "$work/$image"
fetch "$image_url/SHA256SUMS" "$work/SHA256SUMS"
awk -v file="$image" '$2 == "*" file || $2 == file {print}' "$work/SHA256SUMS" >"$out/ubuntu.sha256"
[ -s "$out/ubuntu.sha256" ]
(cd "$work" && sha256sum -c "$out/ubuntu.sha256")
{
  printf 'Release: %s\nCommit: %s\nBundle SHA256: %s\n' "$tag" "$commit" "$bundle_sha"
  printf 'Ubuntu image: %s/%s\n' "$image_url" "$image"
  cat "$out/ubuntu.sha256"
  printf 'Harness commit: %s\n' "$(git -C "$here" rev-parse HEAD)"
} | tee "$out/identity.txt"

cp "$here/offline-install-guest.sh" "$work/payload/guest.sh"
cat >"$work/seed/meta-data" <<EOF
instance-id: offline-install-${tag}
local-hostname: offline-install
EOF
printf 'version: 2\nethernets: {}\n' >"$work/seed/network-config"
cat >"$work/seed/user-data" <<EOF
#!/bin/bash
set -euo pipefail
systemctl mask --now serial-getty@ttyS0.service
exec > /dev/ttyS0 2>&1
trap 'rc=\$?; set +e; echo "GUEST_EXIT=\$rc"; sync; poweroff -f' EXIT
mkdir -p /payload
mount -L OFFLINE /payload
bash -x /payload/guest.sh '$tag' '$commit' '$bundle_sha'
EOF
genisoimage -quiet -output "$work/seed.iso" -volid cidata -joliet -rock "$work/seed"
genisoimage -quiet -output "$work/payload.iso" -volid OFFLINE -joliet -rock "$work/payload"
qemu-img create -q -f qcow2 -F qcow2 -b "$work/$image" "$work/guest.qcow2" 16G
accel=( -accel tcg -cpu max )
if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then accel=( -accel kvm -cpu host ); fi
printf 'QEMU acceleration: %s\nNetwork: -nic none\n' "${accel[*]}" | tee -a "$out/identity.txt"
# Serial output is the evidence channel. No SSH, shared host directory,
# network backend or guest credentials. Timeout preserves the raw log.
set +e
timeout --signal=TERM --kill-after=20s 30m qemu-system-x86_64 \
  "${accel[@]}" -m 4096 -smp 2 -display none -monitor none -serial stdio \
  -nic none -no-reboot \
  -drive "file=$work/guest.qcow2,format=qcow2,if=virtio" \
  -drive "file=$work/seed.iso,format=raw,media=cdrom,readonly=on" \
  -drive "file=$work/payload.iso,format=raw,media=cdrom,readonly=on" \
  2>&1 | tee "$out/serial.log"
rc=${PIPESTATUS[0]}
set -e
[ "$rc" -eq 0 ] || { echo "FAIL: QEMU exited $rc"; exit 1; }
tr -d '\r' <"$out/serial.log" >"$work/serial.txt"
grep -Fx "OFFLINE_INSTALL_PASS $tag $commit $bundle_sha" "$work/serial.txt"
grep -Fx 'GUEST_EXIT=0' "$work/serial.txt"
echo "Verified $tag @ $commit: clean Ubuntu 24.04, no guest NIC, real offline installation and empty-apt rejection." | tee "$out/result.txt"
