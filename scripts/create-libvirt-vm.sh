#!/usr/bin/env bash
# Create a libvirt/KVM VM on a Containarium backend (or any
# Ubuntu host with libvirt + virt-install). The VM lives
# OUTSIDE Incus — useful as a sandbox for experiments that
# shouldn't touch production LXC workloads (e.g., eBPF Phase
# 0 validation, nested-virtualization tests, throwaway lab
# environments).
#
# Assumes:
#   - libvirt-daemon-system, qemu-system-x86, virtinst,
#     cloud-image-utils are installed
#   - libvirtd is running, virbr0 is up
#   - the caller has sudo
#
# Examples:
#   # Default sizing (4 vCPU, 8GB RAM, 50GB disk)
#   sudo ./scripts/create-libvirt-vm.sh sandbox-vm
#
#   # Custom sizing
#   sudo ./scripts/create-libvirt-vm.sh cloud-fts-13700k \
#       --vcpus 8 --memory 16384 --disk 100
#
#   # With a specific SSH key (default: first key in ~/.ssh/authorized_keys)
#   sudo ./scripts/create-libvirt-vm.sh testvm --ssh-key /root/.ssh/lab.pub

set -euo pipefail

# --- defaults ---
NAME=""
VCPUS=4
MEMORY=8192            # MB
DISK=50                # GB
OS_VARIANT="ubuntu24.04"
IMG_URL="https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img"
IMG_DIR="/var/lib/libvirt/images"
SSH_KEY_FILE=""
NETWORK="default"
WAIT_FOR_IP=1

usage() {
    sed -n '2,/^$/p' "$0" | sed 's|^# \{0,1\}||'
    cat <<EOF

Usage:
  $(basename "$0") NAME [options]

Options:
  --vcpus N             vCPU count (default $VCPUS)
  --memory MB           Memory in MB (default $MEMORY)
  --disk GB             Root disk in GB (default $DISK)
  --os-variant VARIANT  libvirt os-variant (default $OS_VARIANT)
  --image URL           Override cloud image URL
  --ssh-key PATH        Path to SSH public key file (default: first
                        line of \$HOME/.ssh/authorized_keys; falls back
                        to /root/.ssh/authorized_keys when run via sudo)
  --network NETWORK     libvirt network name (default $NETWORK)
  --no-wait             Skip the wait-for-IP step at the end
  -h, --help            Show this help

Exit 0 on success; 2 on usage error; 1 on operational failure.
EOF
}

# --- arg parse ---
# Handle help / no-args before requiring a positional name.
for arg in "$@"; do
    case "$arg" in
        -h|--help) usage; exit 0 ;;
    esac
done
if [ $# -eq 0 ]; then
    usage
    exit 2
fi
NAME="$1"; shift
if [[ "$NAME" =~ ^- ]]; then
    echo "first argument must be the VM name, not a flag" >&2
    exit 2
fi

while [ $# -gt 0 ]; do
    case "$1" in
        --vcpus)        VCPUS="$2"; shift 2 ;;
        --memory)       MEMORY="$2"; shift 2 ;;
        --disk)         DISK="$2"; shift 2 ;;
        --os-variant)   OS_VARIANT="$2"; shift 2 ;;
        --image)        IMG_URL="$2"; shift 2 ;;
        --ssh-key)      SSH_KEY_FILE="$2"; shift 2 ;;
        --network)      NETWORK="$2"; shift 2 ;;
        --no-wait)      WAIT_FOR_IP=0; shift ;;
        -h|--help)      usage; exit 0 ;;
        *)
            echo "unknown arg: $1" >&2
            exit 2 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "must run as root (libvirt + qemu-img + ZFS-backed image dir all need it)" >&2
    exit 2
fi

# --- preflight ---
for cmd in virsh virt-install qemu-img curl cloud-localds nc; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "missing required command: $cmd" >&2
        echo "install with: apt install -y qemu-system-x86 libvirt-daemon-system libvirt-clients virtinst cloud-image-utils netcat-openbsd" >&2
        exit 2
    fi
done

if ! systemctl is-active --quiet libvirtd; then
    echo "libvirtd is not active — start it with: systemctl enable --now libvirtd" >&2
    exit 2
fi

if [ ! -d "$IMG_DIR" ]; then
    echo "image directory $IMG_DIR does not exist" >&2
    exit 2
fi

if virsh dominfo "$NAME" >/dev/null 2>&1; then
    echo "VM '$NAME' already exists. Delete it first:" >&2
    echo "  virsh destroy $NAME 2>/dev/null; virsh undefine $NAME --remove-all-storage" >&2
    exit 1
fi

# --- resolve SSH key ---
# Order of precedence:
#   1. --ssh-key flag value
#   2. ~/.ssh/authorized_keys of the invoking user (via SUDO_USER's home)
#   3. /root/.ssh/authorized_keys (last resort)
resolve_ssh_key() {
    if [ -n "$SSH_KEY_FILE" ]; then
        if [ ! -r "$SSH_KEY_FILE" ]; then
            echo "--ssh-key $SSH_KEY_FILE not readable" >&2
            exit 2
        fi
        head -1 "$SSH_KEY_FILE"
        return
    fi
    local home
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
        home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    else
        home=$HOME
    fi
    local ak="$home/.ssh/authorized_keys"
    if [ -r "$ak" ] && [ -s "$ak" ]; then
        head -1 "$ak" | cut -d' ' -f1-2
        return
    fi
    if [ -r /root/.ssh/authorized_keys ] && [ -s /root/.ssh/authorized_keys ]; then
        head -1 /root/.ssh/authorized_keys | cut -d' ' -f1-2
        return
    fi
    echo "no SSH key found. Pass --ssh-key /path/to/key.pub or seed ~/.ssh/authorized_keys first." >&2
    exit 2
}
SSH_KEY=$(resolve_ssh_key)

echo "=== Plan ==="
echo "  Name:         $NAME"
echo "  vCPUs:        $VCPUS"
echo "  Memory:       $MEMORY MB"
echo "  Disk:         $DISK GB"
echo "  OS variant:   $OS_VARIANT"
echo "  Image URL:    $IMG_URL"
echo "  Image dir:    $IMG_DIR"
echo "  Network:      $NETWORK"
echo "  SSH key:      $(echo "$SSH_KEY" | cut -c1-50)..."
echo

# --- download cloud image ---
echo "=== 1. cloud image ==="
DISK_PATH="$IMG_DIR/$NAME.qcow2"
if [ -f "$DISK_PATH" ]; then
    echo "  $DISK_PATH already exists; reusing"
else
    TMP_IMG=$(mktemp -p "$IMG_DIR" "$NAME.qcow2.XXXXXX")
    if ! curl -fsSL --progress-bar -o "$TMP_IMG" "$IMG_URL"; then
        rm -f "$TMP_IMG"
        echo "download failed" >&2
        exit 1
    fi
    mv "$TMP_IMG" "$DISK_PATH"
    qemu-img resize "$DISK_PATH" "${DISK}G"
fi
ls -lh "$DISK_PATH"

# --- cloud-init seed ---
echo "=== 2. cloud-init seed ==="
SEED_PATH="$IMG_DIR/$NAME-seed.iso"
USERDATA=$(mktemp -t "$NAME-userdata.XXXXXX")
trap 'rm -f "$USERDATA"' EXIT
cat >"$USERDATA" <<EOF
#cloud-config
hostname: $NAME
ssh_authorized_keys:
  - $SSH_KEY
package_update: false
growpart:
  mode: auto
  devices: ['/']
EOF
cloud-localds "$SEED_PATH" "$USERDATA"
ls -lh "$SEED_PATH"

# --- virt-install ---
echo "=== 3. virt-install ==="
virt-install --name "$NAME" \
    --os-variant "$OS_VARIANT" \
    --memory "$MEMORY" --vcpus "$VCPUS" \
    --disk "path=$DISK_PATH,format=qcow2" \
    --disk "path=$SEED_PATH,device=cdrom" \
    --network "network=$NETWORK" \
    --import --noautoconsole --graphics none

if [ "$WAIT_FOR_IP" -eq 0 ]; then
    echo
    echo "=== DONE (skipped wait-for-IP) ==="
    echo "Check IP later with: virsh domifaddr $NAME"
    exit 0
fi

# --- wait for IP ---
echo "=== 4. wait for IP (cloud-init takes ~30-60s on first boot) ==="
IP=""
for _ in $(seq 1 60); do
    IP=$(virsh domifaddr "$NAME" 2>/dev/null \
        | awk '/ipv4/ {split($4,a,"/"); print a[1]; exit}')
    [ -n "$IP" ] && break
    sleep 2
done

if [ -z "$IP" ]; then
    echo "VM started but did not get an IP within 120s." >&2
    echo "Check with: virsh domifaddr $NAME" >&2
    exit 1
fi

echo "  IP: $IP"

# --- smoke-test SSH port ---
echo "=== 5. smoke-test SSH port ==="
if nc -zv -w 5 "$IP" 22 2>&1 | head -1; then
    :
else
    echo "  SSH port not reachable yet — cloud-init may still be running"
    echo "  Try in a minute: ssh -J $(hostname) ubuntu@$IP"
fi

cat <<EOF

────────────────────────────────────────────────────────────
  ✓ VM '$NAME' READY
────────────────────────────────────────────────────────────
  IP:        $IP
  From host: ssh ubuntu@$IP
  Remote:    ssh -J $(hostname) ubuntu@$IP

  Operate:
    virsh start    $NAME
    virsh shutdown $NAME
    virsh console  $NAME      (^] to detach)
    virsh dominfo  $NAME
    virsh domifaddr $NAME

  Snapshot:
    virsh snapshot-create-as $NAME baseline
    virsh snapshot-revert    $NAME baseline

  Delete (irreversible):
    virsh destroy   $NAME
    virsh undefine  $NAME --remove-all-storage
────────────────────────────────────────────────────────────
EOF
