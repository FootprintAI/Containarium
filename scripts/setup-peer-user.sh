#!/bin/bash
#
# Setup a jump server user on a peer node that proxies SSH into an Incus container.
#
# Usage: sudo bash setup-peer-user.sh <username> [sentinel_pubkey]
#
# This creates:
#   1. containarium-shell script (if not already installed)
#   2. Host-level user with containarium-shell as login shell
#   3. Authorized keys (sentinel upstream key + user key from container)
#   4. Sudoers entry for passwordless incus access
#

set -euo pipefail

USERNAME="${1:-}"
# Default sentinel pubkey: empty. Operators MUST pass the second arg
# (or set SENTINEL_PUBKEY env). Pubkeys are not secrets, but the
# `comment` field bundled with them — `<user>@<sentinel-host>` —
# leaks the sentinel hostname per CLAUDE.md.
SENTINEL_PUBKEY="${2:-${SENTINEL_PUBKEY:-}}"

if [[ -z "$USERNAME" ]]; then
    echo "Usage: sudo $0 <username> [sentinel_pubkey]"
    echo "Example: sudo $0 <tenant-username>"
    exit 1
fi

if [[ -z "$SENTINEL_PUBKEY" ]]; then
    echo "Error: sentinel pubkey required — pass as 2nd arg or via SENTINEL_PUBKEY env"
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo "Error: must run as root (use sudo)"
    exit 1
fi

CONTAINER="${USERNAME}-container"

# 1. Install containarium-shell if missing
if [[ ! -f /usr/local/bin/containarium-shell ]]; then
    echo "==> Installing containarium-shell..."
    cat > /usr/local/bin/containarium-shell << 'SHELL'
#!/bin/bash
# containarium-shell: Proxy SSH sessions into Incus containers
USERNAME="$(whoami)"
CONTAINER="${USERNAME}-container"

# Collaborator accounts use the pattern <owner>-container-<collaborator>.
# If the derived container doesn't exist, try stripping the collaborator suffix.
if ! sudo incus info "$CONTAINER" &>/dev/null; then
    STRIPPED="${USERNAME%-*}"
    if [ "$STRIPPED" != "$USERNAME" ] && sudo incus info "$STRIPPED" &>/dev/null; then
        CONTAINER="$STRIPPED"
    fi
fi

if ! sudo incus info "$CONTAINER" &>/dev/null; then
    echo "Error: Container $CONTAINER not found" >&2
    exit 1
fi

STATE=$(sudo incus info "$CONTAINER" 2>/dev/null | grep "^Status:" | awk '{print $2}')
if [ "$STATE" != "RUNNING" ]; then
    echo "Error: Container $CONTAINER is not running (status: $STATE)" >&2
    exit 1
fi

COMMAND="${SSH_ORIGINAL_COMMAND}"
if [ -z "$COMMAND" ] && [ "$1" = "-c" ]; then
    COMMAND="$2"
fi

if [ -n "$COMMAND" ]; then
    exec sudo incus exec "$CONTAINER" --mode non-interactive -- su - "$USERNAME" -c "$COMMAND"
fi

exec sudo incus exec "$CONTAINER" -t -- su -l "$USERNAME"
SHELL
    chmod +x /usr/local/bin/containarium-shell
    echo "  containarium-shell installed"
else
    echo "==> containarium-shell already installed"
fi

# 2. Create or update host user
if id "$USERNAME" &>/dev/null; then
    echo "==> User $USERNAME exists, updating shell..."
    usermod -s /usr/local/bin/containarium-shell "$USERNAME"
else
    echo "==> Creating user $USERNAME..."
    useradd -m -s /usr/local/bin/containarium-shell "$USERNAME"
fi

# Unlock the account (useradd creates locked accounts by default, sshd rejects them)
passwd -d "$USERNAME" >/dev/null 2>&1
chmod 755 "/home/$USERNAME"

# 3. Setup authorized_keys
echo "==> Setting up SSH keys..."
mkdir -p "/home/$USERNAME/.ssh"

# Start with sentinel upstream key
echo "$SENTINEL_PUBKEY" > "/home/$USERNAME/.ssh/authorized_keys"

# Try to copy user's SSH key from the container
if incus info "$CONTAINER" &>/dev/null; then
    CONTAINER_KEY=$(incus exec "$CONTAINER" -- cat "/home/$USERNAME/.ssh/authorized_keys" 2>/dev/null | grep -v "sentinel" || true)
    if [[ -n "$CONTAINER_KEY" ]]; then
        echo "$CONTAINER_KEY" >> "/home/$USERNAME/.ssh/authorized_keys"
        echo "  Added user key from container"
    else
        echo "  Warning: no user SSH key found in container, add manually later"
    fi
fi

chown -R "$USERNAME:$USERNAME" "/home/$USERNAME/.ssh"
chmod 700 "/home/$USERNAME/.ssh"
chmod 600 "/home/$USERNAME/.ssh/authorized_keys"

# 4. Sudoers for incus access
echo "==> Setting up sudoers..."
echo "$USERNAME ALL=(root) NOPASSWD: /usr/bin/incus" > "/etc/sudoers.d/containarium-$USERNAME"
chmod 440 "/etc/sudoers.d/containarium-$USERNAME"

echo ""
echo "=== Done ==="
echo "  User: $USERNAME"
echo "  Shell: /usr/local/bin/containarium-shell"
echo "  Container: $CONTAINER"
echo "  Keys: $(wc -l < /home/$USERNAME/.ssh/authorized_keys) entries"
