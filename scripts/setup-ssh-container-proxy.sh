#!/bin/bash
# setup-ssh-container-proxy.sh
#
# Configures the host sshd to proxy SSH sessions into Incus containers.
# When a user with a "containarium user" account SSHes to the host,
# their session is automatically forwarded into their container via incus exec.
#
# This is needed on standalone/tunnel backends (e.g., fts-5900x) where
# the sentinel's sshpiper routes SSH to the host, but the container
# runs its own sshd on the Incus bridge.
#
# How it works:
#   1. A shell wrapper script replaces /usr/sbin/nologin for containarium users
#   2. The wrapper runs: incus exec <username>-container -- su - <username>
#   3. This gives the user an interactive shell inside their container
#
set -e

WRAPPER_SCRIPT="/usr/local/bin/containarium-shell"

echo "==> Setting up SSH container proxy..."

# Create the wrapper script
cat > "$WRAPPER_SCRIPT" << 'SHELLEOF'
#!/bin/bash
# containarium-shell: Proxy SSH sessions into Incus containers
# Installed by setup-ssh-container-proxy.sh

USERNAME="$(whoami)"
CONTAINER="${USERNAME}-container"

# Check if container exists and is running
if ! sudo incus info "$CONTAINER" &>/dev/null; then
    echo "Error: Container $CONTAINER not found" >&2
    exit 1
fi

STATE=$(sudo incus info "$CONTAINER" 2>/dev/null | grep "^Status:" | awk '{print $2}')
if [ "$STATE" != "RUNNING" ]; then
    echo "Error: Container $CONTAINER is not running (status: $STATE)" >&2
    exit 1
fi

# Handle SSH command execution (ssh user@host "command")
if [ -n "$SSH_ORIGINAL_COMMAND" ]; then
    exec sudo incus exec "$CONTAINER" --mode non-interactive -- su - "$USERNAME" -c "$SSH_ORIGINAL_COMMAND"
fi

# Interactive shell
exec sudo incus exec "$CONTAINER" -t -- su -l "$USERNAME"
SHELLEOF

chmod 755 "$WRAPPER_SCRIPT"
echo "  Created $WRAPPER_SCRIPT"

# Add to /etc/shells if not present (required for sshd to accept it)
if ! grep -q "$WRAPPER_SCRIPT" /etc/shells 2>/dev/null; then
    echo "$WRAPPER_SCRIPT" >> /etc/shells
    echo "  Added $WRAPPER_SCRIPT to /etc/shells"
fi

# Allow containarium users to run incus commands via sudo without password
SUDOERS_FILE="/etc/sudoers.d/containarium-incus"
if [ ! -f "$SUDOERS_FILE" ]; then
    cat > "$SUDOERS_FILE" << 'SUDOEOF'
# Allow containarium users to exec into their containers via incus
# This is used by containarium-shell to proxy SSH sessions
ALL ALL=(root) NOPASSWD: /usr/bin/incus exec *, /usr/bin/incus info *
SUDOEOF
    chmod 440 "$SUDOERS_FILE"
    echo "  Created $SUDOERS_FILE (passwordless sudo for incus exec/info)"
fi

echo ""
echo "==> Done! To enable for a user, run:"
echo "    sudo usermod -s $WRAPPER_SCRIPT <username>"
echo ""
echo "  Or to enable for all existing containarium users:"
echo "    getent passwd | grep 'Containarium user' | cut -d: -f1 | while read u; do"
echo "      sudo usermod -s $WRAPPER_SCRIPT \$u"
echo "      echo \"  Updated \$u\""
echo "    done"
