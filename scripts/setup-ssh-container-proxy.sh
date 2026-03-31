#!/bin/bash
# setup-ssh-container-proxy.sh
#
# Configures the host sshd to proxy SSH sessions into Incus containers.
# When a user with a "containarium user" account SSHes to the host,
# their session is automatically forwarded into their container via incus exec.
#
# This is needed on standalone/tunnel backends where the sentinel's sshpiper
# routes SSH to the host, but the container runs inside Incus.
#
# What it sets up:
#   1. containarium-shell wrapper (replaces nologin for containarium users)
#      - Interactive: incus exec <container> -t -- su -l <user>
#      - Non-interactive (ssh host "cmd"): handles -c arg and SSH_ORIGINAL_COMMAND
#   2. Sudoers for passwordless incus exec/info
#   3. sshd config to suppress host MOTD for containarium users
#   4. Containarium MOTD banner
#
set -e

WRAPPER_SCRIPT="/usr/local/bin/containarium-shell"
INCUS_BIN=$(which incus 2>/dev/null || echo "/usr/bin/incus")
INCUS_REAL=$(readlink -f "$INCUS_BIN" 2>/dev/null || echo "$INCUS_BIN")

echo "==> Setting up SSH container proxy..."
echo "  Incus binary: $INCUS_BIN (real: $INCUS_REAL)"

# ============================================================
# 1. Create containarium-shell wrapper
# ============================================================
cat > "$WRAPPER_SCRIPT" << 'SHELLEOF'
#!/bin/bash
# containarium-shell: Proxy SSH sessions into Incus containers

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

# Resolve the command to run, if any.
# Three possible invocation modes:
#   1. SSH_ORIGINAL_COMMAND is set: ForceCommand mode
#   2. Called as "containarium-shell -c <cmd>": sshpiper forwarded exec request;
#      the upstream sshd invokes the user's shell as "<shell> -c <cmd>"
#   3. No command: interactive session
COMMAND="${SSH_ORIGINAL_COMMAND}"
if [ -z "$COMMAND" ] && [ "$1" = "-c" ]; then
    COMMAND="$2"
fi

if [ -n "$COMMAND" ]; then
    exec sudo incus exec "$CONTAINER" --mode non-interactive -- su - "$USERNAME" -c "$COMMAND"
fi

# Show banner for interactive sessions
IP=$(sudo incus info "$CONTAINER" 2>/dev/null | awk '/eth0:/,/inet:/{if(/inet:/) print $2}' | head -1 | cut -d/ -f1)

cat << 'BANNER'

   ____            _        _                 _
  / ___|___  _ __ | |_ __ _(_)_ __   __ _ _ __(_)_   _ _ __ ___
 | |   / _ \| '_ \| __/ _` | | '_ \ / _` | '__| | | | | '_ ` _ \
 | |__| (_) | | | | || (_| | | | | | (_| | |  | | |_| | | | | | |
  \____\___/|_| |_|\__\__,_|_|_| |_|\__,_|_|  |_|\__,_|_| |_| |_|

BANNER

echo "  Container:   ${CONTAINER}"
echo "  User:        ${USERNAME}"
[ -n "$IP" ] && echo "  IP:          ${IP}"
echo "  Host:        $(hostname)"
echo ""

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

# ============================================================
# 2. Sudoers — passwordless incus exec/info for all users
# ============================================================
SUDOERS_FILE="/etc/sudoers.d/containarium-incus"
cat > "$SUDOERS_FILE" << SUDOEOF
# Allow containarium users to exec into their containers via incus
# This is used by containarium-shell to proxy SSH sessions
ALL ALL=(root) NOPASSWD: $INCUS_BIN exec *, $INCUS_BIN info *
SUDOEOF

# Also allow the real binary path if it's different (e.g., /opt/incus/bin/incus)
if [ "$INCUS_REAL" != "$INCUS_BIN" ]; then
    echo "ALL ALL=(root) NOPASSWD: $INCUS_REAL exec *, $INCUS_REAL info *" >> "$SUDOERS_FILE"
fi

chmod 440 "$SUDOERS_FILE"
echo "  Created $SUDOERS_FILE"

# ============================================================
# 3. sshd config — suppress host MOTD for containarium users
# ============================================================
SSHD_MATCH_FILE="/etc/ssh/sshd_config.d/containarium-motd.conf"
if [ -d /etc/ssh/sshd_config.d ]; then
    cat > "$SSHD_MATCH_FILE" << 'SSHDEOF'
# Suppress host MOTD for containarium container users
# containarium-shell shows its own banner with container info
Match User *,!ubuntu,!root
    PrintMotd no
    PrintLastLog no
SSHDEOF
    echo "  Created $SSHD_MATCH_FILE"
    systemctl reload sshd 2>/dev/null || true
else
    # Fallback: append to main sshd_config if .d directory doesn't exist
    if ! grep -q "containarium-motd" /etc/ssh/sshd_config 2>/dev/null; then
        cat >> /etc/ssh/sshd_config << 'SSHDEOF'

# containarium-motd: suppress host MOTD for container users
Match User *,!ubuntu,!root
    PrintMotd no
    PrintLastLog no
SSHDEOF
        echo "  Updated /etc/ssh/sshd_config"
        systemctl reload sshd 2>/dev/null || true
    fi
fi

# ============================================================
# 4. Containarium MOTD banner
# ============================================================
HOSTNAME=$(hostname)
GPU_INFO=""
if command -v nvidia-smi &>/dev/null; then
    GPU_NAME=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -1)
    [ -n "$GPU_NAME" ] && GPU_INFO=" ($GPU_NAME)"
fi

cat > /etc/motd << MOTDEOF

   ____            _        _                 _
  / ___|___  _ __ | |_ __ _(_)_ __   __ _ _ __(_)_   _ _ __ ___
 | |   / _ \| '_ \| __/ _\` | | '_ \ / _\` | '__| | | | | '_ \` _ \\
 | |__| (_) | | | | || (_| | | | | | (_| | |  | | |_| | | | | | |
  \\____\\___/|_| |_|\\__\\__,_|_|_| |_|\\__,_|_|  |_|\\__,_|_| |_| |_|

  Container Platform — ${HOSTNAME}${GPU_INFO}

  Documentation: https://github.com/footprintai/Containarium

MOTDEOF
echo "  Created /etc/motd"

echo ""
echo "==> SSH container proxy setup complete!"
echo ""
