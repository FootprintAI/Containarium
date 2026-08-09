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
# Collaborator jump accounts are "<owner>-container-<collab>" (see
# CollaboratorManager.AddCollaborator); the container they access is
# "<owner>-container", NOT "<login>-container". Owner logins never contain the
# "-container-" infix, so they are unaffected. Without this a collaborator
# session resolves to "<owner>-container-<collab>-container" and dies with
# "Container ... not found" — the SSH-session half of the #1140 fix (the other
# half is the keysync orphan filter, fixed separately).
case "$USERNAME" in
    *-container-*) CONTAINER="${USERNAME%-container-*}-container" ;;
esac

# Check if container exists and is running
if ! sudo incus info "$CONTAINER" &>/dev/null; then
    echo "Error: Container $CONTAINER not found" >&2
    exit 1
fi

STATE=$(sudo incus info "$CONTAINER" 2>/dev/null | grep "^Status:" | awk '{print $2}')
if [ "$STATE" != "RUNNING" ]; then
    # wake-on-SSH (#539/#593): transparently start an auto-slept box on an
    # inbound SSH connection, parity with wake-on-HTTP. This wrapper IS the
    # daemon-local SSH router, so it starts the box directly and stamps the
    # same bookkeeping the daemon's StartContainer does:
    #   - last_started_at  → autosleep anti-thrash (don't re-sleep for 2x the
    #                        idle window right after a start)
    #   - clear stopped_at → two-phase reaping (reset the stopped->delete timer)
    # Then it waits (bounded, ~30s like wake-on-HTTP) for the box to be RUNNING
    # and exec-ready before proceeding.
    echo "Waking $CONTAINER (was: $STATE)..." >&2
    if ! sudo incus start "$CONTAINER" >/dev/null 2>&1; then
        echo "Error: failed to start $CONTAINER" >&2
        exit 1
    fi
    sudo incus config set "$CONTAINER" user.containarium.last_started_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >/dev/null 2>&1 || true
    sudo incus config unset "$CONTAINER" user.containarium.stopped_at >/dev/null 2>&1 || true
    READY=
    for _ in $(seq 1 30); do
        STATE=$(sudo incus info "$CONTAINER" 2>/dev/null | grep "^Status:" | awk '{print $2}')
        if [ "$STATE" = "RUNNING" ] && sudo incus exec "$CONTAINER" --mode non-interactive -- true >/dev/null 2>&1; then
            READY=1
            break
        fi
        sleep 1
    done
    if [ -z "$READY" ]; then
        echo "Error: $CONTAINER did not become ready in time" >&2
        exit 1
    fi
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
SSHD_BIN="$(command -v sshd || echo /usr/sbin/sshd)"

# NO `Match` BLOCK HERE — this is load-bearing (#1137).
#
# PrintMotd and PrintLastLog are not permitted inside a Match block. Wrapping
# them in one makes the ENTIRE sshd config unparseable, so sshd refuses to
# start on its next restart:
#
#   sshd_config.d/containarium-motd.conf line 2: Directive 'PrintMotd' is
#   not allowed within a Match block
#
# That takes SSH to the host down, and with it every box on the backend
# (sshpiper's upstream is this host's sshd) — while the daemon, the tunnel
# and the containers all keep running and the backend still reports healthy.
# Nothing surfaces it until someone tries to connect, and recovery needs the
# machine's console. It is not restricted to the drop-in either: the same
# block appended to the main sshd_config is equally invalid, because the
# restriction is on Match, not on where the file lives.
#
# Global scope is therefore the only option — the directives cannot be
# per-user. In practice the cost is nil on Ubuntu, which already sets
# `PrintMotd no` globally in its stock sshd_config and prints the MOTD from
# pam_motd rather than sshd; the one real change is that admin logins lose
# the "Last login:" line. On rocky9/rhel9, where PrintMotd defaults to yes,
# the setting does the job it was written for.
write_sshd_dropin() {
    cat > "$SSHD_MATCH_FILE" << 'SSHDEOF'
# Suppress host MOTD/last-login for containarium container users.
# containarium-shell shows its own banner with container info.
#
# Global, NOT inside a Match block: PrintMotd/PrintLastLog are rejected
# inside Match and would make sshd_config unparseable (#1137).
PrintMotd no
PrintLastLog no
SSHDEOF
}

# Validate before reloading, and fail loudly.
#
# `sshd -t` parses the whole config, drop-ins included. Previously this was
# `systemctl reload sshd 2>/dev/null || true`, which discarded both the
# output and the exit status — and since the running sshd keeps serving its
# already-loaded config, the host looked healthy for hours or days. The
# breakage landed at the next restart, in practice an unattended-upgrades
# openssh update at an arbitrary time. Checking here turns a delayed,
# console-only outage into an immediate install failure.
reload_sshd_or_revert() {
    local revert_cmd="$1"
    if ! "$SSHD_BIN" -t 2>&1; then
        echo "ERROR: sshd config is invalid after writing the containarium MOTD settings." >&2
        echo "       Reverting so sshd keeps starting; SSH to this host is not at risk." >&2
        eval "$revert_cmd"
        if "$SSHD_BIN" -t 2>/dev/null; then
            echo "       Revert succeeded — the config is valid again." >&2
        else
            echo "       WARNING: config is STILL invalid after revert; do not restart sshd." >&2
        fi
        exit 1
    fi
    systemctl reload sshd
}

if [ -d /etc/ssh/sshd_config.d ]; then
    write_sshd_dropin
    echo "  Created $SSHD_MATCH_FILE"
    reload_sshd_or_revert "rm -f '$SSHD_MATCH_FILE'"
else
    # Fallback: append to main sshd_config if the .d directory doesn't exist.
    if ! grep -q "containarium-motd" /etc/ssh/sshd_config 2>/dev/null; then
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.containarium-bak
        cat >> /etc/ssh/sshd_config << 'SSHDEOF'

# containarium-motd: suppress host MOTD/last-login for container users.
# Global, NOT inside a Match block — see #1137.
PrintMotd no
PrintLastLog no
SSHDEOF
        echo "  Updated /etc/ssh/sshd_config"
        reload_sshd_or_revert "mv -f /etc/ssh/sshd_config.containarium-bak /etc/ssh/sshd_config"
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
