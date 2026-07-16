#!/usr/bin/env bash
#
# agent-box image entrypoint: prepare authorized_keys + host key, then run
# dropbear in the foreground. By default every session is pinned by a forced
# command to agent-box (the in-box MCP server); set AGENTBOX_MODE=shell for an
# interactive login shell instead (opt-in — see the mode note below).
# See images/agent-box/Dockerfile.
set -euo pipefail

# The daemon mounts the box's authorized_keys Secret at
# /etc/agent-box/authorized_keys; dropbear reads ~/.ssh/authorized_keys, so
# point there. The file may not exist until the Secret is mounted — dropbear
# simply rejects every login until it appears (fail closed).
mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"
if [ -e /etc/agent-box/authorized_keys ]; then
  ln -sf /etc/agent-box/authorized_keys "$HOME/.ssh/authorized_keys"
fi

# Host keys in a writable per-container dir. Regenerated each start; the gateway
# uses ignore_hostkey today (host-key pinning is a follow-up), so fresh keys
# per restart are fine. BOTH an ed25519 and an RSA key are generated: the
# sshpiper gateway (Go x/crypto/ssh) offers rsa-sha2 host-key algorithms, and a
# dropbear with no RSA host key hits a NULL-key assertion (rsa.c) and drops the
# connection before auth — observed live against sshpiper. Shipping an RSA host
# key too makes the upstream handshake succeed.
KEYDIR="$HOME/.dropbear"
mkdir -p "$KEYDIR"
ED_HOSTKEY="$KEYDIR/ed25519_host_key"
RSA_HOSTKEY="$KEYDIR/rsa_host_key"
# Stable ed25519 host key: if the daemon mounted one (so the gateway can pin it
# via known_hosts), convert that OpenSSH key to dropbear format; otherwise fall
# back to an ephemeral key. Converting the same mounted key each start keeps the
# host key stable across pod restarts.
if [ -f /etc/agent-box-hostkey/host_key ]; then
  dropbearconvert openssh dropbear /etc/agent-box-hostkey/host_key "$ED_HOSTKEY" >/dev/null 2>&1 \
    || dropbearkey -t ed25519 -f "$ED_HOSTKEY" >/dev/null 2>&1
elif [ ! -f "$ED_HOSTKEY" ]; then
  dropbearkey -t ed25519 -f "$ED_HOSTKEY" >/dev/null 2>&1
fi
# Same for the RSA host key (both are mounted + pinned, since the sshpiper
# gateway may negotiate either).
if [ -f /etc/agent-box-hostkey/host_key_rsa ]; then
  dropbearconvert openssh dropbear /etc/agent-box-hostkey/host_key_rsa "$RSA_HOSTKEY" >/dev/null 2>&1 \
    || dropbearkey -t rsa -s 3072 -f "$RSA_HOSTKEY" >/dev/null 2>&1
elif [ ! -f "$RSA_HOSTKEY" ]; then
  dropbearkey -t rsa -s 3072 -f "$RSA_HOSTKEY" >/dev/null 2>&1
fi

# dropbear flags:
#   -F  foreground (PID 1)            -E  log to stderr
#   -s  disable password auth         -j -k  no local/remote port forwarding
#   -p 2222  unprivileged port        -r  host key file (repeatable)
dropbear_flags=(-F -E -s -j -k -p 2222 -r "$ED_HOSTKEY" -r "$RSA_HOSTKEY")

# Session mode (AGENTBOX_MODE, default "mcp"):
#   mcp    every session is a forced command into agent-box — the key can start
#          the MCP server and nothing else, so a leaked key's blast radius is one
#          box's MCP surface, never a shell. This is the default and the property
#          the K8s agent-box design is built around.
#   shell  interactive login shell (the agent user's /bin/bash). Opt-in: it
#          trades the forced-command guarantee for a general shell, so anyone who
#          can authenticate gets shell access inside the box. Use it for a
#          developer-style SSH box, and pair it with a default-deny NetworkPolicy
#          so the shell can't reach the cluster network.
case "${AGENTBOX_MODE:-mcp}" in
  mcp)
    exec dropbear "${dropbear_flags[@]}" -c /usr/local/bin/agent-box
    ;;
  shell)
    echo "[agent-box-entrypoint] AGENTBOX_MODE=shell — interactive shell enabled, forced-command MCP disabled" >&2
    exec dropbear "${dropbear_flags[@]}"
    ;;
  *)
    echo "[agent-box-entrypoint] unknown AGENTBOX_MODE='${AGENTBOX_MODE}' (want: mcp | shell)" >&2
    exit 1
    ;;
esac
