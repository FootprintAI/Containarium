#!/usr/bin/env bash
#
# agent-box image entrypoint: prepare authorized_keys + host key, then run
# dropbear in the foreground with a forced command pinning every session to
# agent-box. See images/agent-box/Dockerfile.
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
#   -c  forced command — every session runs agent-box, nothing else
exec dropbear -F -E -s -j -k -p 2222 -r "$ED_HOSTKEY" -r "$RSA_HOSTKEY" -c /usr/local/bin/agent-box
