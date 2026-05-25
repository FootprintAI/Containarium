# Cross-Peer File Transfer Guide

Transfer files between containers on different peer nodes over LAN. Avoids the sentinel tunnel (which is slow) by using direct host-to-host communication.

## Architecture

```
peer-a (LAN: <peer-a-ip>)               peer-b (LAN: <peer-b-ip>)
  └── incusbr0 (10.100.0.0/24)            └── incusbr0 (10.100.0.0/24)
      └── container-A                         └── container-B
          (isolated bridge)                        (isolated bridge)
```

Containers on different peers can't reach each other directly — they're on separate bridge networks. File transfers must go through the host filesystem layer.

## Prerequisites

### One-Time Setup: Root SSH Between Peers

Direct host-to-host rsync requires root SSH access (container storage paths are root-owned).

**On the source peer**:
```bash
# Generate root SSH key (if not already done)
sudo ssh-keygen -t ed25519 -N "" -f /root/.ssh/id_ed25519

# Print the public key
sudo cat /root/.ssh/id_ed25519.pub
```

**On the destination peer**:
```bash
# Add the source peer's root key
sudo mkdir -p /root/.ssh
sudo bash -c 'echo "PASTE_THE_PUBLIC_KEY_HERE" >> /root/.ssh/authorized_keys'
sudo chmod 700 /root/.ssh
sudo chmod 600 /root/.ssh/authorized_keys
```

**Verify** (on source peer):
```bash
sudo ssh -o StrictHostKeyChecking=no <peer-b-ip> echo "SSH OK"
```

## Method 1: rsync (Recommended for Large Transfers)

Best for large directories (100GB+). Supports resume on interruption.

### Find Container Storage Paths

Container rootfs is at:
```
/var/lib/incus/storage-pools/default/containers/<CONTAINER_NAME>/rootfs/
```

Example:
```bash
# Source path (on the source peer)
SRC=/var/lib/incus/storage-pools/default/containers/<src-container>/rootfs/home/<tenant-user>/data/

# Destination path (on the destination peer)
DST=/var/lib/incus/storage-pools/default/containers/<dst-container>/rootfs/home/<tenant-user>/data/
```

### Run Transfer

On the **source peer** as root (substitute `<peer-b-ip>` with the destination peer's LAN IP):
```bash
# Create destination directory
sudo ssh <peer-b-ip> "mkdir -p '$DST'"

# rsync with progress and compression
sudo rsync -avP --compress "$SRC" "<peer-b-ip>:$DST"

# Fix ownership for LXC uid mapping (unprivileged containers use uid 1000000+)
sudo ssh <peer-b-ip> "chown -R 1000000:1000000 '$DST'"
```

### Speed Reference

| Network | Speed | 100GB | 500GB |
|---------|-------|-------|-------|
| WiFi LAN (802.11ac) | ~300-500 Mbps | ~30-50 min | ~2.5-4 hours |
| Gigabit Ethernet | ~900 Mbps | ~15 min | ~1.5 hours |
| 2.5GbE | ~2.3 Gbps | ~6 min | ~30 min |
| 10GbE | ~5 Gbps | ~3 min | ~15 min |

## Method 2: tar + ssh (No Temp Space)

Streams data directly without temp files. Good when disk space is tight.

On the **source peer** as root (substitute `<peer-b-ip>` with the destination peer):
```bash
sudo tar cf - -C "$SRC" . | ssh <peer-b-ip> "mkdir -p '$DST' && tar xf - -C '$DST'"

# Fix ownership
sudo ssh <peer-b-ip> "chown -R 1000000:1000000 '$DST'"
```

Add `pv` for progress monitoring (install with `apt install pv`):
```bash
sudo tar cf - -C "$SRC" . | pv -s $(sudo du -sb "$SRC" | cut -f1) | ssh <peer-b-ip> "tar xf - -C '$DST'"
```

## Method 3: incus file (Simple, Small Files)

For small files or directories. Uses Incus API, no root SSH needed.

**Pull from source container → push to destination container:**

On the **source peer**:
```bash
# Pull files out of container to host
sudo incus file pull -r <container>/path/to/files /tmp/transfer/
```

Transfer to destination peer:
```bash
scp -r /tmp/transfer/ <dest-peer>:/tmp/transfer/
```

On the **destination peer**:
```bash
# Push files into container
sudo incus file push -r /tmp/transfer/ <container>/path/to/files/
```

**Drawback**: Requires temp space on both hosts equal to the transfer size.

## UID/GID Mapping

Incus unprivileged containers map UIDs:
- Host UID `1000000` = Container UID `0` (root)
- Host UID `1001000` = Container UID `1000` (first user)

After copying files via host-level tools (rsync, tar), fix ownership:
```bash
# For files owned by the container's first user (uid 1000 inside container):
sudo chown -R 1000000:1000000 /path/on/host/

# To match a specific user (e.g., uid 1001 inside container):
sudo chown -R 1001000:1001000 /path/on/host/
```

Verify inside the container:
```bash
incus exec <container> -- ls -la /path/to/files/
```

## Troubleshooting

### Permission denied on storage path
- Run as root: `sudo rsync ...`
- ZFS storage: check `zfs list | grep <container>` for the correct mount

### Transfer interrupted
- rsync automatically resumes: just re-run the same command
- tar does not resume: start over or switch to rsync

### Slow transfer over WiFi
- Use wired ethernet between peers for 10x+ speed improvement
- Add `--compress` to rsync (helps for compressible data, hurts for pre-compressed files like model weights)
- For model weights (already compressed): skip `--compress` flag

### Container can't see transferred files
- Check ownership: `ls -la` should show the container user, not root
- Run `chown -R 1000000:1000000` on the host path
- Restart the container if files still don't appear (rare)

### Storage path differs on ZFS
If using ZFS with non-default pool names:
```bash
# Find the actual mount point
mount | grep <container-name>
# Example output:
# incus-local/containers/containers/<name> on /var/lib/incus/storage-pools/default/containers/<name> type zfs
```
