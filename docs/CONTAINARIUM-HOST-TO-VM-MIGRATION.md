# Containarium Host → VM Migration

> Status: **Plan, awaiting decisions.** Generic operational
> runbook; the pattern applies to any Containarium bare-metal
> node we want to clean up. First execution is on an internal
> lab host (2026-05-25); specifics live in a private runbook.

## Why

Containarium installed on bare-metal pollutes the host: its iptables
DNAT/REDIRECT rules catch any non-Containarium VM's outbound traffic,
its Caddy occupies host :80/:443, its Incus owns the host's bridges.
This was diagnosed the hard way when a libvirt sandbox VM on a
Containarium-bare-metal node had its HTTPS hijacked by the host's
Containarium Caddy.

Moving Containarium into a VM:

- Host stays minimal (hypervisor + Tailscale + monitoring).
- Sibling VMs can come and go without their traffic being intercepted.
- Snapshots, backups, host swaps become VM-level operations.
- Multi-tenant: prod + staging Containariums can be separate VMs.
- Solves the Caddy-intercept bug structurally, not by patching.

## Host inventory shape (illustrative)

A Containarium bare-metal node typically runs an LXC mix of:

| Tier | Typical role | Special constraints |
| --- | --- | --- |
| **GPU user container(s)** | Tenant ML/inference workload | GPU passthrough (PCI device) |
| **CPU user containers** | Tenant CPU workloads (CI, web apps, data jobs) | None |
| **Platform services (5 LXCs)** | `containarium-core-{caddy, postgres, otelcollector, security, victoriametrics}` | Small, fixed resource budget |

Resource sizing depends on the deployment. Sum up CPU/RAM commitments before sizing the destination VM (over-commit ratios that work on bare-metal need re-validation when CPU is virtualized).

## Target architecture

```
┌─ host (bare-metal) ────────────────────────────────────────┐
│                                                            │
│  Ubuntu 24.04 + libvirt + Tailscale                        │
│  /dev/kvm + VFIO bound to GPU (passthrough device)         │
│  Host's iGPU (if present) stays bound to host i915/Xe      │
│                                                            │
│  ┌─ containarium-vm (libvirt KVM) ───────────────────────┐ │
│  │  Ubuntu 24.04, sized to match host LXC commitments   │ │
│  │  PCI: GPU passthrough                                │ │
│  │  Net: bridged to LAN (own MAC/IP, not NAT)           │ │
│  │  Incus 6.x + Containarium daemon                     │ │
│  │  zpool: ZVOL carved from host's pool, OR             │ │
│  │  a dataset mounted into the VM                       │ │
│  │                                                      │ │
│  │  ├─ all production LXCs (GPU + CPU + platform)       │ │
│  └──────────────────────────────────────────────────────┘ │
│                                                            │
│  ┌─ sibling sandbox VMs (any number)  ────────────────────┐│
│  │  Ad-hoc VMs for testing, etc. Traffic goes through    ││
│  │  libvirt NAT to LAN; NOT hijacked by Containarium     ││
│  │  Caddy anymore (it's scoped inside the other VM).     ││
│  └────────────────────────────────────────────────────────┘│
└────────────────────────────────────────────────────────────┘
```

## Decisions needed before execution

| # | Decision | Options | Recommendation |
| --- | --- | --- | --- |
| D1 | VM network mode | (a) bridged to LAN — VM gets a real LAN IP, can keep existing Tailscale identity / sentinel-peer registration. (b) libvirt NAT — simpler but loses the existing LAN IP + needs sentinel re-pointing | **(a) bridged**, to minimize sentinel + Tailscale churn |
| D2 | Storage for VM disk | (a) raw qcow2 on `/var/lib/libvirt/images` (root ext4). (b) ZVOL carved from the host's main zpool. (c) New ZFS dataset mounted into the VM | **(b) ZVOL** — fastest path (same disk as production data), single block device, ZFS snapshots of the whole VM, no double-COW |
| D3 | LXC migration method | (a) `incus copy` over network. (b) `incus export` + scp + `incus import`. (c) `zfs send | zfs receive` from host pool → VM pool | **(c) zfs send/receive** — fastest, lossless, ZFS snapshots come along. Falls back to (b) if VM doesn't have host's zpool visible |
| D4 | Tailscale identity for the VM | (a) Keep the original hostname on the VM; host becomes `<hostname>-hv` or similar. (b) New name for the VM, keep original on host | **(a)** — keeps existing sentinel registration, peer ID, and SSH config pointing at the unchanged hostname |
| D5 | Cutover window | (a) Off-hours scheduled downtime, coordinate with workload owners. (b) ASAP, accept ~1-2 hours visible downtime | **(a)** — user-facing workloads need a maintenance window |
| D6 | Rollback trigger | When do we abort + restore from snapshot? | **If GPU passthrough doesn't work in the VM after Phase 4**, that's the abort gate — no point continuing if the GPU is broken |

## Phased migration

### Phase 0 — Pre-flight (no changes; gather data)

```bash
# All on the target host.
echo "=== IOMMU groups for the passthrough GPU (must be in own group OR group of devices we can pass too) ==="
# Replace <pci-slot> with the GPU's PCI BDF, e.g. 01:00.
for g in /sys/kernel/iommu_groups/*; do
    iommu=$(basename "$g")
    devs=$(ls "$g/devices/" 2>/dev/null)
    if echo "$devs" | grep -q "<pci-slot>"; then
        echo "IOMMU group $iommu:"
        for d in $devs; do lspci -nns "$d"; done
    fi
done

echo "=== current GPU bindings ==="
lspci -nnk -s <pci-slot>.0   # GPU
lspci -nnk -s <igpu-slot>.0  # iGPU (e.g. Intel 00:02.0)

echo "=== /etc/default/grub current cmdline ==="
grep CMDLINE /etc/default/grub

echo "=== existing zpool snapshot baseline (must have one before we start) ==="
sudo zfs list -t snapshot -o name,refer,creation -s creation | tail -10
```

**Gate:** confirm GPU is in an IOMMU group of its own (or only with its audio device), and that there's enough free space on the backup pool for a baseline snapshot of the main pool.

### Phase 1 — Baseline snapshot (rollback insurance)

```bash
# Replace <main-pool> / <backup-pool> with the local zpool names.
sudo zfs snapshot -r <main-pool>@pre-host-to-vm-$(date -u +%Y%m%dT%H%M%SZ)
sudo zfs send -R <main-pool>@pre-host-to-vm-* \
    | sudo zfs receive <backup-pool>/snapshots/pre-host-to-vm
sudo zfs list -t snapshot -r <main-pool> | head
```

**Gate:** snapshot exists and is replicated to the backup pool. We can roll back to this point at any later phase.

### Phase 2 — VFIO setup (requires reboot)

```bash
# 1. Add IOMMU + VFIO to kernel cmdline.
#    Replace <gpu-vid:pid> with the GPU's VID:PID, e.g. 10de:2204
#    (plus the HDMI-audio function VID:PID, e.g. 10de:1aef).
sudo sed -i 's|GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"|GRUB_CMDLINE_LINUX_DEFAULT="\1 intel_iommu=on iommu=pt vfio-pci.ids=<gpu-vid:pid>,<audio-vid:pid>"|' /etc/default/grub
sudo update-grub

# 2. Bind vfio-pci at module load.
echo "options vfio-pci ids=<gpu-vid:pid>,<audio-vid:pid>" | sudo tee /etc/modprobe.d/vfio.conf
echo "vfio
vfio_pci
vfio_iommu_type1" | sudo tee /etc/modules-load.d/vfio.conf
sudo update-initramfs -u

# 3. REBOOT.
sudo reboot

# 4. After boot, verify:
lspci -nnk -s <pci-slot>.0     # should show: Kernel driver in use: vfio-pci
dmesg | grep -i vfio | head
```

**Gate:** GPU is bound to `vfio-pci`, host display still works on the iGPU (if present), host SSH still reachable.

**Impact during Phase 2:** any LXC currently using the GPU loses access when vfio-pci grabs it. Schedule accordingly with workload owners.

### Phase 3 — Provision the Containarium VM

```bash
# 1. Carve a ZVOL for the VM root disk on the main zpool.
sudo zfs create -V 200G -o volblocksize=16k <main-pool>/containarium-vm

# 2. Bridge the host's LAN interface.
#    If the host's default route is on wifi, bridging is unreliable —
#    use `macvtap passthrough` as a workaround, or accept libvirt NAT
#    and re-point sentinel registration (D1 fallback).

# 3. virt-install with VFIO + bridge + ZVOL disk.
sudo virt-install --name containarium-vm \
    --os-variant ubuntu24.04 \
    --memory <sized-to-host-LXC-RAM-sum> --vcpus <sized-to-host-vCPU-sum> \
    --disk path=/dev/zvol/<main-pool>/containarium-vm,format=raw,bus=virtio,cache=none \
    --network bridge=br0 \
    --hostdev pci_0000_<pci-slot>_0 \
    --hostdev pci_0000_<pci-slot>_1 \
    --cdrom /var/lib/libvirt/images/ubuntu-24.04-server-installer.iso \
    --graphics none --console pty,target_type=serial

# 4. Inside the VM (via serial console install), configure: hostname, SSH, Tailscale.
# 5. Install Incus 6.x, init with `incus admin init --auto` against a ZFS pool.
# 6. Verify nvidia-smi inside the VM sees the GPU.
```

**Gate:** VM is up, has a LAN IP, Tailscale-reachable, `nvidia-smi` sees the GPU, Incus is initialized.

> Verify GPU passthrough end-to-end — that the GPU is usable from inside an
> **LXC**, not just from the VM shell — with the standalone gate script (no
> daemon needed). It launches a throwaway `nvidia.runtime=true` LXC, runs
> `nvidia-smi` inside, parses the model + driver, and tears it down:
>
> ```sh
> sudo ./scripts/validate-gpu-passthrough.sh            # or --pci 0000:01:00.0, --json
> # → ✓ GPU PASSTHROUGH OK: NVIDIA GeForce RTX 4090 (driver 570.x)
> ```
>
> A non-zero exit here is the **D6 rollback trigger** — abort the migration
> rather than continue with a broken GPU. Re-run it after any VFIO bind or
> driver upgrade too. (#316)

### Phase 4 — LXC migration (host → VM)

For each container, in this order (platform first, then CPU-only user containers, GPU container last):

1. containarium-core-postgres
2. containarium-core-victoriametrics
3. containarium-core-otelcollector
4. containarium-core-security
5. containarium-core-caddy
6. CPU-only user containers
7. GPU user container (GPU passthrough config rewritten for VM-side PCI ID)

Per-container procedure (zfs send/receive variant, fastest):

```bash
# On host:
NAME=<container-name>
incus stop "$NAME"
sudo zfs snapshot <main-pool>/containers/$NAME@migrate
sudo zfs send <main-pool>/containers/$NAME@migrate \
    | ssh <vm-hostname> 'sudo zfs receive <vm-pool>/containers/'$NAME

# In VM:
# Re-create the incus instance metadata pointing at the received dataset.
# (Incus has `incus copy --refresh` for this; or use `incus import` after export.)
incus start "$NAME"
incus exec "$NAME" -- systemctl status   # sanity check
```

For the **GPU user container**, rewrite the GPU device config to use the VM's view of the PCI BDF:

```bash
# Inside the VM, after the container is imported:
incus config device set <gpu-container-name> gpu pci=<vm-side-pci-slot>
incus start <gpu-container-name>
incus exec <gpu-container-name> -- nvidia-smi
```

**Gate:** all containers running in the VM, accessible at their original `incusbr0` addresses (assuming we keep the same Incus subnet inside the VM).

### Phase 5 — Cutover

```bash
# On host: stop the old (still-on-host) Containarium daemon + Incus
sudo systemctl stop containarium
sudo systemctl stop incus
# (Leave the data in place for rollback. Don't delete.)

# Move Tailscale identity to the VM if D4=(a):
# - On host: `sudo tailscale logout`
# - In VM:   `sudo tailscale up --hostname=<original-hostname>`

# Sentinel re-registration is automatic once the VM's daemon registers
# itself with the same peer ID.
```

**Gate:** sentinel shows the host peer via the VM; SSH to the original hostname lands in the VM; GPU + CPU workloads are back up.

### Phase 6 — Soak + cleanup

- 24h observation: VictoriaMetrics graphs, sentinel peer health, no surprise restarts.
- After soak: **don't yet delete** the host's `<main-pool>/containers/*`. That's our rollback. Mark with a clear timestamped retention window (e.g., 7 days).
- After retention: `zfs destroy -r <main-pool>/containers` on the host.

## Rollback procedure

If any gate fails irrecoverably:

1. In VM: `incus stop --all` (don't lose data; just stop).
2. On host: `sudo systemctl start containarium && sudo systemctl start incus`.
3. Containers come back up where they were. ~1 min downtime per container.
4. The VM stays around (does nothing) until we decide what to do.
5. The GPU stays bound to vfio-pci. To return it to the host: remove the cmdline + reboot.

The `<backup-pool>/snapshots/pre-host-to-vm` ZFS snapshot is the nuclear-rollback option (restore the entire main pool to its pre-Phase-1 state).

## Open technical risks

- **Bridging requires wired Ethernet.** If the host's default route is on wifi, bridging wifi NICs to a guest VM is unreliable (most APs don't allow client MAC multiplexing). Need to confirm there's a wired interface to bridge against. If not: use `macvtap passthrough` or accept libvirt NAT + sentinel re-pointing.
- **IOMMU group composition.** If the GPU shares an IOMMU group with other host-critical devices (USB controller, root port), we have to pass them all together — sometimes a deal-breaker. Phase 0 will tell us.
- **Memory pinning.** A VM with a large RAM allocation should pin its memory (`virsh memtune` `hard_limit`) so VFIO has stable DMA mappings. Out-of-default; document in the runbook.
- **Tailscale conflict.** Tailscale logged in on the host AND the same hostname trying to log in on the VM will collide. Phase 5 covers the cutover — must be sequential, not parallel.

## What this is NOT

- Not a generic "make Containarium production-grade" doc — it's a specific operational migration pattern with a worked GPU passthrough case.
- Not done. We finish this doc + ratify the 6 decisions BEFORE touching the host.

## Related

- 2026-05-24 incident — Caddy intercept on a Containarium-bare-metal node hijacking sibling libvirt VM traffic. Concrete motivation.
- `docs/security/NETWORK-ISOLATION-DESIGN.md` — eBPF Phase A may run inside the new VM; clean test environment.
- `docs/EPHEMERAL-SANDBOX-DESIGN.md` — depends on having sibling VMs that DON'T get hijacked, which this migration enables.
