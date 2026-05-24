# Containarium Host → VM Migration

> Status: **Plan, awaiting decisions.** First worked example is
> `fts-13700k` (2026-05-25); the pattern generalizes to any
> Containarium bare-metal node we want to clean up.

## Why

Containarium installed on bare-metal pollutes the host: its iptables
DNAT/REDIRECT rules catch any non-Containarium VM's outbound traffic,
its Caddy occupies host :80/:443, its Incus owns the host's bridges.
This was diagnosed the hard way when a libvirt sandbox VM on
`fts-13700k` got its HTTPS hijacked by the host's Containarium Caddy
(2026-05-24).

Moving Containarium into a VM:

- Host stays minimal (hypervisor + Tailscale + monitoring).
- Sibling VMs can come and go without their traffic being intercepted.
- Snapshots, backups, host swaps become VM-level operations.
- Multi-tenant: prod + staging Containariums can be separate VMs.
- Solves the Caddy-intercept bug structurally, not by patching.

## fts-13700k inventory (2026-05-25)

| # | Container | Type | CPU/RAM | GPU | Notes |
| --- | --- | --- | --- | --- | --- |
| 1 | apibox-dev-3090-container | User | 16c / 64GB | **RTX 3090 (01:00.0)** | docker: cockburn-inference-server |
| 2 | dataspark-cicd-container | User | 8c / 32GB | — | docker: pes-resume-search + pes-postgres-vector |
| 3 | cicd-container | User | 4c / 16GB | — | empty |
| 4 | containarium-core-caddy | Platform | 1c / 512MB | — | systemd Caddy |
| 5 | containarium-core-postgres | Platform | 2c / 2GB | — | systemd Postgres |
| 6 | containarium-core-otelcollector | Platform | 1c / 512MB | — | OTel collector |
| 7 | containarium-core-security | Platform | 2c / 3GB | — | ClamAV + scanners |
| 8 | containarium-core-victoriametrics | Platform | 1c / 1GB | — | VictoriaMetrics |

Host: 24c/48t, 125GB RAM, ZFS `incus-local` (1.9TB NVMe), `incus-backup` (1.8TB HDD mirror), boot SSD (`nvme0n1`, 953G).

## Target architecture

```
┌─ fts-13700k bare-metal ────────────────────────────────────┐
│                                                            │
│  Ubuntu 24.04 + libvirt + Tailscale                        │
│  /dev/kvm + VFIO bound to RTX 3090 (10de:2204)             │
│  Intel UHD 770 stays bound to host (display + i915)        │
│                                                            │
│  ┌─ containarium-vm (libvirt KVM) ───────────────────────┐ │
│  │  Ubuntu 24.04, 20 vCPU, 100 GB RAM, 200GB disk       │ │
│  │  PCI: RTX 3090 passthrough                           │ │
│  │  Net: bridged to LAN (own MAC/IP, not NAT)           │ │
│  │  Incus 6.x + Containarium daemon                     │ │
│  │  zpool: incus-local-vm (carved from host's pool      │ │
│  │  via ZVOL OR a vdisk on the host's zpool)            │ │
│  │                                                      │ │
│  │  ├─ apibox-dev-3090-container  (RTX 3090 from VM)    │ │
│  │  ├─ dataspark-cicd-container                         │ │
│  │  ├─ cicd-container                                   │ │
│  │  └─ 5× containarium-core-*                           │ │
│  └──────────────────────────────────────────────────────┘ │
│                                                            │
│  ┌─ cloud-fts-13700k (libvirt KVM)  — and future siblings ┐│
│  │  Ad-hoc sandbox VMs. Traffic goes through libvirt NAT  ││
│  │  to LAN; NOT hijacked by Containarium Caddy anymore.   ││
│  └────────────────────────────────────────────────────────┘│
└────────────────────────────────────────────────────────────┘
```

## Decisions needed before execution

| # | Decision | Options | Recommendation |
| --- | --- | --- | --- |
| D1 | VM network mode | (a) bridged to LAN — VM gets a real LAN IP, can keep existing Tailscale identity / sentinel-peer registration. (b) libvirt NAT — simpler but loses the existing LAN IP + needs sentinel re-pointing | **(a) bridged**, to minimize sentinel + Tailscale churn |
| D2 | Storage for VM disk | (a) raw qcow2 on `/var/lib/libvirt/images` (root ext4). (b) ZVOL carved from `incus-local`. (c) New ZFS dataset on `incus-local` mounted into the VM | **(b) ZVOL on incus-local** — fastest path (same disk as production data), single block device, ZFS snapshots of the whole VM, no double-COW |
| D3 | LXC migration method | (a) `incus copy` over network. (b) `incus export` + scp + `incus import`. (c) `zfs send | zfs receive` from host pool → VM pool | **(c) zfs send/receive** — fastest, lossless, ZFS snapshots come along. Falls back to (b) if VM doesn't have host's zpool visible |
| D4 | Tailscale identity for the VM | (a) Keep `fts-13700k` hostname on the VM, host becomes `fts-13700k-hv` or similar. (b) New name like `fts-13700k-vm` for the VM | **(a)** — keeps existing sentinel registration, peer ID, and SSH config pointing at the unchanged `fts-13700k` |
| D5 | Cutover window | (a) Off-hours scheduled downtime, coordinate with apibox-dev-3090 + dataspark users. (b) ASAP, accept ~1-2 hours visible downtime | **(a)** — schedule it; both user containers serve real workloads (cockburn-inference-server, pes-resume-search) |
| D6 | Rollback trigger | When do we abort + restore from snapshot? | **If apibox-dev-3090's RTX 3090 doesn't work in VM after Phase 4**, that's the abort gate — no point continuing if the GPU is broken |

## Phased migration

### Phase 0 — Pre-flight (no changes; gather data)

```bash
# All on fts-13700k.
echo "=== IOMMU groups for the 3090 (must be in own group OR group of devices we can pass too) ==="
for g in /sys/kernel/iommu_groups/*; do
    iommu=$(basename "$g")
    devs=$(ls "$g/devices/" 2>/dev/null)
    if echo "$devs" | grep -q "01:00"; then
        echo "IOMMU group $iommu (the 3090's):"
        for d in $devs; do
            lspci -nns "$d"
        done
    fi
done

echo "=== current GPU bindings ==="
lspci -nnk -s 01:00.0
lspci -nnk -s 00:02.0    # Intel UHD 770

echo "=== /etc/default/grub current cmdline ==="
grep CMDLINE /etc/default/grub

echo "=== existing zpool snapshot baseline (must have one before we start) ==="
sudo zfs list -t snapshot -o name,refer,creation -s creation | tail -10
```

**Gate:** confirm RTX 3090 is in an IOMMU group of its own (or only with its audio device), and that there's enough free space on `incus-backup` for a baseline snapshot of `incus-local`.

### Phase 1 — Baseline snapshot (rollback insurance)

```bash
sudo zfs snapshot -r incus-local@pre-host-to-vm-$(date -u +%Y%m%dT%H%M%SZ)
sudo zfs send -R incus-local@pre-host-to-vm-* | sudo zfs receive incus-backup/snapshots/pre-host-to-vm
sudo zfs list -t snapshot -r incus-local | head
```

**Gate:** snapshot exists and is replicated to `incus-backup`. We can roll back to this point at any later phase.

### Phase 2 — VFIO setup (requires reboot)

```bash
# 1. Add IOMMU + VFIO to kernel cmdline.
sudo sed -i 's|GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"|GRUB_CMDLINE_LINUX_DEFAULT="\1 intel_iommu=on iommu=pt vfio-pci.ids=10de:2204,10de:1aef"|' /etc/default/grub
sudo update-grub

# 2. Bind vfio-pci at module load (10de:2204 = RTX 3090, 10de:1aef = its HDMI audio).
echo "options vfio-pci ids=10de:2204,10de:1aef" | sudo tee /etc/modprobe.d/vfio.conf
echo "vfio
vfio_pci
vfio_iommu_type1" | sudo tee /etc/modules-load.d/vfio.conf
sudo update-initramfs -u

# 3. REBOOT.
sudo reboot

# 4. After boot, verify:
lspci -nnk -s 01:00.0     # should show: Kernel driver in use: vfio-pci
dmesg | grep -i vfio | head
```

**Gate:** RTX 3090 is bound to `vfio-pci`, host display still works on Intel UHD 770, host SSH still reachable.

**Impact during Phase 2:** apibox-dev-3090's GPU stops working when vfio-pci grabs the 3090. cockburn-inference-server inside that container fails. Schedule accordingly.

### Phase 3 — Provision the Containarium VM

```bash
# 1. Carve a ZVOL for the VM root disk on incus-local (200GB).
sudo zfs create -V 200G -o volblocksize=16k incus-local/containarium-vm

# 2. Bridge the host's LAN interface (wlp6s0 is wifi — need wired for bridging; if wifi-only, use macvtap "passthrough" mode as a workaround, or accept libvirt NAT and re-point sentinel).
#    TBD: confirm we have a wired Ethernet on fts-13700k. If not, this is a blocker — bridging wifi is unreliable; macvtap is the workaround.

# 3. virt-install with VFIO + bridge + ZVOL disk.
sudo virt-install --name containarium-vm \
    --os-variant ubuntu24.04 \
    --memory 102400 --vcpus 20 \
    --disk path=/dev/zvol/incus-local/containarium-vm,format=raw,bus=virtio,cache=none \
    --network bridge=br0 \
    --hostdev pci_0000_01_00_0 \
    --hostdev pci_0000_01_00_1 \
    --cdrom /var/lib/libvirt/images/ubuntu-24.04-server-installer.iso \
    --graphics none --console pty,target_type=serial

# 4. Inside the VM (via serial console install), configure: hostname, SSH, Tailscale.
# 5. Install Incus 6.x, init with `incus admin init --auto` against a ZFS pool
#    (carved from a second ZVOL or a dataset mounted into the VM).
# 6. Verify nvidia-smi inside the VM sees the 3090.
```

**Gate:** VM is up, has a LAN IP, Tailscale-reachable as `fts-13700k` (after D4 cutover), `nvidia-smi` sees the 3090, Incus is initialized.

### Phase 4 — LXC migration (host → VM)

For each container, in this order (platform first, then user containers, GPU container last):

1. containarium-core-postgres
2. containarium-core-victoriametrics
3. containarium-core-otelcollector
4. containarium-core-security
5. containarium-core-caddy
6. cicd-container
7. dataspark-cicd-container
8. apibox-dev-3090-container (GPU passthrough config rewritten for VM-side PCI ID)

Per-container procedure (zfs send/receive variant, fastest):

```bash
# On host (fts-13700k):
NAME=containarium-core-postgres
incus stop "$NAME"
sudo zfs snapshot incus-local/containers/$NAME@migrate
sudo zfs send incus-local/containers/$NAME@migrate \
    | ssh containarium-vm 'sudo zfs receive incus-local/containers/'$NAME

# In VM:
# Re-create the incus instance metadata pointing at the received dataset.
# (Incus has `incus copy --refresh` for this; or use `incus import` after export.)
incus start "$NAME"
incus exec "$NAME" -- systemctl status   # sanity check
```

For **apibox-dev-3090-container**, rewrite the GPU device config:

```bash
# Inside the VM, after the container is imported:
incus config device set apibox-dev-3090-container gpu pci=01:00.0
incus start apibox-dev-3090-container
incus exec apibox-dev-3090-container -- nvidia-smi
```

**Gate:** all 8 containers running in the VM, accessible at their original `10.100.0.x` addresses (assuming we keep the `incusbr0` subnet inside the VM).

### Phase 5 — Cutover

```bash
# On host: stop the old (still-on-host) Containarium daemon + Incus
sudo systemctl stop containarium
sudo systemctl stop incus
# (Leave the data in place for rollback. Don't delete.)

# Move Tailscale identity to the VM if D4=(a):
# - On host: `sudo tailscale logout`
# - In VM:   `sudo tailscale up --hostname=fts-13700k`

# Sentinel re-registration is automatic once the VM's daemon registers
# itself as tunnel-fts-13700k-gpu (same peer ID).
```

**Gate:** sentinel shows `fts-13700k` peer via the VM; SSH `fts-13700k` lands in the VM; apibox-dev-3090's cockburn-inference-server is back up; dataspark stack is back up.

### Phase 6 — Soak + cleanup

- 24h observation: VictoriaMetrics graphs, sentinel peer health, no surprise restarts.
- After soak: **don't yet delete** the host's `incus-local/containers/*`. That's our rollback. Mark with a clear timestamped retention window (e.g., 7 days).
- After retention: `zfs destroy -r incus-local/containers` on the host.

## Rollback procedure

If any gate fails irrecoverably:

1. In VM: `incus stop --all` (don't lose data; just stop).
2. On host: `sudo systemctl start containarium && sudo systemctl start incus`.
3. Containers come back up where they were. ~1 min downtime per container.
4. The VM stays around (does nothing) until we decide what to do.
5. The 3090 GPU stays bound to vfio-pci. To return it to the host: remove the cmdline + reboot.

The `incus-backup/snapshots/pre-host-to-vm` ZFS snapshot is the nuclear-rollback option (restore the entire `incus-local` to its pre-Phase-1 state).

## Open technical risks

- **Bridging requires wired Ethernet.** `fts-13700k`'s default route is `wlp6s0` (wifi). Bridging wifi NICs is unreliable (most APs don't allow client MAC multiplexing). Need to confirm there's a wired interface (`enpXsY`) we can bridge against. If not: use `macvtap passthrough` or accept libvirt NAT + sentinel re-pointing.
- **IOMMU group composition.** If the 3090 shares an IOMMU group with other host-critical devices (USB controller, root port), we have to pass them all together — sometimes a deal-breaker. Phase 0 will tell us.
- **Memory pinning.** A VM with 100GB RAM allocated should pin its memory (`virsh memtune` `hard_limit`) so VFIO has stable DMA mappings. Out-of-default; document in the runbook.
- **Tailscale conflict.** Tailscale logged in on the host AND the same hostname trying to log in on the VM will collide. Phase 5 covers the cutover — must be sequential, not parallel.

## What this is NOT

- Not a generic "make Containarium production-grade" doc — it's a specific operational migration for one node with a worked GPU case.
- Not done. We finish this doc + ratify the 6 decisions BEFORE touching the host.

## Related

- 2026-05-24 incident — Caddy intercept on `fts-13700k` hijacking sibling libvirt VM traffic. Concrete motivation.
- `docs/security/NETWORK-ISOLATION-DESIGN.md` — eBPF Phase A may run inside the new VM; clean test environment.
- `docs/EPHEMERAL-SANDBOX-DESIGN.md` — depends on having sibling VMs that DON'T get hijacked, which this migration enables.
