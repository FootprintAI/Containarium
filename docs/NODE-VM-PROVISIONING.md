# Node-VM provisioning — carve one host into multiple Containarium nodes

Status: **design + scaffold** (CPU path implemented; GPU/VFIO path gated and
partial). Validated by hand on an RTX 3090 workstation (see "Validation").

## What this is

A first-class `containarium node` command group that turns one physical
host into **several Containarium backends** by provisioning Incus VMs,
each running its own daemon + tunnel and registering with the sentinel as
a distinct pool-tagged node:

```
physical host (Incus, qemu driver)
├─ VM "gpu-node"  ──VFIO GPU──┐   daemon + `containarium tunnel --pool gpu`
│     └─ nested Incus → LXC + nvidia.runtime → tenant GPU containers
└─ VM "cpu-node" (no GPU)     ┘   daemon + `containarium tunnel --pool cpu`
        └─ nested Incus → LXC → tenant CPU containers
                  ↓ each tunnels to the sentinel
        sentinel sees TWO backends; MULTI-POOL routes workloads by pool tag
```

The container/peer/pool machinery already exists (`docs/MULTI-POOL.md`,
`docs/MULTI-BACKEND-PEERS.md`, `containarium tunnel`). This feature is the
missing **day-0 carve**: provision the VMs and bootstrap a daemon+tunnel
into each.

## When to use it (and when not to)

A single bare-metal daemon can already run GPU **and** CPU containers and
route them with pool tags — no VMs, no nested Incus. Reach for node-VMs
only when you need:

- **Hard isolation** between the GPU tenant(s) and CPU tenants (separate
  kernels, contained blast radius),
- **Independent lifecycle** — snapshot / reboot / upgrade one node without
  touching the other,
- a clean **capacity boundary** (the GPU VM gets the GPU + a CPU slice;
  the rest becomes a pure CPU node).

If the goal is only "send GPU work to GPU capacity," use pool-tagged
containers on bare metal instead — it's strictly simpler.

## Why the CLI, not the daemon API (no proto)

Everything daemon-served in this repo is proto-first. This is **not** —
carving a hypervisor host is a day-0 operation that runs *before and
around* the daemon (there is no daemon to call yet), manipulates Incus +
system config on the bare-metal host, and bootstraps daemons *into* the
VMs. It therefore belongs with the other **host-local** CLI commands
(`daemon`, `tunnel`, `recover`), as a cobra command with local logic — not
a gRPC RPC. The CLI is canonical; the existing `scripts/setup-peer.sh` /
`scripts/setup-gpu-host.sh` become thin wrappers over it.

The orchestration logic lives in `pkg/core/nodevm` as pure `incus`-argv
builders behind an injected runner (the same testable pattern as
`pkg/core/volume`), so it's unit-tested even though a real run needs
hardware.

## Command surface

```
# One-time, reboot-class host prep for a GPU node (VFIO). Explicit + gated.
containarium node prepare-gpu --gpu pci=0000:01:00.0
    → adds intel_iommu=on iommu=pt to GRUB, binds the GPU's PCI IDs to
      vfio-pci, prints the reboot instruction. DOES NOT reboot for you.
      WARNS: the host (and its current GPU containers) lose the GPU.

# Provision a node-VM (idempotent; re-run reconciles).
containarium node provision \
    --name cpu-node --kind cpu --pool cpu \
    --cpu 16 --memory 64GiB --disk 200GiB \
    --sentinel <sentinel-host:port> --tunnel-token <token>

containarium node provision \
    --name gpu-node --kind gpu --pool gpu \
    --cpu 8 --memory 32GiB --gpu pci=0000:01:00.0 \
    --sentinel <sentinel-host:port> --tunnel-token <token>

containarium node list                    # node-VMs on this host + state
containarium node destroy --name cpu-node # tear a node-VM down
```

`--tunnel-token` / `--sentinel` may also come from
`CONTAINARIUM_TUNNEL_TOKEN` / `CONTAINARIUM_SENTINEL_ADDR` (same env the
peer setup already honors), so the token never has to sit in shell
history.

## What `provision` does (per VM)

1. **Create the VM** via Incus's native qemu driver:
   `incus launch <image> <name> --vm -c limits.cpu=N -c limits.memory=X`
   (+ `--device root,size=<disk>`).
2. **For `--kind gpu`**: attach the GPU —
   `incus config device add <name> gpu0 gpu pci=<addr>` — which requires
   `prepare-gpu` + reboot to have run first (the host must already have
   the GPU on `vfio-pci`).
3. **Bootstrap inside the VM via cloud-init** — the same sequence
   `scripts/setup-peer.sh` runs today, just executed in the guest:
   - drop the `containarium` binary in (`/usr/local/bin/containarium`),
   - install nested Incus + `incus admin init --auto` (+ the NVIDIA driver
     for a GPU node),
   - `containarium service install` (daemon systemd unit + override),
   - a `containarium-tunnel.service` running
     `containarium tunnel --sentinel-addr <addr> --pool <pool> --spot-id <name>-<pool>`,
   - the tunnel token delivered as a cloud-init secret, written
     `0600 root` (never on the kernel cmdline / process args).
4. The node tunnels up and **registers as a backend**; verify with
   `containarium backends list` and `backends validate-gpu --backend-id <name>`.

## Idempotency / reconcile

`provision` is safe to re-run: an existing VM with the right config is
left alone; a half-provisioned one is reconciled (re-run cloud-init steps
that didn't complete). Mirrors the `runner provision` reconcile model — a
partial failure is a retryable state, not a duplicate-creating one.

## Open decisions

1. **`node` vs `host`** as the command group name.
2. **Binary delivery into the VM**: copy the operator's local binary vs.
   pull a pinned release URL in cloud-init. (Lean: copy local, so the node
   matches the operator's version exactly; fall back to release URL.)
3. **GRUB/VFIO edit safety**: `prepare-gpu` should back up the GRUB config
   and refuse if the GPU shares an IOMMU group with host-critical devices
   (no clean passthrough without ACS override — detect and bail with a
   clear message).
4. **Resource-split policy**: explicit `--cpu/--memory/--disk` per node
   (this design) vs. an auto-split heuristic. Explicit wins for v1.
5. **Reversal**: `node destroy` removes the VM; reclaiming a VFIO'd GPU for
   the host is a separate `node release-gpu` (unbind vfio-pci → nvidia →
   reboot), not automatic.

## Security notes

- The **tunnel token** is the credential that lets a node join the
  cluster. It's passed via env / a cloud-init secret and written `0600`
  inside the VM — never on argv or the kernel cmdline.
- `prepare-gpu` is the only privileged, reboot-class, partially-reversible
  step; it's a separate explicit verb precisely so it is never buried
  inside `provision`.
- A GPU passed to a node-VM is **exclusive to that VM** — the host and any
  host-side GPU containers lose it (it's bound to `vfio-pci`). This is
  inherent to VM GPU passthrough, not a tooling choice.

## Validation (what's proven)

On an RTX 3090 workstation (Incus 6.23, KVM, IOMMU active with the GPU
alone in its IOMMU group), by hand:

- An Incus qemu VM boots cleanly (`virt=kvm`, networking, DNS).
- Nested Incus installs + `admin init` inside the VM and runs LXC
  containers — i.e. the VM is a valid Containarium node substrate.
- Bare-metal → LXC GPU passthrough works (`nvidia.runtime` + GPU device →
  `nvidia-smi` sees the card), so the GPU-node nested path is sound.

`containarium node provision --kind cpu` was then run **live** on that host
(against a real sentinel, token delivered via a 0600 file): it created the
VM, installed nested Incus, pushed the binary, and launched the tunnel —
which dialed the sentinel under the right pool/spot-id, **with the token
NOT on the tunnel's argv** (read from the 0600 file as designed). Three
bugs were caught and fixed by that run: an invalid `incus list --vm` flag,
a `waitAgent` loop missing its inter-probe sleep, and the gap below.

**Known gap (next step):** the in-guest bootstrap launches the tunnel but
does not yet fully configure+start the daemon (jwt secret, override flags,
`systemctl enable --now`, tunnel `--ports`), so the node tunnels up but its
REST `/health` is down and the sentinel sees it as unhealthy. Porting
`scripts/setup-peer.sh`'s daemon stanza into `RenderBootstrap` is required
before a node-VM is a fully-healthy backend.

Not yet exercised: the VFIO GPU-to-VM bind (the reboot-class step).

## Encrypted / external storage for `/var/lib/incus`

If a node-VM (or any Containarium host) keeps `/var/lib/incus` on external or
LUKS-encrypted storage instead of the VM's root disk, the daemon must not start
before that storage is mounted — otherwise it initializes against an empty
directory. `scripts/containarium.service` intentionally ships `Wants=incus.service`,
not `Requires=`, because a failed `Requires=` kills the unit's start job and
`Restart=on-failure` does **not** retry a job failure (see the comment in that
file, and #1152: a hard dependency + fixed-interval restart once crash-looped a
host 1655 times in ~4 hours, restarting the monitoring stack on every cycle so
alerting could not fire during the incident it should have caught).

Gating the daemon on external storage needs the same care. A
`containarium.service.d/` drop-in that re-adds
`RequiresMountsFor=/var/lib/incus` is the natural fix, but `RequiresMountsFor`
has **no retry semantics** — any transient failure in the mount's own dependency
chain (e.g. the LUKS volume's `systemd-cryptsetup@` unit, or the `.device` unit
underneath it) leaves `containarium.service` `inactive (dead)` permanently, with
**zero journal entries for that boot** and nothing to alert on. This silently
reintroduces the exact failure class #1152 already taught this project to design
around — see
[#1317](https://github.com/FootprintAI/Containarium/issues/1317) for a real
incident: a LUKS-encrypted data volume's `systemd-cryptsetup@` unit opened the
device successfully, but the corresponding `dev-mapper-<name>.device` unit timed
out waiting for udev's "add" event (lost/delayed during early boot), cascading
through `systemd-fsck@` → the mount → `incus.socket`/`incus.service` →
`containarium.service` — all failing with `result=dependency`, silently, with no
observable error.

If your storage setup needs `RequiresMountsFor=/var/lib/incus`, pair it with an
`ExecStartPost` on the underlying `systemd-cryptsetup@<instance>.service` that
re-announces the device to udev right after opening it, so a missed/delayed
uevent can't wedge the chain:

```ini
# /etc/systemd/system/systemd-cryptsetup@<instance>.service.d/10-udev-kick.conf
[Service]
ExecStartPost=-/usr/bin/udevadm trigger --action=add --settle /dev/mapper/%i
```

Apply to every LUKS instance backing `/var/lib/incus` (there may be more than
one — e.g. separate volumes for data and a btrfs pool). This has been verified
safe (no regressions across repeated reboots) and effective (the exact
recovery command that fixes a wedged instance live) against the incident in
#1317.

## Related
- `docs/MULTI-POOL.md`, `docs/MULTI-BACKEND-PEERS.md` — pool routing the nodes plug into.
- `docs/CONTAINARIUM-HOST-TO-VM-MIGRATION.md` — the VFIO/host→VM concerns this shares (#318).
- `scripts/setup-peer.sh` — the in-guest bootstrap this cloud-init replicates.
