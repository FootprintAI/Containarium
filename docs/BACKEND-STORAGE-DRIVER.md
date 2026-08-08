# Backend storage-driver selection

Which incus storage driver a backend's pool uses is a **tenant-isolation**
decision, not only a performance one. This page covers what Containarium
picks, why, and how to make a non-isolating pool a hard failure.

## The short version

| Driver | Each container gets | Tenants share a journal? |
| --- | --- | --- |
| `zfs` | its own dataset | no |
| `btrfs` | its own subvolume | no |
| `lvm` | its own logical volume | no |
| `ceph` | its own RBD image | no |
| `dir` | a directory on one shared filesystem | **yes** |

On `dir`, every tenant rootfs is a directory on one ext4 filesystem, so all
tenants share one `jbd2` journal.

## Why `dir` is a last resort

ext4's default `data=ordered` mode writes back a transaction's dirty data
while holding the journal lock. With N tenants on one filesystem, tenant A's
`fsync()` waits for tenants B and C's dirty pages to reach disk.

Measured on a backend running three CI tenants: the same 50-fsync probe went
from **17 ms to 11,885 ms** — a ~700x degradation — with the host, the
hypervisor and the physical device all provably idle.

A tenant can degrade its neighbours by writing normally, with no privilege
and no misconfiguration. That makes it an isolation gap.

Two things make this easy to miss:

- **Idle benchmarks show the opposite of the truth.** At rest, the same
  `dir`-backed containers measured *faster* than a ZFS-backed backend and
  faster than the physical host's own filesystem.
- **The trigger is co-tenant dirty-page volume, not fsync frequency.** Four
  tight `fsync()` loops with 4 KiB writes barely move the probe (32 ms); eight
  workers doing 64 MiB buffered writes then `fsync` produce the 11,885 ms
  stall. A naive fsync-latency check reports healthy.

See [issue #1206](https://github.com/FootprintAI/Containarium/issues/1206) for
the full measurements, the ruled-out hypotheses, and a self-contained
reproduction script.

## What Containarium does

On first provisioning of a pool, `EnsureStorage` picks the most isolating
driver the host can support:

1. **`zfs`** — if the installer's `incus-local/containers` dataset exists.
2. **`btrfs`** — if `/var/lib/incus/storage-pools` is on a btrfs filesystem.
   btrfs is in-tree, so a long-lived backend does not need a DKMS module
   rebuilt across kernel upgrades.
3. **`dir`** — only when neither is available, with a loud startup warning.

A pool that **already exists** is re-checked on every daemon start rather
than accepted silently, so a backend provisioned on `dir` before this
behaviour existed still reports itself.

An unrecognised driver is flagged separately and more weakly: Containarium
says it cannot classify the driver, rather than claiming the `dir` mechanism
it has not established for it.

## Making it a hard failure

For a backend that runs mutually untrusting tenants:

```bash
containarium daemon --require-isolated-storage ...
```

The daemon then refuses to initialize infrastructure on a pool whose driver
does not give each container its own volume — including drivers it does not
recognise and therefore cannot vouch for.

It is **off by default**: a shared journal is harmless on a dev host or a
single-tenant box, and turning it on by default would break those installs on
upgrade.

## Moving an existing backend off `dir`

There is no in-place conversion. The pool has to be recreated and the
containers migrated:

1. Back up every tenant on the host (`scripts/backup-all-tenants.sh`).
2. Provision the new backing store — a ZFS dataset at
   `incus-local/containers`, or a btrfs filesystem mounted at
   `/var/lib/incus/storage-pools`.
3. Recreate the pool (see `containarium recover --storage-driver`).
4. Restore the tenants (`scripts/restore-tenant.sh`).

Verify afterwards by re-running the reproduction from #1206: the ratio
between the idle probe and the under-load probe is the signal, not either
number on its own.
