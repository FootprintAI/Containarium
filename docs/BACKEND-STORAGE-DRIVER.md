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

There is no in-place conversion — the pool has to be recreated. Which
procedure applies depends on whether the tenants on the host carry durable
data.

> **Whichever path you take, the platform's own core services live on the
> same `default` pool as tenants** — core Postgres, Caddy, VictoriaMetrics,
> the security container and the OTel collector. Destroying the pool
> destroys them too. "Tenants are disposable" is not the same as "nothing
> here needs backing up."

### Path A — disposable tenants (CI runners, ephemeral sandboxes)

Recreate the pool **in place, under the same name**. Because the pool is
still called `default`, newly created containers land on it with no code or
config change.

1. Attach the new disk to the host and create the backing store on it — a
   ZFS pool with an `incus-local/containers` dataset, or a btrfs filesystem
   mounted at `/var/lib/incus/storage-pools`.
2. **Back up the platform Postgres** — see
   [DB-BACKUP-OPERATIONS.md](DB-BACKUP-OPERATIONS.md). This holds
   app-hosting state, metering and audit data, and it is the step that
   cannot be redone afterwards.
3. If Let's Encrypt rate limits are a concern, note the Caddy certificate
   state first (see [CADDY-SETUP.md](CADDY-SETUP.md)) — certs are
   re-issuable, but not indefinitely.
4. Destroy and recreate the `default` pool on the new disk. The daemon
   selects a per-container-volume driver automatically once the backing
   store exists; start it with `--require-isolated-storage` so a silent
   fallback to `dir` fails loudly instead.
5. Let core services and tenants be recreated, then restore Postgres.

### Path B — tenants with durable data

Run two pools side by side and move tenants across one at a time, so there
is no fleet-wide outage and rollback is per tenant:

```bash
incus storage create isolated zfs source=<dataset>
incus move <container> --storage isolated     # per tenant
```

This currently needs the storage pool name to be configurable, which it is
not yet — every container-creation path is pinned to the pool literally
named `default`, so newly created tenants would land back on `dir` and the
migration would silently undo itself. Tracked as issue #1213; do not use
Path B until it lands.

### Verifying, either way

Use the **ratio** between a quiet baseline and a probe taken under
co-tenant load. A single number is not a signal — a `dir` pool measured at
rest is the fastest storage in the fleet.

```bash
containarium storage-probe probe          # quiet baseline, box B
containarium storage-probe load           # co-tenant load, box A
containarium storage-probe probe          # again in box B, while A runs
containarium storage-probe compare --baseline-ms <quiet> --under-load-ms <loaded>
```

See [STORAGE-CONTENTION-PROBE.md](STORAGE-CONTENTION-PROBE.md) and issue
#1206.
