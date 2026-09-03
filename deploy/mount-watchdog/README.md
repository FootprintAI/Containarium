# mount-watchdog

Detects and recovers `containarium.service` left permanently dead by a
`RequiresMountsFor` dependency failure (#1317).

## The problem

`containarium.service` ships `Wants=incus.service`, not `Requires=`,
specifically to avoid a hard dependency killing its start job with no retry
(#1152). A host that mounts `/var/lib/incus` from external or encrypted
storage has to reintroduce that dependency class via
`RequiresMountsFor=/var/lib/incus` — otherwise the daemon can start against
an empty, not-yet-mounted directory.

`RequiresMountsFor` has **no retry semantics**: a transient failure anywhere
in the mount's own dependency chain (a LUKS `systemd-cryptsetup@` unit, or
the `.device` unit underneath it missing a udev event) leaves
`containarium.service` `inactive (dead)` **permanently** — zero journal
entries for that boot, no alert, no automatic recovery. See
[docs/NODE-VM-PROVISIONING.md](../../docs/NODE-VM-PROVISIONING.md#encrypted--external-storage-for-varlibincus)
for the preventive fix (an `ExecStartPost` udev-kick drop-in on the
cryptsetup unit, which stops the failure from happening in the first place).
This watchdog is the second layer: it catches the failure if it happens
anyway and recovers without an operator noticing first — the same role
[`deploy/incus-watchdog`](../incus-watchdog/) plays for a different
silent-failure class in `incusd` itself.

## What it does

A tiny systemd service loops on an interval, checking whether `SERVICE`
(default `containarium.service`) is enabled but not active while
`MOUNTPOINT` (default `/var/lib/incus`) is not currently mounted — the exact
#1317 signature. An ordinary crash, or an exhausted `Restart=on-failure`,
leaves the mount up, so this check does not false-positive on those cases.

On detection it replays the incident's proven manual recovery: re-announce
every `/dev/mapper/*` device to udev (recovers a `.device` unit stuck
waiting on a lost/delayed "add" event), `systemctl reset-failed` the
specific unit classes the incident named (never a blanket reset, which would
also clear unrelated services' failed-state triage signal), then
`systemctl start` the service. Failure to recover logs an `ALERT` line via
`logger` so it reaches the host's normal journal-based alerting instead of
staying silent.

## Install (per host that gates `containarium.service` on an
external/encrypted `/var/lib/incus` mount)

```bash
sudo install -m 0755 mount-watchdog.sh /usr/local/bin/mount-watchdog.sh
sudo install -m 0644 mount-watchdog.service /etc/systemd/system/mount-watchdog.service
sudo systemctl daemon-reload
sudo systemctl enable --now mount-watchdog.service
sudo systemctl status mount-watchdog.service --no-pager
journalctl -t mount-watchdog -f      # watch checks / recoveries
```

Pair with the `ExecStartPost` udev-kick drop-in in
[docs/NODE-VM-PROVISIONING.md](../../docs/NODE-VM-PROVISIONING.md#encrypted--external-storage-for-varlibincus)
— that fix prevents the race; this watchdog is the backstop if it happens
anyway (e.g. via a code path other than the specific LUKS instance the
drop-in targets).

## Tuning (env in the unit, or an EnvironmentFile)

| var | default | meaning |
| --- | --- | --- |
| `MOUNT_WATCHDOG_INTERVAL` | `60` | seconds between checks |
| `MOUNT_WATCHDOG_MOUNTPOINT` | `/var/lib/incus` | path that must be mounted |
| `MOUNT_WATCHDOG_SERVICE` | `containarium.service` | unit that depends on it |

A host that doesn't gate `containarium.service` on an external mount doesn't
need this unit at all — `wedged()`'s `enabled` check only fires once
`RequiresMountsFor` is actually in play, but there is no reason to run an
idle watchdog on hosts where the failure class can't occur.
