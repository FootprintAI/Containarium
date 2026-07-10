# incus-watchdog

Force-recovers a wedged incus API (#755).

## The problem

`incusd` can hang with its process alive but its unix-socket API unresponsive:
a cgo call into liblxc's command protocol blocks forever in `recvmsg()` on an
unresponsive container monitor (the command socket has **no receive timeout**),
holding a lock that wedges every other API request behind it. It recurs under
container-churn workloads (create/delete storms — e.g. CI verifiers). Root cause
+ upstream fix: [lxc/lxc#4708](https://github.com/lxc/lxc/pull/4708).

`systemctl restart incus` does **not** reliably recover it — incusd's own
SIGTERM/SIGQUIT handlers are part of the deadlock, so the stop hangs until
`TimeoutStopSec` (incus ships a long one). The reliable recovery is **SIGKILL to
the main process** (unblockable). Because instances run in their own
`lxc.payload.*` scopes — not as children of incusd — **they survive** the restart.

## What it does

A tiny systemd service loops: probe the incus API on an interval; after N
**consecutive** probe timeouts, `systemctl kill -s SIGKILL --kill-who=main
incus.service` then `systemctl start`. Two consecutive failures are required so
one slow probe doesn't cause a needless restart.

## Install (per host running incus)

```bash
sudo install -m 0755 incus-watchdog.sh /usr/local/bin/incus-watchdog.sh
sudo install -m 0644 incus-watchdog.service /etc/systemd/system/incus-watchdog.service
sudo systemctl daemon-reload
sudo systemctl enable --now incus-watchdog.service
sudo systemctl status incus-watchdog.service --no-pager
journalctl -t incus-watchdog -f      # watch probes / recoveries
```

## Tuning (env in the unit, or an EnvironmentFile)

| var | default | meaning |
| --- | --- | --- |
| `INCUS_WATCHDOG_INTERVAL` | `45` | seconds between probes |
| `INCUS_WATCHDOG_PROBE_TIMEOUT` | `25` | seconds before a probe is deemed failed |
| `INCUS_WATCHDOG_FAIL_THRESHOLD` | `2` | consecutive fails before a restart |
| `INCUS_WATCHDOG_UNIT` | `incus.service` | unit to recover |
| `INCUS_WATCHDOG_SETTLE` | `15` | seconds to wait after a restart before probing |

With the defaults, a wedged API is recovered within ~2 minutes (two failed
probes), and a healthy host is never touched. This is a bridge until the
upstream liblxc receive-timeout (lxc/lxc#4708) ships and is built into incus.
