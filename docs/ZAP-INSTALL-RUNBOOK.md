# ZAP install — per-host setup and how to detect a missed one (#960)

OWASP ZAP (the DAST scanner behind `security_scan --kind=zap`) is **not**
bundled with the daemon and is **not** installed automatically. Each host
that should run ZAP scans needs an explicit, one-time `InstallZap` call
against that host's daemon — there is no fleet-wide default-on install.

## Why this is a separate step

`InstallZap` downloads a multi-hundred-MB release from
`github.com/zaproxy/zaproxy`, installs a JRE if missing, and extracts it into
`/opt/zap` inside the host's security container (`containarium-core-security`,
see `internal/zap/installer.go`). That's a meaningful amount of work and
external network I/O to run unconditionally on every daemon boot, so it's
gated behind an admin-triggered call instead.

## Symptom of a missed install (fixed in #960)

Before #960, a host where `InstallZap` was never run would fail ZAP scan
jobs silently and repeatedly: `EnsureDaemonRunning` tried to start
`zap.sh` regardless of whether it existed. Because the start command is
backgrounded (`&`) inside `bash -c` via `incus exec`, the "command not
found" only landed in a log file inside the container — `incus exec`
itself still exited 0. The readiness loop then polled for the full 120
seconds before giving up with a generic timeout, indistinguishable from a
genuinely slow-starting daemon, and this repeated on every subsequent scan
job forever (no code path ever installed ZAP on its own).

As of #960, `EnsureDaemonRunning` checks installation status first and
fails immediately with a clear "ZAP is not installed" error instead. That
turns the symptom from "mysterious 120s timeouts in the logs, forever"
into an unambiguous, fast error — but you still have to notice it and run
the install.

## Detecting an uninstalled host proactively

Don't wait for a scan job to fail. Check before it matters:

```bash
# CLI — exit code / message tells you directly
containarium zap-install
# → "ZAP install OK: ..." (freshly installed) or
#   "ZAP install OK: ZAP is already installed and active" (no-op, safe to re-run)
```

Or read status without mutating anything, via `GET /v1/zap/config`
(`zap_available` in the response) — this is what
`Manager.ZapAvailable()` / `Scanner.Available()` report, and what the
webui's ZAP panel and `security_scan`'s preconditions are backed by.

Run this check as part of onboarding any new host into the fleet, right
alongside the sentinel-auth-secret and other per-host setup steps (see
[SENTINEL-AUTH-SECRET.md](./SENTINEL-AUTH-SECRET.md) for that pattern) —
"add a host" checklists should include "confirm `zap_available: true`" the
same way they include "confirm the sentinel secret is provisioned."

## Installing

```bash
export CONTAINARIUM_SERVER_URL=http://localhost:8080   # or your daemon's address
export CONTAINARIUM_JWT_TOKEN=<admin-scoped JWT>        # RequireRole(RoleAdmin)

containarium zap-install
```

This calls the same underlying Go function (`ZapServer.InstallZap` →
`Installer.InstallZap`) that the `install_zap` MCP tool and the raw
`POST /v1/zap/install` REST endpoint use — one code path, three surfaces,
per this repo's CLI-first convention. It's idempotent: running it again on
an already-installed host reports success without redoing the download.

Expect the download + extract step to take on the order of a minute or two
depending on the host's network link to GitHub — this is a one-time cost
per host, not per scan.
