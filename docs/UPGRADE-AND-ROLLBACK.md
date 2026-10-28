# Upgrade and rollback runbook

How to upgrade a Containarium daemon, check the result, and roll back,
using only the mechanisms that exist in the code today. Every step names
the source it relies on. Tracked in #2563.

> **Status: skeleton.** No drill has been run against this runbook yet.
> Every RTO and RPO below is **TBD — measured by drill**, and nothing here
> is a claim that a drill has proven. Record drills with
> [DRILL-RECORD-TEMPLATE.md](DRILL-RECORD-TEMPLATE.md).

Related: [RELEASE-PROCESS.md](RELEASE-PROCESS.md) (cutting a release),
[DISASTER-RECOVERY.md](DISASTER-RECOVERY.md) (host loss),
[DB-BACKUP-OPERATIONS.md](DB-BACKUP-OPERATIONS.md) (database backups).
CI checks the commands and links on this page against the real CLI
(`internal/cmd/runbook_drift_test.go`).

## The mechanisms

| Mechanism | What it does | Source |
| --- | --- | --- |
| Sentinel auto-update | When the daemon has a sentinel URL, it checks the sentinel every 5 minutes (first check 2 minutes after start) and installs a changed binary. | [autoupdate.go](../internal/server/autoupdate.go), [dual_server.go](../internal/server/dual_server.go) |
| On-demand upgrade | `containarium backends upgrade [backend-id]` runs the same check now. `--github-tag` installs a named GitHub release tag instead; a tag older than the running version is refused unless `--allow-downgrade` is also given. The `upgrade_backend` MCP tool takes the same `github_tag` and `allow_downgrade` arguments. `--force` re-installs a matching binary. | [backends_upgrade.go](../internal/cmd/backends_upgrade.go), [github_upgrade.go](../internal/server/github_upgrade.go) |
| Pre-swap checks | The SHA-256 is checked, then the new binary must run `version`. The running binary is renamed to `.old` and the new one moved in. | [autoupdate.go](../internal/server/autoupdate.go) |
| Upgrade watchdog | `containariumd upgrade-watchdog` (hidden) is started by the daemon before it restarts. It waits 10 s, then polls `/health` every 5 s for 90 s. Its output is appended to `upgrade-watchdog.log` in the binary's directory (mode 0600). On success it renames `.old` to `.prev`, replacing the `.prev` of the earlier upgrade. On timeout it moves `.old` back and runs `systemctl restart containarium`. | [upgrade_watchdog.go](../internal/cmd/upgrade_watchdog.go), [autoupdate.go](../internal/server/autoupdate.go) |
| Version overview | `containarium backends versions` lists each backend's version against the latest release. | [backends_versions.go](../internal/cmd/backends_versions.go) |
| Container snapshots | `containarium snapshot create`, `list` and `rollback`. ZFS backends only. | [snapshot.go](../internal/cmd/snapshot.go), [container_rollback.go](../internal/server/container_rollback.go) |
| Database backups | `containarium backup create`, `verify` and `restore`. These are logical Postgres dumps of tenant databases only (#2372). | [backup_restore.go](../internal/cmd/backup_restore.go), [DB-BACKUP-OPERATIONS.md](DB-BACKUP-OPERATIONS.md) |
| Host recovery | `containariumd recover` rebuilds the network, pool and profile from a surviving ZFS disk. | [DISASTER-RECOVERY.md](DISASTER-RECOVERY.md) |
| Fleet deploy script | Copies one binary to the sentinel, the primary and the peers. On the sentinel and primary it keeps the replaced binary as `containariumd.old`, checks health after the restart, and on failure restores `.old` and stops the deploy. It starts no watchdog. | [deploy-binary.sh](../scripts/deploy-binary.sh) |
| Helm upgrade lane | CI installs the previous published chart, upgrades it to the target version, then runs `helm rollback` to the first revision and checks that revision serves again. | [helm-install-upgrade.yml](../.github/workflows/helm-install-upgrade.yml), [helm-install-upgrade.sh](../scripts/ci/helm-install-upgrade.sh) |

Limits a reader needs to know before relying on these:

- **The watchdog only checks `/health`.** A release that answers `/health`
  but is broken in some other way stays installed. Its predecessor is kept
  as `.prev` (see Rollback), but nothing restores it automatically.
- **The downgrade guard is conservative.** `--github-tag` refuses a tag
  older than the running version unless `--allow-downgrade` is given. It
  refuses only when both versions parse as semver: `latest`, a dev build
  with a non-semver version, or an unparseable tag is not blocked. A
  pre-release (`v1.2.0-rc1`) counts as older than its release (`1.2.0`).
  The sentinel path has no such check. Whether a downgrade works after an
  upgrade has changed state is not established.
  For example, the 0.116.0 retention clamp rewrites stored rows (see
  [CHANGELOG.md](../CHANGELOG.md)). Read each release's **Upgrading** notes.

## Who can do what

This is the access the code enforces today. It is also the default split for
a partner operator until a different one is agreed.

| Action | Needs | Enforced in |
| --- | --- | --- |
| `containarium backends upgrade` | admin role plus the `containers:write` scope (`containers:read` for `GetUpgradeStatus`); tokens with no scopes claim stay unrestricted. Refused against the hosted control plane. | `TriggerUpgrade` in [container_server.go](../internal/server/container_server.go), `isCloudTarget` in [backends_upgrade.go](../internal/cmd/backends_upgrade.go) |
| `containarium snapshot create` / `rollback` | `containers:write`, and you must be the tenant or an admin | `snapshotDatasetFor` in [container_snapshot.go](../internal/server/container_snapshot.go) |
| `containarium snapshot list` | `containers:read`, and you must be the tenant or an admin | same |
| `containarium backup create` / `restore` / `prune` | `backups:write` | [backup_server.go](../internal/server/backup_server.go) |
| `containarium backup verify` | `backups:verify`, or `backups:write` (deprecated: accepted this release only and logged as `DEPRECATED`; re-mint verifier tokens with `backups:read,backups:verify` before the next release) | same |
| `containarium backup list` / `get` | `backups:read` | same |
| `containarium debug <username>` | the tenant or an admin | `DebugContainer` in [debug_container.go](../internal/server/debug_container.go), `AuthorizeTenant` in [authz.go](../internal/auth/authz.go) |
| `containariumd recover`, `containarium doctor`, `containarium service status` | a shell on the host. The DR guide runs `recover` with `sudo`. | [DISASTER-RECOVERY.md](DISASTER-RECOVERY.md) |

Scoped tokens are minted with `containarium token generate --scopes`
([scopes.go](../internal/auth/scopes.go)). For SSH problems, start with
`containarium debug <username>`.

## Before you upgrade

```bash
# 1. Record what is running now.
containarium backends versions --server http://<host>:8080
# 2. Check the host can run the daemon (run on each backend host).
sudo containarium doctor
# 3. Snapshot each tenant container you cannot afford to lose (ZFS only).
containarium snapshot create <username> --name before-upgrade --server <host>
# 4. Take a fresh database backup, then restore-test it.
containarium backup create <username> --database app --dest gcs \
  --gcs-bucket gs://<your-backup-bucket>/pg --server <host>
containarium backup verify <backup-id> --target <username> --server <host>
```

Also read the target release's **Upgrading** section in
[CHANGELOG.md](../CHANGELOG.md). Write down the previous tag: you need it to
roll back.

## Upgrade

Run one backend at a time. Check each one before you start the next.

```bash
# Single host: the binary the sentinel serves, or a named release tag.
containarium backends upgrade --server http://<host>:8080
containarium backends upgrade --github-tag <target-tag> --server http://<host>:8080
# Multi-backend: list the backend ids, then upgrade one peer at a time.
containarium backends list --server http://<host>:8080
containarium backends upgrade <backend-id> --server http://<host>:8080
```

- **The upgrade is asynchronous.** The command returns a job id and the
  daemon restarts. A peer restarts `containarium-tunnel` first, then
  `containarium` (`checkAndUpdate` in [autoupdate.go](../internal/server/autoupdate.go)).
- **A binary on the sentinel goes to every backend.** Each daemon with a
  sentinel URL installs whatever the sentinel serves within about 5 minutes.
  Uploading a binary to the sentinel is therefore a fleet-wide rollout, not
  a staged one.
- **The sentinel itself** is upgraded by
  [deploy-binary.sh](../scripts/deploy-binary.sh), which also does the primary
  and the peers. Set `PRIMARY_SERVICE` and `SENTINEL_SERVICE` to the host's
  real unit names; the script's header explains why.
  After each restart the script waits up to `HEALTH_TRIES` x `HEALTH_INTERVAL`
  seconds (defaults 15 x 2, so 30 seconds). The primary passes on the first
  successful `PRIMARY_HEALTH_URL` check. The sentinel passes only if its unit
  stays active for the whole window, so a binary that crashes a moment after
  start is rolled back. A successful sentinel deploy therefore always takes the
  full window (about 30 seconds by default). Both knobs must be plain decimal
  integers with no sign and no leading zeros: `HEALTH_TRIES` from 1 to 9999,
  `HEALTH_INTERVAL` from 0 to 9999 (a bare `0` is valid; `05` is not). The
  script refuses anything else, including an empty value, before its first
  `gcloud` call, and quotes the rejected value in the message. A healthy
  daemon that needs longer than the window is rolled back too: raise `HEALTH_TRIES` (for example `HEALTH_TRIES=60`) before
  deploying to a slow host.
- **Kubernetes:** `helm upgrade` with the published chart is what CI tests
  ([helm-install-upgrade.sh](../scripts/ci/helm-install-upgrade.sh)).

## After the upgrade: check

- [ ] `containarium backends versions --server http://<host>:8080` shows the target version on every backend.
- [ ] `containarium service status` on each host shows the unit active.
- [ ] `sudo containarium doctor` passes on each host.
- [ ] `containarium list --server <host>` shows the containers in the state they were in before.
- [ ] `containarium debug <username>` is clean for a sample tenant.
- [ ] On a BYOC backend, run the checks in [BYOC-BACKEND-BRINGUP.md](BYOC-BACKEND-BRINGUP.md#verify).

### Sentinel sshpiperd unit

Sentinel units are not part of the binary. The sshpiperd unit comes from
`sshpiper.service.tmpl` or the sentinel startup script, so a binary-only
rollout (`containarium backends upgrade`, `deploy-binary.sh`) does not change
it. A release that adds a sshpiperd flag therefore needs the unit re-rendered,
or the startup script re-applied, on each existing sentinel, then sshpiper
restarted. v0.119.0 is one: it adds `--login-grace-time 90s`, and without it
sshpiperd keeps its 30 s default and drops a login while a user approves a
device (the approval cap is 60 s). It matters only where device approval is
on (`ssh-authz-plugin --ssh-authz-enforce`). Check on the sentinel:

```bash
ps -eo args | grep '[s]shpiperd'
```

The line must contain `--login-grace-time 90s`. When `--ssh-authz-enforce` is
on, the plugin also logs a `WARN ssh-authz: parent sshpiperd ...` line at
startup if the flag is missing or shorter than 70 s (the 60 s cap plus a 10 s
margin). Re-rendering the unit on self-update is not done (#3125).

## Rollback

**Automatic.** If `/health` does not return 200 within the watchdog window,
the watchdog restores `.old` and restarts the daemon. If there is no `.old`,
it gives up with "manual intervention required". The watchdog's output,
including the reason for a rollback, is in `upgrade-watchdog.log` beside the
binary (for example `/usr/local/bin/upgrade-watchdog.log`). Read it with
`sudo cat`; the file is appended to across upgrades.

**Manual, release passed `/health` but is broken.** After a healthy check
the previous binary is kept as `/usr/local/bin/containariumd.prev` (path is
the binary path plus `.prev`). It lives until the next upgrade's healthy
check replaces it. Restore it (`mv` swaps the file atomically; `cp` over a
running binary fails with "text file busy"):

```bash
sudo mv /usr/local/bin/containariumd.prev /usr/local/bin/containariumd
sudo systemctl restart containarium
```

**Manual, daemon still up.** Install the previous tag, then check again. `--allow-downgrade` is required because the tag is older than the running version:

```bash
containarium backends upgrade --github-tag <previous-tag> --allow-downgrade --server http://<host>:8080
containarium backends versions --server http://<host>:8080
```

**Manual, daemon down.** Copy the previous release binary over
`/usr/local/bin/containariumd` and restart the unit. This is the same thing
[deploy-binary.sh](../scripts/deploy-binary.sh) does. The release assets are
listed in [RELEASE-PROCESS.md](RELEASE-PROCESS.md#what-a-tag-push-actually-publishes).

**Tenant storage.** This discards everything written since the snapshot.
The container is left stopped.

```bash
containarium snapshot rollback <username> before-upgrade --force --server <host>
containarium wake <username> --server <host>
```

**Tenant database.** Add `--clean` to drop objects before the restore:

```bash
containarium backup restore <backup-id> --clean --server <host>
```

**Host lost.** Follow [DISASTER-RECOVERY.md](DISASTER-RECOVERY.md):
run `containariumd recover --dry-run` as root first, then again without
`--dry-run`.

## RTO and RPO targets

No target has been measured yet. "Bound" is what the code allows, not
something a drill has shown.

| Component | Recovered by | RTO | RPO | Bound from code or config |
| --- | --- | --- | --- | --- |
| Daemon binary, health check fails | Watchdog | TBD — measured by drill | No data involved | The watchdog stops waiting after 10 s + 90 s. |
| Daemon binary, health check passes but the release is bad | `backends upgrade --github-tag <previous-tag> --allow-downgrade` | TBD — measured by drill | No data involved | — |
| Tenant container storage | `snapshot rollback` | TBD — measured by drill | TBD — measured by drill | Only as recent as the last snapshot. Nothing in this repo schedules snapshots. |
| Tenant database | `backup restore` | TBD — measured by drill | TBD — measured by drill | The shipped timer runs daily at 02:30 ([containarium-backup.timer](../scripts/containarium-backup.timer)). WAL archiving is not provided. |
| Whole box: files, packages, non-Postgres state | Nothing today | Not recoverable from backup | Not recoverable from backup | Backup is DB-only (#2372). Whole-box backup is in progress (#2809). |
| Host | `containariumd recover` | TBD — measured by drill | TBD — measured by drill | Only works if the ZFS data disk survives. |

**Read before quoting an RPO:** until #2809 ships, a box can only be
restored from backup as far as its Postgres databases go. Anything else on
the box can only come back from a ZFS snapshot on the same pool, or from
the surviving disk. An RPO for "the box" cannot honestly be promised yet.

## Supported-release policy

This block is identical to the one in [SECURITY.md](../SECURITY.md#supported-versions).
CI fails if they differ.

<!-- support-policy:begin -->
Containarium is pre-1.0; security fixes land on `main` and are
included in the next tagged release. There is no LTS branch.
Operators running prior releases should upgrade to the latest tag.

From Partner Release 1.0 (target 2026-12-31), each Partner Release has
a 12-month security-fix window. If v1.0 is not cut by then, the Partner
Release is served from a release maintenance branch.

| Branch / version | Supported     |
| ---------------- | ------------- |
| `main`           | ✅ active     |
| Latest release   | ✅ active     |
| Partner Release (from 1.0) | ✅ security fixes for 12 months |
| Older releases   | ❌ upgrade    |
<!-- support-policy:end -->

## Drills still owed

Partner Release 1.0 needs these drills, each recorded with
[DRILL-RECORD-TEMPLATE.md](DRILL-RECORD-TEMPLATE.md):

1. A backup/restore drill on a BYOC host and on a self-hosted install. Its
   timings fill in the RTO and RPO table above.
2. An upgrade-and-rollback drill on each of those two setups, following
   this runbook from start to finish.
