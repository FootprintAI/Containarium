# Drill record template

Copy this file once per drill and fill in every field. A field you could not
measure says why. It is never left blank and never estimated. Drills run on
a real host. This template does not replace running them. The runbook they
exercise is [UPGRADE-AND-ROLLBACK.md](UPGRADE-AND-ROLLBACK.md).

Keep filled-in records out of this repository if they name real hosts,
tenants or IPs. Commit only an anonymized summary (`<host>`, `<tenant>`).

## Common header

| Field | Value |
| --- | --- |
| Drill type | backup/restore, or upgrade-and-rollback |
| Setup | BYOC host, or self-hosted install |
| Date (UTC) and operator role | |
| Starting version (`containarium backends versions`) | |
| Target version, and previous tag for rollback | |
| Storage backend (ZFS or other) and backup destination | |
| Number of backends, and whether a sentinel is involved | |
| Commit of the runbook followed | |

## Backup/restore drill

| Step | Command run | Start (UTC) | End (UTC) | Result and evidence |
| --- | --- | --- | --- | --- |
| Write a known marker row to a tenant database, and record its time | | | | |
| Take a backup (`containarium backup create`) | | | | |
| Write a second marker after the backup | | | | |
| Restore-test (`containarium backup verify`) | | | | |
| Simulate loss, then restore (`containarium backup restore`) | | | | |
| Check which markers survived | | | | |
| Snapshot rollback of the same box (`containarium snapshot rollback`), ZFS only | | | | |

Derived figures:

- **Measured RTO:** time from the start of the restore until the tenant
  app answers again.
- **Measured RPO:** time between the last surviving marker and the loss.
- **What the restore did not bring back:** files outside Postgres
  (see #2372 and #2809).

## Upgrade-and-rollback drill

| Step | Command run | Start (UTC) | End (UTC) | Result and evidence |
| --- | --- | --- | --- | --- |
| Pre-checks from the runbook | | | | |
| Upgrade (`containarium backends upgrade`) | | | | |
| Post-upgrade checklist | | | | |
| Forced watchdog rollback: install a build that fails `/health`, then confirm `.old` came back | | | | |
| Manual rollback (`--github-tag <previous-tag> --allow-downgrade`) | | | | |
| Post-rollback checklist | | | | |

Derived figures:

- **Measured upgrade downtime per backend:** from the restart until `/health` returns 200.
- **Measured rollback RTO:** automatic and manual, given separately.
- **Tenant impact seen:** dropped sessions, stopped containers, failed requests.

## Findings

List each place where the runbook was wrong or unclear, with the issue
filed for it. Paste the drill's measured numbers into the runbook's RTO and
RPO table, citing this record.
