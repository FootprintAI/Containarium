# OpenVAS (Greenbone) scanning

The `openvas` pentest module (#2426) scans containers with Greenbone. It runs
beside the nuclei and trivy modules and writes into the same findings store.

## Where it runs

Greenbone runs in a dedicated Incus box (default `containarium-core-openvas`,
override with `CONTAINARIUM_OPENVAS_BOX`), never inside tenant boxes. The
daemon drives it with `gvm-cli` over gvmd's unix socket
(`/run/gvmd/gvmd.sock`). Credentials come from the gvm-tools config inside the
scanner box, so none appear in a command line. The module is loaded only when
`/usr/bin/gvm-cli` exists in that box (re-checked on tool refresh).

Provisioning the box and syncing the feed is an operator step; feed age and
last-run status are not yet exposed through the API.

## Who gets scanned: opt-in only

Scanning is an action on a workload, so nothing is scanned by default. A
container is scanned only when one of these allows it, checked in this order:

1. **A recorded decision** for the container. It wins over everything else, in
   both directions: a recorded refusal beats the operator list below, and a
   recorded opt-in works without an entry in it.
2. **The operator list**, `CONTAINARIUM_OPENVAS_OPT_IN`, a comma-separated list
   of container names. `*` selects every container; use it only on hosts the
   operator owns.
3. Otherwise the container is not scanned. If the recorded decision cannot be
   read (database error), the container is skipped; consent is never assumed.

Record a decision with the CLI (the container's owner or an admin may):

```
containarium security scan-opt-in allow  <container> --reason "..."
containarium security scan-opt-in refuse <container> --reason "..."
containarium security scan-opt-in list [container]    # all containers needs admin
```

REST: `PUT /v1/pentest/scan-opt-ins/{container_name}` and
`GET /v1/pentest/scan-opt-ins`. Each decision stores who made it, when, and
why (the latest replaces the earlier one), and every change is written to the
audit log as `pentest.scan_opt_in.set` with the reason and the previous value.

Only container IPs are scanned; routes are skipped, as are core service boxes.

## Impact limits

- Scan config is Greenbone's "Full and fast", which excludes NVTs flagged
  dangerous (DoS, intrusive).
- At most two scan tasks run at once, however many pentest workers are busy.
- A scan that exceeds two hours is stopped.
- Targets and tasks are deleted after each scan.
- Results below QoD 70 are dropped.

## Severity mapping

CVSS 9.0+ critical, 7.0+ high, 4.0+ medium, above 0 low. Zero-score log
results are not recorded. Findings dedupe on (box IP, port, finding name).

## Not wired to auto-quarantine

Findings describe packages and services inside a box, so they never trigger
quarantine (see `security/AUTO-QUARANTINE.md`).
