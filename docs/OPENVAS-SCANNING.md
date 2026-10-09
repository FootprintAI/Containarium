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

Scanning is an action on a workload, so nothing is scanned by default.
`CONTAINARIUM_OPENVAS_OPT_IN` is a comma-separated list of container names.

- Empty (default): no container is scanned, and no GMP command is sent.
- Names: only those containers are scanned.
- `*`: every container. Use it only on hosts the operator owns.

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
