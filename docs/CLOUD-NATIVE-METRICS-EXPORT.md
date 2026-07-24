# Quickstart: cloud-native metrics export (host + platform groups)

**Scope of this doc (#1085):** enabling the `host` and `platform` metric
groups together, importing the committed GCM dashboard, and creating one
platform alert — the single pane of glass the design doc
(`docs/architecture/cloud-export-domain-metrics.md`) describes.

**Not in scope here:** the full "bare GCP VM → visible metrics" onboarding
walkthrough with a measured per-container-count cost estimate and
third-party live verification is tracked separately as
[#1073](https://github.com/FootprintAI/Containarium/issues/1073) — still
open pending a real GCP verification pass. This file gains that end-to-end
walkthrough once #1073 lands; until then it assumes export is already
enabled at the `host` level (see #1073 / the design doc's prerequisites)
and focuses on the `platform` group specifically.

## Prerequisites

- A backend already exporting the `host` group successfully:

  ```bash
  containarium monitoring export status   # last_success_at recent, no last_error
  ```

- `roles/monitoring.metricWriter` on the service account the daemon's
  ambient credentials (ADC) resolve to — no key files, no separate
  credential to manage.

## Enable both groups

```bash
containarium monitoring export enable --provider gcp --groups host,platform
```

`--groups` is additive over `host` alone; omitting it keeps the pre-#1081
host-only default, so this is purely opt-in. Confirm both groups are live:

```bash
containarium monitoring export status
# cloud metrics export: enabled (provider=gcp, groups=host,platform, interval=60s)
```

Within ~2 minutes, the platform series appear in Metrics Explorer
alongside the existing host series:

| Series | What it shows |
|---|---|
| `containarium.platform.api.requests` / `.api.errors` | API traffic by coarse outcome class (`code_class`) — [#1082](https://github.com/FootprintAI/Containarium/issues/1082) |
| `containarium.platform.provision.attempts` / `.failures` / `.duration_seconds_sum` | Container create/delete outcomes by `operation` — [#1083](https://github.com/FootprintAI/Containarium/issues/1083) |
| `containarium.platform.peers.connected` / `.tunnel.state` | BYOC peer connectivity, `peer_id` = enrolled host name — [#1084](https://github.com/FootprintAI/Containarium/issues/1084) |

## Import the committed dashboard

The platform charts (API errors, provisioning failures, peers connected)
sit alongside the host charts (CPU/memory/disk/containers) on one
dashboard, committed at
[`deploy/monitoring/gcm-containarium-hosts.json`](../deploy/monitoring/gcm-containarium-hosts.json)
so it's reproducible rather than a hand-built, undocumented artifact:

```bash
gcloud monitoring dashboards create \
  --project="${PROJECT_ID}" \
  --config-from-file=deploy/monitoring/gcm-containarium-hosts.json
```

Re-run the same command with `dashboards update` (matching the dashboard's
assigned name) after pulling a change to the committed JSON, so the live
dashboard never silently drifts from what's in the repo.

## Create one platform alert

Any of the platform series can back a Cloud Monitoring alert policy the
same way the host-side dead-man alert does. The fully worked example —
`gcloud`/JSON, a `conditionThreshold` on `containarium.platform.provision.
failures` that fires on a sustained run of provisioning failures (not a
single bad request) — is documented in
[`docs/METRICS-EXPORT-DEADMAN-ALERT-RUNBOOK.md`](METRICS-EXPORT-DEADMAN-ALERT-RUNBOOK.md#provisioning-failure-alert-1083):
create it exactly as written there. That runbook is also where the
underlying heartbeat dead-man alert (the `host`-group prerequisite this
doc assumes is already live) is documented, so it's the one place to look
for every alert policy this feature ships, regardless of which group it
watches.

## Verify (live)

Not reproducible in CI — verify against a real project, same as the
runbook's own verification sections:

1. `containarium monitoring export status` shows `groups=host,platform`.
2. Both group's series appear in Metrics Explorer within ~2 minutes.
3. The imported dashboard renders all charts (host + platform) with real
   data, not "no data."
4. The platform alert policy created above fires under the condition it
   describes and clears once the condition resolves.
