# Quickstart: cloud-native metrics export — bare GCP VM to visible metrics + one alert

**Covers:** [#1073](https://github.com/FootprintAI/Containarium/issues/1073)
(bare VM → host metrics → one working alert, in ~10 minutes) and
[#1085](https://github.com/FootprintAI/Containarium/issues/1085) (enabling
the `platform` group on top, the committed GCM dashboard, and one platform
alert) — the single onboarding path the design doc
(`docs/architecture/cloud-export-domain-metrics.md`,
`docs/CLOUD-NATIVE-METRICS-EXPORT-DESIGN.md`) describes.

> **Verification status (read before relying on this doc for a release
> claim):** the IAM/ADC content, the measured cost estimate, and the
> generic-placeholder convention below are all in place. **What is
> explicitly NOT yet done:** an end-to-end walkthrough of this exact doc,
> on a genuinely fresh VM, by someone who did not build the feature —
> #1073's own hardest acceptance criterion. Until that happens, treat this
> as reviewed-but-unverified: report anything that doesn't match reality
> on [#1073](https://github.com/FootprintAI/Containarium/issues/1073)
> rather than silently working around it.

## 1. Provision a bare GCP VM

Any VM works; the only requirement is a service account with Cloud
Monitoring write access (step 3). Example, all placeholders generic:

```bash
gcloud compute instances create <VM_NAME> \
  --project="${PROJECT_ID}" \
  --zone="${ZONE}" \
  --machine-type=e2-standard-2 \
  --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud \
  --scopes=https://www.googleapis.com/auth/monitoring.write
```

`--scopes` here is the simplest path (grants the instance's default
service account monitoring-write via its VM scope); the IAM-role path in
step 3 is the more precise alternative if the default service account
already has broader scopes than you want.

## 2. Install Containarium

```bash
curl -fsSL https://raw.githubusercontent.com/footprintai/containarium/main/hacks/install.sh \
  | sudo bash
```

Installs Containarium + Incus + dependencies and starts the daemon —
nothing metrics-export-specific yet; this is the same install path as the
top-level README's quick start.

## 3. IAM and credentials — no keys, ever

Enabling export resolves **Application Default Credentials (ADC)** with
the Cloud Monitoring write scope and performs one dry-run token fetch
before persisting anything. There is no key file to create, copy, or
rotate:

- **On a GCE VM** (the common case for this quickstart): attach
  `roles/monitoring.metricWriter` to the VM's service account —
  `gcloud projects add-iam-policy-binding` with that role, targeting the
  VM's own service account, or use `--scopes` at VM-creation time as
  shown in step 1. ADC resolves this automatically from the metadata
  server; nothing to configure on the box itself.
- **On a workstation** (for local testing, not the production path):
  `gcloud auth application-default login`.
- **On BYOC / non-GCP hardware**: the probe fails closed — this is
  intentional, not a bug. See
  `docs/CLOUD-NATIVE-METRICS-EXPORT-DESIGN.md`'s BYOC section (#1078)
  for why, and what to use instead.

If the probe fails, the error is actionable and literal (this is the
real message the daemon returns, not paraphrased):

```
no Application Default Credentials found for GCP Cloud Monitoring
(run 'gcloud auth application-default login' for a workstation, or
attach a service account with the roles/monitoring.metricWriter IAM
role to this VM): <underlying error>
```

## 4. Enable export

```bash
containarium monitoring export enable --provider gcp
```

Omitting `--groups` defaults to `host` only — the #1070 host-infra series
(CPU/memory/disk load, container count) plus the always-on heartbeat.
Confirm:

```bash
containarium monitoring export status
# cloud metrics export: enabled (provider=gcp, groups=host, interval=60s)
```

## 5. Verify metrics are visible

Within ~2 minutes, in Cloud Monitoring → Metrics Explorer, query
`workload.googleapis.com/containarium.host.cpu.load_1m` (or any of the
other seven host series, or `workload.googleapis.com/containarium.export.
heartbeat`) filtered to your project — a real, moving data point confirms
the pipeline end to end.

## 6. Create one working alert (the dead-man heartbeat)

The fully worked `gcloud`/JSON recipe — a `conditionAbsent` policy that
pages when the heartbeat stops arriving — is documented in
[`docs/METRICS-EXPORT-DEADMAN-ALERT-RUNBOOK.md`](METRICS-EXPORT-DEADMAN-ALERT-RUNBOOK.md):
create it exactly as written there, then verify it fires by stopping the
daemon and watching the policy transition to firing (the runbook's own
"Verify (live)" section walks through this). That closes the "one working
alert" leg of this quickstart's 10-minute journey.

## Cost estimate (real numbers, not a hand-wave)

GCP Cloud Monitoring bills custom metrics at **$0.2580/MiB** of ingested
data, with the **first 150 MiB per billing account per month free**
([pricing](https://cloud.google.com/products/observability/pricing),
[worked examples](https://cloud.google.com/stackdriver/observability-pricing-examples)).
Each numeric data point (this exporter's fixed 60s interval = 1
point/minute) is 8 bytes by GCP's own sizing model, i.e. **~0.334
MiB/series/month**.

Containarium's own exported series counts are fixed and code-verified —
not estimated — so the only variable is container count:

| Containers | Fixed series (host+heartbeat+platform, worst case) | Container series (5×N) | Total series | MiB/month | Cost/month |
|---|---|---|---|---|---|
| 0 | ~16 | 0 | ~16 | ~5 | **$0** |
| 10 | ~16 | 50 | ~66 | ~22 | **$0** |
| 50 | ~16 | 250 | ~266 | ~89 | **$0** |
| 100 (design doc's "10x" scenario) | ~16 | 500 | ~516 | ~172 | **~$5.68** |

("Fixed series, worst case" = 8 host + 1 heartbeat + 6 fixed platform
series + up to a handful for BYOC peer count via `tunnel.state`, if the
`platform` group is enabled — the `host`-only default from step 4 is
just 9.)

At any realistic single-backend scale, this stays at or near $0/month —
the design's per-series allowlist and 60s-floor cost guard (see the
design doc's "Rejected alternatives" and #1070's original review) do
their job. This table supersedes the design doc's placeholder note ("the
documented cost table in #1073 is per-container-count") — it is that
table.

## Next: the `platform` group, its dashboard, and one platform alert (#1085)

Once the host-only baseline above is verified, opt into the richer
`platform` group (API health, provisioning outcomes, BYOC connectivity)
and the committed dashboard:

```bash
containarium monitoring export enable --provider gcp --groups host,platform
```

`--groups` is additive over `host` alone; this is purely opt-in and does
not change anything about the baseline above. Confirm:

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

### Import the committed dashboard

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

### Create one platform alert

Any of the platform series can back a Cloud Monitoring alert policy the
same way the host-side dead-man alert does. The fully worked example —
`gcloud`/JSON, a `conditionThreshold` on `containarium.platform.provision.
failures` that fires on a sustained run of provisioning failures (not a
single bad request) — is documented in
[`docs/METRICS-EXPORT-DEADMAN-ALERT-RUNBOOK.md`](METRICS-EXPORT-DEADMAN-ALERT-RUNBOOK.md#provisioning-failure-alert-1083):
create it exactly as written there.

## Verify (live)

Not reproducible in CI — verify against a real project:

1. `containarium monitoring export status` shows the groups you enabled.
2. Every enabled group's series appears in Metrics Explorer within ~2
   minutes (host-only: step 5 above; platform: the table above).
3. The dead-man heartbeat alert (step 6) fires when the daemon stops and
   clears when it resumes.
4. If the `platform` group is enabled: the imported dashboard renders all
   charts with real data, not "no data," and the platform alert policy
   fires under the condition it describes and clears once resolved.

**Still open:** none of the above has been run end-to-end by someone who
did not build the feature, on a genuinely fresh VM — see the verification
status callout at the top. That is the one piece of #1073 this doc cannot
close on its own.
