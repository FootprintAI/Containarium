# Runbook: dead-man alert for backend liveness (GCP Cloud Monitoring)

**Applies to:** the opt-in cloud-native metrics export (`containarium
monitoring export`, design: `docs/CLOUD-NATIVE-METRICS-EXPORT-DESIGN.md`).
**Goal:** page an operator when a backend goes silent — host or daemon
dead, wedged, or network-partitioned from the cloud — *out of band*, so
the alert does not fate-share with the thing it is watching.

## Why this exists

Host-local alerting (vmalert on the backend's own VictoriaMetrics LXC)
cannot report that its host is dead: when the host dies, the alerter dies
with it. The metrics export emits a **heartbeat series** to the cloud
provider's own monitoring every interval; a **metric-absence** alert
policy there fires precisely when that series stops arriving. Nothing on
the backend needs to survive for the alert to work — that is the whole
point.

## The heartbeat series

| Field | Value |
|---|---|
| Metric (OTel instrument) | `containarium.export.heartbeat` |
| Cloud Monitoring metric type | `workload.googleapis.com/containarium.export.heartbeat` |
| Monitored resource | `gce_instance` (GCP resource detector) |
| Kind / value | gauge, constant `1` |
| Labels | `backend_id`, `hostname`, `daemon_version` |
| Emit cadence | every export interval (default 60s, floor 60s) |

The heartbeat is emitted on its own callback, **independent of the host
metric sources**. A transient source error (e.g. incus briefly
unavailable) skips the host series for that tick but still emits the
heartbeat — a source hiccup is not backend death and must not trip this
alert. The series stops if and only if the daemon stops exporting: host
down, daemon down, or the daemon cannot reach Cloud Monitoring.

## Prerequisites

1. Export enabled on the backend and confirmed healthy:

   ```bash
   containarium monitoring export enable --provider gcp
   containarium monitoring export status   # last_success_at recent, no last_error
   ```

2. The series is arriving in the project. Confirm the metric descriptor
   exists (it is created on first ingest, usually within ~2 minutes):

   ```bash
   gcloud monitoring metrics-descriptors list \
     --project="${PROJECT_ID}" \
     --filter='metric.type = "workload.googleapis.com/containarium.export.heartbeat"'
   ```

3. A notification channel to page (email/PagerDuty/Slack/etc.). To list
   existing ones:

   ```bash
   gcloud alpha monitoring channels list --project="${PROJECT_ID}" \
     --format='table(name, type, displayName)'
   ```

## Create the dead-man alert policy

Write the policy to a file (`deadman-heartbeat-policy.json`). Replace
`${PROJECT_ID}` and `${CHANNEL_ID}` with your project and notification
channel id.

```json
{
  "displayName": "Containarium backend dead-man (heartbeat absent)",
  "documentation": {
    "content": "The containarium.export.heartbeat series stopped arriving from a backend. The daemon or host is dead, wedged, or network-partitioned from Cloud Monitoring. Check the backend host and the containarium daemon; this alert fires precisely because the backend went silent, so host-local dashboards may be unreachable.",
    "mimeType": "text/markdown"
  },
  "combiner": "OR",
  "conditions": [
    {
      "displayName": "Heartbeat absent for 5m (per backend)",
      "conditionAbsent": {
        "filter": "resource.type = \"gce_instance\" AND metric.type = \"workload.googleapis.com/containarium.export.heartbeat\"",
        "duration": "300s",
        "aggregations": [
          {
            "alignmentPeriod": "60s",
            "perSeriesAligner": "ALIGN_MEAN"
          }
        ],
        "trigger": { "count": 1 }
      }
    }
  ],
  "notificationChannels": [
    "projects/${PROJECT_ID}/notificationChannels/${CHANNEL_ID}"
  ],
  "alertStrategy": {
    "autoClose": "1800s"
  }
}
```

Create it:

```bash
gcloud alpha monitoring policies create \
  --project="${PROJECT_ID}" \
  --policy-from-file=deadman-heartbeat-policy.json
```

### Why these values

- **`conditionAbsent`** is the metric-absence ("dead-man") condition
  type — it fires when *no* data matches the filter for `duration`,
  which is exactly what a stopped heartbeat looks like. A threshold
  condition would not fire on absence.
- **`duration: 300s`** with a **60s** export interval tolerates a few
  dropped batches (transient export failure, one slow tick) before
  paging — five missed heartbeats, not one. Raise it if your interval is
  longer; keep it at a small multiple of the interval.
- **`alignmentPeriod: 60s`** matches the emit cadence so each interval is
  one aligned point.
- The **filter has no `backend_id`**, so the policy covers every backend
  exporting into the project. Cloud Monitoring evaluates absence
  per-time-series, so one silent backend fires while the others stay
  green. To scope to a single backend, add
  `AND metric.label.backend_id = "<backend-id>"`.
- **`autoClose: 1800s`** clears the incident once heartbeats resume.

## Verify (live)

This is the acceptance test for the alert and can only be done against a
real project with real ingestion — it is not reproducible in CI:

1. With export enabled and the policy created, confirm the series in
   Metrics Explorer (metric
   `workload.googleapis.com/containarium.export.heartbeat`) shows a flat
   line at `1`.
2. Stop the daemon on the backend (`systemctl stop containarium` or the
   equivalent for your deployment).
3. Wait for `duration` + one alignment period (~6 minutes with the values
   above). The policy transitions to **firing** and the notification
   channel pages.
4. Restart the daemon; heartbeats resume within one interval and the
   incident auto-closes.

Record the fired-incident screenshot / link in your operator log.

## Tuning notes

- **False pages on export flakiness:** if the provider endpoint or the
  backend's egress is intermittently slow, widen `duration` (e.g. to
  `600s`) rather than lowering the export interval — the interval floor
  is a cost guard (custom metrics are billed per sample) and dropping it
  is not supported.
- **Cost:** one extra series per backend at one sample per interval;
  negligible next to the host/container series already exported.
- **Multi-cloud:** AWS export is not implemented yet; the equivalent
  there is a CloudWatch "missing data → breaching" alarm on the same
  heartbeat metric once an AWS sink lands.
