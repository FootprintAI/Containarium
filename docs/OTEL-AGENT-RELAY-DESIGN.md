# OTel sidecar image — design

**Status:** Draft
**Last updated:** 2026-05-16 (pivoted from "LXC-level systemd relay" to "docker-compose sidecar")
**Related:**
- [`docs/PLATFORM-SIDECAR-DESIGN.md`](PLATFORM-SIDECAR-DESIGN.md) — the generic platform-sidecar pattern this is the first instance of. **Read this first.**
- [`docs/OTEL-COLLECTOR-DESIGN.md`](OTEL-COLLECTOR-DESIGN.md) — the central gateway this sidecar forwards to.

## Context

This doc specifies the `containarium/otel-sidecar` Docker image — the first instance of the [platform sidecar pattern](PLATFORM-SIDECAR-DESIGN.md). The platform-pattern doc covers the registry, identity contract, naming, lifecycle, and why we picked the docker-compose sidecar shape over the rejected "systemd unit in LXC" approach. This doc covers only what's specific to telemetry:

- What the OTel sidecar's baked-in config looks like.
- How it overrides app-claimed identity attributes (`container.id`, `backend.id`).
- How it exports to the central `containarium-core-otelcollector` LXC.
- The OTel-specific failure cases.

## Image contract

`ghcr.io/footprintai/containarium-otel-sidecar:v1` is a thin wrapper over `otelcol-contrib`:

- **Base image:** the upstream `otel/opentelemetry-collector-contrib:0.110.0` (or whichever the central collector is also pinned to).
- **Listening ports:** `0.0.0.0:4318` (OTLP/HTTP), `0.0.0.0:4317` (OTLP/gRPC), `0.0.0.0:13133` (health check).
- **Required env vars at start:**
  - `OTEL_EXPORTER_OTLP_ENDPOINT` — central collector URL, e.g. `http://10.0.3.112:4318`.
  - `OTEL_RESOURCE_ATTRIBUTES` — the platform-stamped `container.id=<lxc-name>,backend.id=<host>` string.
  - `OTEL_SERVICE_NAME` — the tenant's per-service name (e.g. `payment-api`). Owned by the tenant; the sidecar passes it through.
- **Fail-closed startup:** missing any of the first two → log + exit non-zero. The third defaults to the LXC's username if unset.

## Baked-in config

The image ships a `config.yaml` baked at `/etc/otelcol-contrib/config.yaml`. The collector reads env vars from `${env:VAR_NAME}` references — same shape as the central collector's config.

```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
      grpc:
        endpoint: 0.0.0.0:4317

processors:
  # The whole point of the sidecar: override app-claimed identity
  # attributes with the platform-stamped values. `upsert` writes the
  # key whether or not the app already set it.
  resource:
    attributes:
      - key: container.id
        value: ${env:CONTAINARIUM_CONTAINER_ID}
        action: upsert
      - key: backend.id
        value: ${env:CONTAINARIUM_BACKEND_ID}
        action: upsert
      # service.namespace defaults to the LXC's tenant ID but the
      # app can override per-service via OTEL_SERVICE_NAME in its
      # own compose env.
      - key: service.namespace
        value: ${env:CONTAINARIUM_TENANT_ID}
        action: insert  # only-if-absent

  batch:
    timeout: 5s
    send_batch_size: 1024

extensions:
  health_check:
    endpoint: 0.0.0.0:13133

exporters:
  otlphttp:
    endpoint: ${env:OTEL_EXPORTER_OTLP_ENDPOINT}
    tls:
      insecure: true

service:
  extensions: [health_check]
  pipelines:
    metrics:
      receivers: [otlp]
      processors: [resource, batch]
      exporters: [otlphttp]
```

Notes:

- We use new env names (`CONTAINARIUM_CONTAINER_ID` / `CONTAINARIUM_BACKEND_ID` / `CONTAINARIUM_TENANT_ID`) rather than parsing `OTEL_RESOURCE_ATTRIBUTES` because the OTel config language can't split a comma-separated string at config-load time. Containarium's LXC env stamping populates all four (`OTEL_RESOURCE_ATTRIBUTES` + the three `CONTAINARIUM_*` keys) when `--monitoring=true`, so compose interpolation gets them for free.
- No traces / logs pipeline — same scope as the central collector. v2.
- No Prometheus scraping in the sidecar. The central collector handles scrape compatibility for legacy `/metrics` apps. The sidecar is OTLP-only; that's its whole job.

## Compose usage (canonical example)

```yaml
services:
  payment-api:
    image: my-payment-api:v1.2
    # Share network namespace with the sidecar — app reaches it at
    # localhost:4318 with no special compose plumbing.
    network_mode: "service:payment-api-otel"
    depends_on:
      payment-api-otel:
        condition: service_healthy
    environment:
      OTEL_EXPORTER_OTLP_ENDPOINT: http://localhost:4318
      OTEL_SERVICE_NAME: payment-api
      # OTEL_RESOURCE_ATTRIBUTES intentionally unset — the sidecar
      # overrides it anyway, and any value the app sets is dropped.

  payment-api-otel:
    image: ghcr.io/footprintai/containarium-otel-sidecar:v1
    restart: unless-stopped
    environment:
      # ${VAR} interpolation reads from the LXC env Containarium
      # stamps when --monitoring=true. Tenant doesn't fill in any
      # values — they're auto-resolved.
      OTEL_EXPORTER_OTLP_ENDPOINT: ${OTEL_EXPORTER_OTLP_ENDPOINT}
      CONTAINARIUM_CONTAINER_ID: ${CONTAINARIUM_CONTAINER_ID}
      CONTAINARIUM_BACKEND_ID: ${CONTAINARIUM_BACKEND_ID}
      CONTAINARIUM_TENANT_ID: ${CONTAINARIUM_TENANT_ID}
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:13133/"]
      interval: 10s
      timeout: 3s
      retries: 3
      start_period: 5s
```

`containarium sidecar otel compose <username>` will print this snippet pre-filled for the requesting LXC, so the tenant copy-pastes one command's output rather than reading docs.

## Identity override semantics

The sidecar's `resource` processor uses two different actions:

| Attribute | Action | Why |
|---|---|---|
| `container.id` | `upsert` | Platform owns this. If the app set it, replace. |
| `backend.id` | `upsert` | Same. |
| `service.namespace` | `insert` | Default it from the tenant ID, but allow app override (per-service grouping like `payment` vs `auth`). |
| `service.name` | (not touched) | App-owned. The app sets it via `OTEL_SERVICE_NAME` env or SDK API. |

This composes with the central collector's existing `attributes/identity` processor (which stamps `source.ip` from the connecting IP). Two layers of platform-controlled identity, each at a different scope:

- **Sidecar layer**: `container.id` / `backend.id` from the LXC's env. Defends against "app in container A claims to be container B" if both apps are in the same LXC.
- **Central layer**: `source.ip` from the TCP source address. Defends against "container A talks to a different VM's collector and tries to forge `source.ip`" — incusbr0's iptables guarantees the source IP is real.

## Why this beats the LXC-level systemd relay

The prior Draft of this doc proposed installing `otelcol-contrib` as a systemd unit inside each `--monitoring=true` LXC, lifecycle-managed by Containarium. That approach had three problems the sidecar pattern fixes:

1. **Platform reaching into tenant LXC.** The systemd relay was a Containarium-owned process the tenant couldn't see in `docker compose ps`. Operations surprises ("why is there a random otelcol-contrib eating 50MB?") were inevitable. With the sidecar, it's *in the compose file* — operators see it like any other service.
2. **Lifecycle coupling to RPCs.** Install/uninstall hooks on `CreateContainer --monitoring`, `ToggleMonitoring enable`, `ToggleMonitoring disable`, `AdoptMigratedContainer`. Each hook was a shell-exec into the LXC, with its own failure modes. The sidecar pivot removes all of those — lifecycle is `docker compose up/down`, owned entirely by the tenant.
3. **No per-service identity.** One systemd unit per LXC means all services share the same `container.id` namespace. Sidecars give each app its own collector instance with its own platform-stamped identity, so a 4-service compose stack actually has 4 well-attributed metric streams instead of one mixed stream.

## Failure modes

Most failure modes are inherited from the [platform sidecar pattern](PLATFORM-SIDECAR-DESIGN.md#failure-modes). OTel-specific:

| Failure | Effect | Mitigation |
|---|---|---|
| Central collector unreachable | `otlphttp` exporter buffers per `batch` config, then drops with backoff. App SDKs don't notice (they POST 200 from the local sidecar). | Surface via `otelcol_exporter_send_failed_total` on the sidecar's `:13133` health endpoint. |
| App sends 100k metrics/sec | `batch` processor caps; back-pressure flows back to the app's OTLP-HTTP POST. SDK applies its own buffering / drop policy. | Future: add a `memory_limiter` processor to the sidecar config. |
| Two sidecars in one LXC point at different central collectors | Shouldn't happen — `OTEL_EXPORTER_OTLP_ENDPOINT` comes from the LXC env, single source. | Documented; if tenant hand-edits compose to point at a different collector, that's their choice. |
| Sidecar's container.id env doesn't match the LXC's actual container name | Tenant edited the env in compose. Sidecar still works but `container.id` is whatever they wrote. | Documented; the sidecar trusts its env. Operators can audit via `docker compose config`. |

## Open questions

These are the OTel-sidecar-specific ones. The cross-cutting platform questions are in [platform-sidecar-design](PLATFORM-SIDECAR-DESIGN.md#open-questions).

| # | Question | Why it matters | Proposed answer |
|---|---|---|---|
| 1 | Image base: `otel/opentelemetry-collector-contrib` or custom-built `otel/builder`? | The contrib image is ~280MB; a custom minimal builder image with only the components we need is closer to 30MB. Pull-time-per-LXC matters when sidecars proliferate. | Contrib for v1 (less ceremony); switch to a custom-built minimal collector for v2 once we know what receivers/processors/exporters we actually need. |
| 2 | OTLP/gRPC receiver: ship or skip? | Some OTel SDKs default to gRPC. HTTP is simpler in compose. | Ship both. gRPC is "free" in the contrib image; tenants pick one. |
| 3 | `service.namespace` insert vs upsert? | If we insert (only-if-absent), apps can override per-service. If we upsert, apps can't claim a different namespace. | Insert. Apps overriding `service.namespace` to e.g. group services into "auth" / "payment" / "infra" is a legit use case. |
| 4 | Should the sidecar also pin `service.version` from a compose env? | Useful for canary / rollback metric breakdowns. | Yes, as `service.version` `insert` from `${SERVICE_VERSION}` env. Tenant sets per service; sidecar doesn't override. |
| 5 | What happens on `OTEL_RESOURCE_ATTRIBUTES` env unset but the three `CONTAINARIUM_*` envs set? | Backward compat: today's LXC env stamps `OTEL_RESOURCE_ATTRIBUTES` as the comma string; the sidecar wants three split values. | Daemon adds the three `CONTAINARIUM_*` env stamps alongside the existing `OTEL_RESOURCE_ATTRIBUTES`. Sidecar reads only the `CONTAINARIUM_*` ones; the comma string stays for non-sidecar apps that read it directly. |
| 6 | Health-check endpoint exposure | Should the sidecar expose `:13133` to the tenant's other containers, or keep it internal? | Expose. Operators want to curl it from neighboring containers when debugging. |

## Phased rollout

These phases nest under the [platform sidecar phased rollout](PLATFORM-SIDECAR-DESIGN.md#phased-rollout):

| Phase | Scope | Effort |
|---|---|---|
| **1. Image repo + Dockerfile** | `containarium-sidecars/otel-sidecar/Dockerfile`; bakes config + entrypoint script that validates env. | ~½ day |
| **2. GH Actions for build + sign + push to GHCR** | Reuse the main Containarium release workflow shape. Pinned to `:v1.0.0`. | ~½ day |
| **3. Smoke test on prod's devbox** | `docker run` the image locally pointing at the prod collector; verify OTLP forward + identity override. | ~½ day |
| **4. `containarium sidecar otel compose <username>` CLI subcommand** | Prints the ready-to-paste compose block for the named LXC. | ~½ day |
| **5. Daemon stamps the three `CONTAINARIUM_*` env vars** | Update `pkg/core/container/otel.go` to set them alongside existing `OTEL_*`. | ~½ day |
| **6. Update OTEL-COLLECTOR-DESIGN.md** | Replace the "docker-passthrough" section with: "the recommended path is the otel-sidecar; legacy compose-env passthrough is still supported." | ~½ day |
| **7. Roll out to prod's 5 monitoring=true services** | Tenant-side compose updates. Containarium just publishes the image. | (per service) |

**Total: ~2.5 days OSS + image build** to ship the OTel sidecar v1.

## History

| Date | Author | Change |
|---|---|---|
| 2026-05-16 | hsinhoyeh, drafted with Claude | Initial draft: per-LXC `otelcol-contrib` as a systemd unit installed by Containarium during `--monitoring` lifecycle hooks. Status: Draft. |
| 2026-05-16 | hsinhoyeh, redrafted with Claude | Pivot from "platform installs systemd unit in LXC" to "platform publishes a docker sidecar image, tenant composes it in." Scope narrowed to the `containarium/otel-sidecar:v1` image specifically; generic platform pattern moved to `PLATFORM-SIDECAR-DESIGN.md`. Status: still Draft, now scoped. |
