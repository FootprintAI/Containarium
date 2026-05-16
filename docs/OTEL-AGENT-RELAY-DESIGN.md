# Per-LXC OTel agent relay — design

**Status:** Draft
**Last updated:** 2026-05-16
**Related:**
- [`docs/OTEL-COLLECTOR-DESIGN.md`](OTEL-COLLECTOR-DESIGN.md) — the central VictoriaMetrics-backed collector this relay forwards to (the "gateway" in OTel agent/gateway terminology)
- [`docs/OTEL-COLLECTOR-DESIGN.md#operator-note-docker-in-lxc-needs-explicit-passthrough`](OTEL-COLLECTOR-DESIGN.md#operator-note-docker-in-lxc-needs-explicit-passthrough) — the docker-in-LXC gap this design replaces

## Context

Containerium's app-emitted OTel design (shipped v0.16.9 + v0.16.10) stamps `OTEL_EXPORTER_OTLP_ENDPOINT` and three other env vars onto a `--monitoring=true` LXC. Processes launched **directly** under the LXC's PID 1 inherit them automatically. But the majority of real production deployments run a **docker daemon inside the LXC** and launch the actual app processes as docker containers — and docker doesn't inherit its host's env into containers by default. We documented the operator-side passthrough patterns (compose `${VAR}` interpolation, `docker run -e NAME`), but that's developer-side plumbing for every team and every compose file.

This doc designs the platform-side alternative: a fluentd-style **agent relay** that Containarium installs inside each `--monitoring=true` LXC. Apps inside docker emit OTLP to a stable local endpoint; the relay rewrites resource attributes from the LXC's env and forwards to the central collector. Zero compose changes for the tenant; full identity stamping is platform-controlled and unforgeable.

## Goals / non-goals

**Goals**

- Apps running inside docker containers emit OTLP with **zero compose changes** — point at a well-known local endpoint, get correct backend.id / container.id labels for free.
- Per-tenant identity is **platform-stamped**, not app-claimed — the relay overrides container.id and backend.id resource attributes regardless of what the app sent. (Anti-spoofing at the resource-attribute layer; complements the existing source-IP processor at the gateway.)
- Same `--monitoring` per-container opt-in shape — no new flag, no new tenant decision.
- `ToggleMonitoring enable/disable` and `MoveContainer` lifecycles cleanly install / uninstall / re-stamp the relay.
- No memory regression on `--monitoring=false` LXCs (the relay isn't installed at all there).

**Non-goals (for v1)**

- Tracing and logs. Same scope as the central collector — metrics-only v1; v2 adds trace + log receivers when needed.
- Bare-metal peers (`fts-5900x`, `fts-13700k`). Those run their daemons outside the Incus LXC model; they need a separate "host-level OTel collector" plan that this doc doesn't cover.
- Non-monitoring LXCs. Relay only exists when `--monitoring=true`.
- Per-docker-container override of `OTEL_SERVICE_NAME`. Apps that set their own `service.name` keep it; we don't try to map `<docker-container-name> → <service.name>` automatically (out of scope, app-side concern).
- Replacing the existing operator-side compose / run patterns. The compose `${VAR}` form still works; teams that have it wired up already don't have to switch. The relay is an additive opt-in.

## Architecture

```
┌────────── inside one Containarium user LXC (monitoring=true) ────────────┐
│                                                                          │
│   docker0 (172.17.0.1/16) — also br-XXXX named bridges per compose       │
│                                                                          │
│   ┌───────────────────────────┐   ① app emits OTLP/HTTP to                │
│   │ docker container          │      172.17.0.1:4318 (or another bridge   │
│   │ (the tenant's app)        │      gateway; all reach the relay)         │
│   │                           │                                          │
│   │ no OTEL_* env set in      │   ② OTLP/HTTP                              │
│   │ compose — points at       │──────────────────────┐                   │
│   │ stable local relay        │                      ▼                   │
│   └───────────────────────────┘   ┌────────────────────────────────────┐ │
│                                   │  otel-relay (systemd, in this LXC) │ │
│                                   │                                    │ │
│                                   │  receivers: otlp http/grpc :4318/  │ │
│                                   │                              :4317 │ │
│                                   │                                    │ │
│                                   │  processors:                       │ │
│                                   │    - resource (upsert from         │ │
│                                   │      OTEL_RESOURCE_ATTRIBUTES,     │ │
│                                   │      overrides app-claimed         │ │
│                                   │      container.id / backend.id)    │ │
│                                   │    - batch                         │ │
│                                   │                                    │ │
│                                   │  exporters: otlphttp →             │ │
│                                   │    http://<core-collector>:4318    │ │
│                                   └────────────────┬───────────────────┘ │
│                                                    │ ③ OTLP/HTTP         │
└────────────────────────────────────────────────────┼─────────────────────┘
                                                     │ (cross-LXC over
                                                     │  incusbr0)
                                                     ▼
                       ┌────────────────────────────────────────────────┐
                       │  containarium-core-otelcollector (central LXC) │
                       │                                                │
                       │  unchanged from v0.16.9:                       │
                       │    attributes/identity (source.ip anti-spoof)  │
                       │    transform (PII drop-list)                   │
                       │    batch                                       │
                       │    otlphttp → VictoriaMetrics                  │
                       └────────────────────────────────────────────────┘
```

Two layers of anti-spoofing now apply:

- **Resource-attribute layer (new):** the per-LXC relay overrides `container.id` and `backend.id` with values from the LXC's env. A misbehaving app inside docker can't claim to be another tenant by setting those in its SDK config.
- **Network layer (existing):** the central collector's `attributes/identity` processor stamps `source.ip` from `client.address`. Even if a tenant somehow tampered with their relay, the gateway still sees the relay's LXC IP, not the impersonated tenant's.

## Detailed design

### 1. Binary choice — `otelcol-contrib`

v1 reuses `otelcol-contrib` (already vendored for the central collector) rather than a custom Go relay. Reasoning:

- Same operational model — same systemd unit shape, same config format, same upstream-supported release artifacts. No new "Containarium-specific binary" the team has to maintain.
- Memory cost is ~30–50MB resident per relay. For our typical LXC count (~17 in prod) and prod boxes (c3d-highmem-8, 64GB RAM), that's a rounding error. If it ever stops being a rounding error we can drop in a 5MB custom Go relay later — the wire protocol is OTLP either way.

v2 may swap for a smaller binary if memory pressure shows up on small bare-metal hosts.

### 2. Relay placement and lifecycle

The relay runs as a systemd unit **inside** the user LXC, owned by Containarium (root). Lifecycle hooks:

| Containarium event | Relay action |
|---|---|
| `create_container --monitoring=true` | Install `otelcol-contrib` binary + write config + write `otel-relay.service` unit + `systemctl enable --now otel-relay` |
| `toggle_monitoring enable` | Same as create-with-monitoring (idempotent — skips install if already present) |
| `toggle_monitoring disable` | `systemctl stop otel-relay && systemctl disable otel-relay`; leave the binary/config in place (next enable is faster). Do not delete the binary — the operator can disable monitoring without re-incurring an 80MB download on next enable. |
| `AdoptMigratedContainer` (with monitoring) | Same as toggle-enable; the relay's config is regenerated against the destination's collector IP. |
| `delete_container` | The whole LXC goes away; the relay disappears with it. No special cleanup needed. |

Trade-off note: putting the relay binary on every monitoring LXC adds ~80MB of disk per LXC. We accept it; disk is cheap and operationally simpler than network-mounting a shared binary.

### 3. Listening address — `0.0.0.0:4318`

The relay binds OTLP/HTTP on `0.0.0.0:4318` and OTLP/gRPC on `0.0.0.0:4317`. This makes it reachable from any docker bridge inside the LXC — `docker0` (172.17.0.1), named compose bridges (`br-XXXX` at 172.18.0.1, 172.19.0.1, …), and `--network=host` containers (localhost). Tenants don't have to know which bridge their compose created.

For apps: set `OTEL_EXPORTER_OTLP_ENDPOINT=http://172.17.0.1:4318` in compose, or use the standard `host.docker.internal:host-gateway` mapping if the team already wires it. We'll document the `172.17.0.1` form because every docker installation has docker0 by default.

### 4. The resource processor

The relay's `resource` processor stamps these on every metric, **overriding** what the app may have set:

```yaml
processors:
  resource:
    attributes:
      - key: container.id
        value: ${LXC_CONTAINER_ID}
        action: upsert
      - key: backend.id
        value: ${LXC_BACKEND_ID}
        action: upsert
      # service.namespace inserted (not upsert) — sets a default but
      # doesn't clobber an app-provided value
      - key: service.namespace
        value: ${LXC_USERNAME}
        action: insert
```

`upsert` for the platform-controlled keys, `insert` (only-if-absent) for `service.namespace`. `service.name` is never touched — apps own it, fine-grained per docker service.

The `LXC_*` placeholders are env vars Containarium stamps on the relay's systemd unit when it installs (not on the LXC's general environment). Three explicit vars rather than parsing `OTEL_RESOURCE_ATTRIBUTES` so the config is readable.

### 5. Exporter — same shape as the gateway

```yaml
exporters:
  otlphttp:
    endpoint: http://${CORE_COLLECTOR_IP}:4318
    tls:
      insecure: true
```

`CORE_COLLECTOR_IP` is templated into the config at install time. On `AdoptMigratedContainer` we rewrite the config with the destination's collector IP and `systemctl restart otel-relay`.

### 6. Compatibility with the existing env-stamp path

The existing LXC-env approach (`OTEL_EXPORTER_OTLP_ENDPOINT`, etc.) stays in place. Two reasons:

- LXC-level processes that aren't running in docker (systemd unit, native binary, agent-box) still need the env to know where to emit. The relay is *for* docker; non-docker processes don't need it.
- The relay reads `LXC_CONTAINER_ID` / `LXC_BACKEND_ID` from its own systemd unit env, which Containarium populates from the same source (the LXC's resource-attribute string). Single source of truth.

If a tenant wants to disable the relay but keep LXC-level OTel env (e.g. an LXC with only native processes), that's not a configuration we expose. Either both or neither — keeps the operator model simple.

## Failure modes

| Failure | Effect | Mitigation |
|---|---|---|
| Relay crashes | `systemctl Restart=always` brings it back in <5s. Apps see connection-refused during the gap → OTel SDK buffers + drops, same as if the gateway were briefly down. | Restart policy plus operator alert on `otelcol-contrib` unit being inactive for >30s. |
| Relay binary missing on toggle-enable | `systemctl enable` fails; toggle returns Internal error before stamping env vars. | Install is idempotent; if the binary went missing, next enable re-downloads. |
| App emits before relay starts (cold start) | First few seconds of metrics lost; SDK retries usually succeed. | Acceptable — same as any agent collector pattern. |
| Central collector unreachable | Relay buffers per its `batch` processor, then drops. | Operator alert via `otelcol_exporter_send_failed_total` on the relay (scrape the relay's `:13133` metrics endpoint). |
| `MoveContainer` mid-flight: source's relay still up, destination's not yet | App's OTLP traffic continues hitting the source's relay (still resolvable via LXC's IP for a moment). After cutover, app connects to destination's relay. | The brief overlap stamps `container.id` correctly either way (both relays know the tenant). Worst case is a few seconds of duplicate metrics. |
| Operator manually mutates the relay's config inside the LXC | Containarium's next install/restart overwrites it without warning. | Documented; operators shouldn't hand-edit per-LXC platform files. Same posture as `/etc/caddy/Caddyfile` on the core Caddy LXC. |
| Tenant runs `--network=host` docker | Container shares LXC netns; can hit relay at `localhost:4318`. | Document; works out of the box. |
| Tenant uses `iptables -A OUTPUT -j DROP` to firewall inside docker | They block their own metrics. | Out of scope. |

## Open questions

| # | Question | Why it matters | Proposed answer |
|---|---|---|---|
| 1 | **Relay binary on disk: per-LXC copy or shared mount?** | Per-LXC means ~80MB × N LXCs. Shared mount (via Incus shared disk device) is one copy but introduces a tight coupling between Containarium upgrades and tenant LXC reboots. | Per-LXC copy. Disk is cheap; tight coupling is operationally risky. Revisit if a deployment has hundreds of monitoring LXCs. |
| 2 | **Default `OTEL_EXPORTER_OTLP_ENDPOINT` in compose docs: `172.17.0.1:4318` or `host.docker.internal:4318`?** | Both work if the bridge is set up right; `host.docker.internal` needs `extra_hosts` in compose, `172.17.0.1` doesn't. | Document `172.17.0.1:4318` as the default. Mention `host.docker.internal` as an alternative for teams already using it. |
| 3 | **What about LXCs running Podman instead of docker?** | The `pes` and `ccu*` containers on prod use Containarium's podman-in-LXC path. Podman's network model is different from docker's; whether the relay is reachable at the same address needs verification. | v1: support docker only. Document podman-in-LXC as a follow-up. Podman rootless uses `slirp4netns` which gives `10.0.2.2` as the host gateway — different recipe but same idea. |
| 4 | **Authentication between relay and central collector?** | Today the central collector accepts any OTLP on `:4318` without auth (it relies on network isolation via `incusbr0`). Relay → collector is the same VPC + bridge, so same trust model — but should we add a token? | v1 no auth (matches existing posture). v2 may add per-relay mTLS if cross-VM relays appear. |
| 5 | **Should the relay listen on Unix socket too?** | A bind-mounted Unix socket would let apps hit the relay without any IP plumbing, more portable than a bridge gateway IP. | v1: TCP-only on `0.0.0.0:4318`. The Unix-socket path requires per-tenant compose changes (`-v /run/otel.sock:...`) which defeats the "zero compose changes" goal. Revisit if a real use case emerges. |

## Phased rollout

| Phase | Scope | Effort |
|---|---|---|
| **0. RFC accepted** | this doc + decisions on the 5 open questions | (you) |
| **1. Bake the relay config generator** | Pure function `BuildRelayConfig(containerID, backendID, username, coreCollectorIP) string`; unit-tested without touching real systemd. | ~½ day |
| **2. Install/uninstall hooks** | `installAgentRelay(containerName)` / `uninstallAgentRelay(containerName)` wrappers around `incus exec` calls (download binary, write config + unit, enable/disable). Idempotent. | ~1 day |
| **3. Wire into lifecycle paths** | CreateContainer with `--monitoring`, ToggleMonitoring enable/disable, AdoptMigratedContainer. | ~½ day |
| **4. Update OTel design doc** | Replace the "Operator note: docker-in-LXC needs explicit passthrough" section with a pointer to this design; add the relay as a documented layer. | ~½ day |
| **5. Tests** | Unit (config generator) + integration (toggle enable inserts unit; toggle disable removes it; AdoptMigratedContainer rewrites endpoint). | ~1 day |
| **6. Backfill on existing prod monitoring=true LXCs** | One-shot script that installs the relay on the 5 prod services (api, facelabor, pes, voicegpt, wordpress) without flipping `--monitoring` (which is already true). | ~½ day |

**Total: ~4 days.** Phases 1–5 are OSS; phase 6 is operator work specific to our prod deployment.

## History

| Date | Author | Change |
|---|---|---|
| 2026-05-16 | hsinhoyeh, drafted with Claude | Initial draft. Fluentd-style agent relay inside each `--monitoring=true` LXC; reuses `otelcol-contrib` to avoid a new binary; platform-stamps resource attributes to extend anti-spoofing into the docker-in-LXC case. Status: Draft. |
