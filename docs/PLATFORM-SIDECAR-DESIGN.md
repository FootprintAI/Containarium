# Platform sidecar pattern — design

**Status:** Approved
**Last updated:** 2026-05-16
**Related:**
- [`docs/OTEL-AGENT-RELAY-DESIGN.md`](OTEL-AGENT-RELAY-DESIGN.md) — the first concrete sidecar (OTel collector); now scoped to the `containarium/otel-sidecar` image
- [`docs/OTEL-COLLECTOR-DESIGN.md`](OTEL-COLLECTOR-DESIGN.md) — the central gateway sidecars forward to (for telemetry sidecars specifically)

## Context

Containarium's deployment model is **LXC → docker compose**: every user LXC runs a docker daemon, and the tenant's actual application lives as a set of docker-compose services. As we add platform-managed cross-cutting concerns (telemetry, log shipping, file scanning, audit capture, network policy enforcement), we keep hitting the same gap: **docker containers don't inherit env from their LXC host, and we don't want the platform reaching into tenant compose files**.

The K8s ecosystem solved this with the **sidecar pattern**: each pod carries small companion containers that share its network namespace and lifecycle. The OTel community ships `opentelemetry-operator` to inject those sidecars automatically; security tooling ships Falco/Pixie agents the same way. The pattern is mature precisely because cross-cutting concerns are easy to layer in this shape.

Docker compose has equivalent primitives — `network_mode: "service:<other>"` shares network namespaces, `volumes` shares filesystem, env interpolation passes configuration — but no operator that injects sidecars automatically. This doc designs the next-best thing: a small set of **platform-published sidecar images** with a stable identity-injection contract, that tenants compose into their stack like any other service.

OTel is the first instance. Log shipping, virus scanning, audit capture follow once the primitive is stable.

## Goals / non-goals

**Goals**

- Cross-cutting concerns (telemetry, logs, scanning, audit) ride **inside the tenant's compose** rather than as platform-managed systemd units inside their LXC. Operationally cleaner: no platform processes the tenant can't see; no platform-owned files inside their LXC.
- Platform-controlled identity. Sidecars stamp `container.id` / `backend.id` (and the future `org.id` / `tenant.id`) from LXC env vars Containarium owns; apps inside docker can't impersonate.
- Per-service granularity where it matters. Each app's `OTEL_SERVICE_NAME` / `log.source` / `scanner.scope` is tenant-controlled per docker service, exactly like other compose properties.
- Stable image contract. The first OTel sidecar should establish conventions (env-var names, network sharing model, failure semantics) that the next 3–4 sidecars reuse without re-litigation.
- Composable without recreate. A tenant adds the sidecar to compose, runs `docker compose up -d`, and it's live. No platform RPC, no LXC restart.

**Non-goals (for v1)**

- Auto-injection. Containarium does **not** read or write tenant compose files. Tenants explicitly add sidecars they want. (A future "compose-overrides" RPC could generate sidecar definitions for tenants to chain, but that's v2.)
- Mandatory adoption. Existing `--monitoring=true` LXCs that haven't added the sidecar still work — the env vars stay stamped on the LXC, native processes still inherit them, the [docker-passthrough form](OTEL-COLLECTOR-DESIGN.md#operator-note-docker-in-lxc-needs-explicit-passthrough) keeps working. The sidecar is *better*, not *required*.
- Third-party sidecar discovery. Initially the only documented sidecars are Containarium-published. A community-registry / "any image that follows the contract" model can come later.
- Sidecar-to-sidecar communication. Each sidecar is a leaf: it talks to its app (over shared netns / volume) and to upstream services (collector, log store, etc.). Sidecars don't form a mesh.

## Architecture

```
┌────────── one Containarium user LXC (monitoring=true) ──────────┐
│                                                                 │
│   docker daemon  +  the tenant's docker-compose stack           │
│                                                                 │
│   ┌──────────────────────┐    ┌────────────────────────┐        │
│   │ payment-api          │    │ payment-api-otel       │        │
│   │ image: my-app:v1     │◄───┤ image: containarium/   │        │
│   │ network_mode:        │    │   otel-sidecar:v1      │        │
│   │   "service:          │    │                        │        │
│   │    payment-api-otel" │    │ env (from compose      │        │
│   │                      │    │  ${VAR} interpolation, │        │
│   │ ⇒ app emits OTLP to  │    │  ultimately from LXC   │        │
│   │   localhost:4318     │    │  env stamped by        │        │
│   │   (shared netns)     │    │  Containarium):        │        │
│   └──────────────────────┘    │   OTEL_EXPORTER_OTLP_  │        │
│                               │     ENDPOINT           │        │
│   ┌──────────────────────┐    │   OTEL_RESOURCE_       │        │
│   │ payment-worker       │    │     ATTRIBUTES         │        │
│   │ image: my-worker:v1  │    │   (container.id,       │        │
│   │ network_mode:        │    │    backend.id)         │        │
│   │  "service:           │    │                        │        │
│   │   payment-worker-    │    │ ⇒ rewrites those       │        │
│   │   otel"              │    │   attributes via       │        │
│   └──────────────────────┘    │   resource processor   │        │
│                               │   `upsert`             │        │
│   ┌──────────────────────┐    │                        │        │
│   │ payment-worker-otel  │    │ ⇒ forwards to central  │        │
│   │ (own sidecar)        │    │   collector (next LXC) │        │
│   └──────────────────────┘    └────────────────────────┘        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
              │
              │ OTLP over incusbr0
              ▼
   containarium-core-otelcollector LXC (unchanged from v0.16.9)
```

The sidecar's role: bridge between the docker container's localhost and the platform's central collector, **and** stamp platform-controlled identity attributes on the way through.

## The platform sidecar contract

Every Containarium-published sidecar image satisfies this contract:

1. **Reads its identity from env vars at start time.** Specifically:
   - `OTEL_RESOURCE_ATTRIBUTES` for `container.id` / `backend.id` (telemetry sidecars).
   - `CONTAINARIUM_TENANT_ID` / `CONTAINARIUM_LXC_NAME` for non-telemetry sidecars (log, scanner, audit).
   These come from the tenant's compose via `${VAR}` interpolation, which reads from the LXC env that Containarium stamps via `--monitoring=true`. The sidecar trusts these env vars because they originate from the platform.

2. **Overrides app-claimed identity.** If the upstream signal (OTLP datapoint, log line, scan event) carries identity attributes the app set, the sidecar **replaces** them with the env-sourced values before forwarding. Apps can claim `service.name` freely; they cannot claim `container.id`.

3. **Fails closed on missing identity env.** If the required env vars are unset, the sidecar logs a startup error and exits non-zero. `docker-compose up` reports the failure; the tenant sees they forgot to stamp identity. No silent forwarding without provenance.

4. **Listens on a stable port per protocol.** Telemetry: `:4318` OTLP/HTTP, `:4317` OTLP/gRPC. Logs: TBD (`:24224` if we adopt fluent-bit's protocol). Sidecars don't accept "configurable listen port" — the contract is the port.

5. **Forwards to a Containarium-resolved upstream.** The sidecar's image baked-in config knows how to reach the central collector / log store / etc. by env (`OTEL_EXPORTER_OTLP_ENDPOINT`, etc.). Tenants don't configure upstream addresses; the platform does via LXC env.

6. **Restarts cleanly on signal.** Sidecars handle SIGTERM by draining their in-flight batches before exit, so `docker compose down && up` doesn't lose data.

## Sharing model

Each sidecar joins its app's container via one of three shapes:

- **Network share** (`network_mode: "service:<sidecar>"`). The app and sidecar share a netns. App reaches sidecar at `localhost:<port>`. Used by: telemetry, log sidecars that scrape over network.
- **Filesystem share** (`volumes:` with the same named volume on both). Used by: scanner sidecars watching a directory, log sidecars tailing a file.
- **Mixed** (both network and volume). Used by: audit sidecars that capture process exec via the shared netns and write structured logs to a shared volume.

The compose author picks the right model per sidecar. The platform docs describe which is appropriate for each published image.

## Naming convention

Per-app sidecars use the format `<app-name>-<purpose>-sidecar` or short `<app-name>-<purpose>` if it reads naturally:

- `payment-api-otel`
- `payment-api-log`
- `payment-api-scanner`

The convention is documentation, not enforced. Compose's `network_mode: "service:..."` ties them together explicitly. The naming just makes long compose files greppable.

## Image registry and versioning

Containarium-published sidecars live at `ghcr.io/footprintai/containarium-<purpose>-sidecar`. **Sidecar image versions track the Containarium project version** rather than maintaining independent semver — one release number per Containarium release covers daemon + every sidecar. Packages are public on GHCR; tenants `docker pull` without auth.

For Containarium `v0.16.10`, each published sidecar gets three tags:

- `:v0.16.10` — immutable, points at the exact build associated with that Containarium release. Pin here for paranoid stability.
- `:v0.16` — moves with the latest `v0.16.X` release in the minor series. Recommended for compose; inherits security patches automatically.
- `:latest-stable` — moves with the latest tagged Containarium release. Useful for local testing; not recommended for production compose.

Each sidecar's GitHub release page documents the upstream binary version baked in (e.g. `containarium-otel-sidecar:v0.16.10` is built on `otelcol-contrib v0.110.0`). Operators inheriting a Containarium release inherit its sidecars — no separate compatibility matrix to manage.

## Future sidecars sketched

Not part of v1, but the pattern should support these without re-design:

- `log-sidecar`: tail an app's stdout (via shared volume) or a log file, ship to VictoriaMetrics/VictoriaLogs as structured logs. Identity from `CONTAINARIUM_TENANT_ID` env.
- `scanner-sidecar`: watch a shared volume for new files; ClamAV-scan; emit alerts to the central audit collector. Decouples scanning from the daemon's existing `containarium-core-security` LXC by moving it inline with the app.
- `audit-sidecar`: tracks shell `exec` calls in the app container via shared netns + auditd; ships structured exec events to an audit collector. Useful for compliance use cases (ISO 27001 A.12.4 logging requirements).
- `egress-policy-sidecar`: enforces outbound network policy via iptables in the shared netns. Default-deny except allow-listed CIDRs. Per-tenant policy from env.

Each of these slots into the same shape — image at `ghcr.io/footprintai/containarium-*-sidecar:v1`, contract-compliant — without changing the platform.

## Failure modes

| Failure | Effect | Mitigation |
|---|---|---|
| Sidecar image pull fails on `docker-compose up` | App service fails to start (compose dependency: `depends_on`). | Tenant sees the error; can debug like any other compose pull failure. |
| Sidecar crashes mid-flight | Compose's `restart: unless-stopped` brings it back. App's network connections to `localhost:<port>` see a brief gap. | OTel SDKs / log libs retry with backoff. |
| Identity env vars unset (`--monitoring=false` LXC) | Sidecar exits non-zero at startup. App service fails to start (depends_on). | By design — fail closed. Tenant either enables monitoring or removes the sidecar. |
| App claims spoofed identity in OTLP attributes | Sidecar's `resource` processor `upsert` overrides. | The whole point. |
| Sidecar version skew with central collector | OTLP is wire-stable across collector versions. Sidecar and gateway can be different versions. | Document a compatibility matrix per sidecar release. |
| Tenant adds sidecar without matching `network_mode` on app | App can't reach `localhost:<port>` because the sidecar's netns is separate. App emits to nowhere. | Documentation. Compose-lint future tooling could catch this. |

## Comparison with prior options

For reference, the trade-offs we considered (and rejected for v1):

| Approach | Where the relay runs | Tenant compose change | Memory per LXC | Per-service identity | Status |
|---|---|---|---|---|---|
| Compose `${VAR}` passthrough | Nowhere; direct app-to-gateway | Env passthrough per service | 0 | App-claimed (untrusted) | Documented in `OTEL-COLLECTOR-DESIGN.md` as the lightest option |
| **LXC-level relay (rejected)** | systemd unit installed by Containarium inside each LXC | None | ~50MB | Tenant-level only | Considered in prior `OTEL-AGENT-RELAY-DESIGN.md` Draft; superseded by this design |
| **Platform sidecar (this design)** | Docker sidecar inside the tenant's compose | Add sidecar service | N × ~30–50MB | Yes, per-service | Recommended for new deployments |

The LXC-level relay was rejected because it requires Containarium to install/manage processes inside tenant LXCs — an unwanted dependency direction. The sidecar pattern flips it: tenants choose what platform components they want, Containarium just publishes the images and stamps the identity env.

## Resolved decisions

| # | Decision | Rationale |
|---|---|---|
| 1 | **Image registry is GHCR** (`ghcr.io/footprintai/containarium-<name>-sidecar`). | Same registry as the main Containarium release artifacts; supports signed image attestations natively; no new vendor dependency. |
| 2 | **`containarium sidecar <name> compose <username>` CLI subcommand** that prints a ready-to-paste compose block customized for the requesting LXC's identity. Tenant copies into their compose. **No platform write to tenant files.** | Discoverability without intrusion. Tenants who want it grab the snippet; the platform never modifies tenant artifacts. |
| 3 | **One gating flag per cross-cutting concern** (`--monitoring`, `--log-shipping`, `--audit-capture`, ...). Each stamps the relevant identity env on the LXC. Sidecars fail closed if their required env is unset. | Lets tenants opt-in granularly. A `log-sidecar` added to a `--monitoring=true --log-shipping=false` LXC errors clearly at compose-up. |
| 4 | **Sidecar image versions track the Containarium project version**, not independent semver. Each Containarium release (`v0.16.10`, `v0.17.0`, ...) produces matching sidecar tags. Moving tags `:latest-stable` and `:v0.16` (the minor-series moving tag) also published. | One number to remember per release. Daemon and sidecars move together — no compat matrix to maintain across decoupled release streams. Operators inheriting a Containarium release inherit its sidecars. |
| 5 | **Non-docker LXCs keep using the LXC-env stamping path** (today's behavior). Sidecar pattern is a *superset* for docker LXCs, not a replacement. | Backward-compatible. Native-binary LXCs (`argus-dev`, etc.) can't `network_mode: service:...` because they have no compose; they read OTEL_* from the LXC env directly, same as v0.16.9 shipped. |
| 6 | **Containarium maintains a sidecar release calendar tied to upstream CVE feeds.** Auto-rebuild and re-push on upstream security release; tenants on `:v0.16` (moving) pick it up automatically; tenants on `:v0.16.10` (immutable) manually bump per the documented timeline. | Security updates inheritable without daemon redeploy. Pinned-version users get explicit timeline rather than silent regressions. |

## Phased rollout

| Phase | Scope | Effort |
|---|---|---|
| **0. RFC accepted** | this doc + decisions on the 6 open questions | (you) |
| **1. Repo for sidecar images** | `containarium-sidecars` repo: Dockerfile + GH Actions for `otel-sidecar` first. CI builds + signs + pushes to GHCR. | ~1 day |
| **2. `otel-sidecar` image** | otelcol-contrib base + baked-in config + resource processor `upsert` + GHCR publish. Smoke-test on prod's `devbox`. | ~½ day |
| **3. `containarium sidecar <name> compose` CLI** | prints a ready-to-paste compose block for the LXC the operator is in. | ~½ day |
| **4. Update docs** | Pivot `OTEL-AGENT-RELAY-DESIGN.md` to "OTel sidecar image — design" (scope of the `otel-sidecar:v1` image, not the platform pattern). Update `OTEL-COLLECTOR-DESIGN.md`'s docker-passthrough section. | ~½ day |
| **5. Backfill prod** | Help the team add `payment-api-otel` style sidecars to their compose files for the 5 prod services already on `--monitoring=true`. Pure tenant-side work; platform just publishes images. | (per service) |
| **6. Second sidecar (log)** | Once `otel-sidecar` has been live for a couple of weeks, ship `log-sidecar` against the same contract to validate it. | ~2 days |

**Total: ~3 days OSS + image-repo work** for the first sidecar end-to-end. Second sidecar is ~2 days because the contract is now well-trodden.

## History

| Date | Author | Change |
|---|---|---|
| 2026-05-16 | hsinhoyeh, drafted with Claude | Initial draft. Platform sidecar pattern as the model for cross-cutting concerns (telemetry, log, scanner, audit). OTel sidecar is the first instance. Replaces the prior "LXC-level relay" design. Status: Draft. |
| 2026-05-16 | hsinhoyeh | Resolved all 6 open questions: GHCR registry, `containarium sidecar ... compose` CLI for discovery, per-concern gating flags, **sidecar versions track the Containarium project release version** (single number for daemon + sidecars), non-docker LXCs keep the legacy env path, CVE-driven auto-rebuild calendar. Status: Draft → Approved. |
