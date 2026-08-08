# Containarium vs. bubblewrap

An end-to-end comparison of Containarium against
[bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`), the
unprivileged sandboxing tool that underlies Flatpak.

**tl;dr:** these solve different problems at different layers.
bubblewrap is a *process-sandboxing primitive*; Containarium is a
*multi-tenant box-provisioning platform*. Comparing them is roughly
comparing a lock to a building — but the comparison is useful for
understanding where Containarium's isolation boundary sits relative to
a well-audited, minimal alternative, and where ideas could cross over.

## What each one is

| | **Containarium** | **bubblewrap** |
|---|---|---|
| Scope | Full platform: provision, network, expose, back up, and manage long-lived boxes across a fleet | Single CLI tool: wrap one process in a restricted namespace/seccomp jail |
| Unit of isolation | Incus/LXC **system container** (shares host kernel, has its own init, persistent rootfs) | One **process** inside temporary Linux namespaces — no persistent rootfs of its own |
| Lifecycle | Long-lived: create → SSH in → work over days/weeks → backup/restore/migrate/delete | Ephemeral: `bwrap ...` execs a command, sandbox dies when it exits |
| Primary consumer | Human devs / AI agents needing a persistent, SSH-reachable box | Flatpak (and rpm-ostree, bwrap-oci) as their sandbox engine |
| Deployment | Self-hosted daemon/gRPC server + CLI + two MCP servers (platform + in-box) | No daemon — just a binary you exec per sandbox |

## Isolation mechanism

- **Containarium** delegates the actual kernel isolation to Incus/LXC
  (namespaces, cgroups, AppArmor profiles are LXC's job, not
  hand-rolled). On top of that it adds a custom layer: a Phase-A eBPF
  TC program (`internal/netbpf`) attached to each container's veth for
  per-tenant network policy (deny CIDRs, tenant IP maps) — this is
  Containarium-specific and goes beyond what LXC gives you out of the
  box.
- **bubblewrap** builds the namespace stack itself, per invocation,
  purely with unprivileged user namespaces (`CLONE_NEWUSER` plus
  mount/pid/net/uts/ipc namespaces) plus a seccomp-bpf filter and
  `PR_SET_NO_NEW_PRIVS`. It explicitly refuses to run setuid
  (`"setuid use of bubblewrap is not supported"` in modern versions) —
  the legacy setuid-root fallback mode is the origin of its two known
  CVEs (2020-5291, 2026-41163), both scoped to that removed mode.

**Practical read:** LXC system containers are coarser and heavier than
bubblewrap's process jails. Containarium's own audit history
(`internal/server/privileged_policy.go`, finding "A-HIGH-3") notes that
`enable_podman=true` historically defaulted to `security.privileged=true`
(host-root inside the container) before a policy gate was added.
bubblewrap's boundary is thinner but its threat model is explicit and
its blast radius is exactly what flags you pass — nothing implicit.

## Networking

- Containarium: full ingress story — a sentinel gateway doing SNI/TLS
  routing, SSH-through-sentinel, port exposure
  (`containarium expose-port`), route/DNS management, per-tenant ACLs,
  egress proxy.
- bubblewrap: `--unshare-net` gives isolated loopback-only networking,
  or the sandbox shares the host's netns. No routing, no ingress, no
  proxy — it's isolation, not connectivity.

## Multi-tenancy

- Containarium has a first-class `TenantRegistry` (mem/Postgres),
  tenant-scoped eBPF policy maps, and a fleet concept (`ListBackends`,
  capacity headroom, GPU inventory across backends).
- bubblewrap has no tenancy concept at all — it's single-machine,
  single-invocation.

## GPU / device passthrough

- Containarium: first-class proto fields (`gpu`, repeated `gpus`), a
  `ValidateGPU` RPC, PCI masking/resolution code in
  `pkg/core/incus/`.
- bubblewrap: no dedicated GPU feature — a device path can be manually
  `--dev-bind`-ed, but it's plumbing, not a product feature.

## API surface

- Containarium: proto-first gRPC + REST (grpc-gateway) + generated
  OpenAPI + typed Go client + CLI + two MCP servers (per this repo's
  CLI-first, MCP-wraps-it convention). Dozens of services: containers,
  network, network-policy, backups, secrets, KMS, agent-skills/crews,
  recipes, alerts, tokens.
- bubblewrap: CLI flags only. No API, no library surface for
  orchestration — anything higher-level (like Flatpak) shells out to
  it.

## Security model framing

- bubblewrap's own docs are candid that it's a mechanism, not a
  policy: "the level of protection... is entirely determined by the
  arguments passed to bubblewrap." Its CVE history is narrow and
  well-understood (all in the removed setuid path).
- Containarium's security boundary is broader and correspondingly
  harder to fully characterize — it inherits LXC/AppArmor's isolation,
  adds its own eBPF network-policy layer, and layers multi-tenant
  RBAC/secrets/KMS on top. That's a larger attack surface by
  construction (proto services, sentinel gateway, tenant registry,
  privileged-podman opt-in) versus bubblewrap's single, auditable
  binary.

## License

Both permissive: Containarium is Apache-2.0; bubblewrap is
LGPL-2.0-or-later.

## Where they'd actually compete

They don't overlap much as-is — but there's one point of contact worth
flagging: Containarium's boxes are LXC system containers with a full
init and persistent state, which is a heavier and more privileged
boundary than bubblewrap gives Flatpak apps. If a future Containarium
feature wanted a lighter, ephemeral, per-command sandbox *inside* a
box (e.g. for agent tool-calls that shouldn't get a whole container),
bubblewrap-style unprivileged-userns + seccomp is the pattern to
borrow — it's the same idea `agent-box`'s `shell_exec` is reaching
for, just at a much finer grain and with a battle-tested minimal
binary instead of a hand-rolled layer.
