# Containarium vs. sandbox-runtime

> **DRAFT — not reviewed, not committed.** Items marked `[VERIFY]` must be
> checked against the code or a live host before this page is published.

A comparison of Containarium against
[`@anthropic-ai/sandbox-runtime`](https://github.com/anthropics/sandbox-runtime)
(`srt`), Anthropic's open-source tool for sandboxing a single agent-run
process on a developer machine.

**tl;dr:** these operate at different layers. `srt` wraps *one process
tree* in OS-native isolation and filters its network egress. Containarium
provisions and runs *long-lived, multi-tenant boxes*. The useful question
is not "which one" but "what runs inside the box." Containarium boxes are
a good place to run `srt`, and the two together give a stronger setup
than either alone.

## What each one is

| | **Containarium** | **sandbox-runtime (`srt`)** |
|---|---|---|
| Scope | Platform: provision, network, expose, back up, and manage boxes across a fleet | CLI and library: wrap one command in a sandbox |
| Unit of isolation | Incus/LXC system container (shares host kernel, has its own init and persistent rootfs). A Kubernetes backend is also supported. | One process tree, inside OS-native primitives |
| Lifecycle | Long-lived: create, SSH in, work for days or weeks, back up, restore, move, delete | Ephemeral: the sandbox lasts as long as the wrapped command |
| Primary consumer | Operators and agents that need a persistent, SSH-reachable box | Developers running Claude Code, local MCP servers, or agents on a laptop or CI runner |
| Deployment | Daemon, control plane, sentinel gateway, CLI, and MCP servers | npm package with a CLI and a TypeScript library. No server. |
| License | Apache-2.0 | Apache-2.0 |
| Maturity | Production use; releases weekly | Labeled "beta research preview"; the API may change |

## Isolation mechanism

- **Containarium** delegates kernel isolation to Incus/LXC. Namespaces,
  cgroups, and AppArmor profiles come from LXC. On top of that it adds an
  eBPF TC program attached to each container's veth for per-tenant network
  policy (`internal/netbpf`).
- **srt** builds its isolation per invocation:
  - macOS: `sandbox-exec` (Seatbelt) profiles
  - Linux: bubblewrap namespaces plus a seccomp-BPF filter. The seccomp
    helper blocks `AF_UNIX` socket creation, `io_uring`, and
    namespace-manipulation syscalls.
  - Windows (alpha): a restricted token, a dedicated low-privilege user,
    and WFP egress filters

**Practical read:** LXC system containers are coarser and heavier than a
per-process jail. A per-process jail has a thinner boundary but also less
to get wrong, and its policy is explicit per invocation.

## Network egress

- **Containarium:** L3/L4 policy at the veth. CIDR deny lists and tenant
  IP maps are enforced by eBPF, and nftables guards handle tenant and core
  separation. Domain names are resolved to addresses in userspace and
  refreshed on the record TTL, capped at 60 seconds with a 1-second floor.
  Rotated-out addresses are kept for two refresh intervals. Enforcement is
  IPv4-only: IPv6 CIDRs are rejected at policy compile time, and IPv6
  packets pass the TC program unfiltered. The eBPF enforcer is off unless
  both `CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT` is set and
  `CONTAINARIUM_NETWORK_POLICY_ENFORCE` is set to `1`, `true`, `yes`, or
  `on`. The Incus NIC-ACL guards are a separate mechanism and are on by
  default. There is no request-level inspection.
- **srt:** all traffic from the sandbox goes through an HTTP and SOCKS5
  proxy running on the host. Policy is domain and port allow and deny
  lists, with a resolved-address guard that blocks loopback, link-local,
  and cloud metadata addresses. Optional TLS termination allows
  request-level filtering and credential substitution. `[VERIFY: TLS
  termination and credential masking behavior against the current srt
  release]`

**Practical read:** srt's egress policy is richer and more readable, and
its denials can be returned to the model as a reason. Containarium's
policy is coarser and sits below the process, so it cannot tell which
process made a request.

## Filesystem policy

- **Containarium:** the tenant is root inside the box. There is no
  in-box filesystem policy. The `agent-box` MCP server checks paths
  against its configured root only. Storage is encrypted at rest per
  tenant.
- **srt:** reads are allowed by default and writes are denied by default.
  Explicit allow and deny lists control both. Certain paths are always
  protected, including shell startup files, git hooks, and MCP and agent
  configuration files that could re-run code.

**Practical read:** srt provides least-privilege for the agent process.
Containarium provides a complete, separate machine for the tenant. These
protect different things.

## Secrets

- **Containarium:** a secrets API with at-rest encryption, optional KMS
  envelope encryption, and per-box delivery. A model gateway issues scoped
  tokens, so provider keys never enter the box.
- **srt:** can inject credentials into sandboxed commands and mask them on
  egress. It only protects material the host process already holds.

## Multi-tenancy

- **Containarium:** a core concept. Each tenant has its own boxes, tenant
  guards, collaborators, and role-based access.
- **srt:** none. It is single-user by design.

## Persistence and operations

- **Containarium:** backups and restores, auto-sleep and wake, resize,
  cross-backend move, GPU passthrough, and fleet capacity views.
- **srt:** none. Each invocation is independent.

## Host separation

This is where Containarium's boundary is strongest. A compromised agent in
a Containarium box runs on a different machine from the user's personal
files and SSH keys. With srt, a sandboxed process can still send anything
it can read through any domain the policy allows. srt's own documentation
says so.

## Where they fit together

Run srt inside a box for per-process control, and use the box for host
separation, persistence, and tenancy.

1. Install `srt` in the box image alongside its dependencies.
2. Launch coding CLIs through `srt` with a per-tenant policy file.
3. Keep Containarium's network guards as the outer layer.

`[VERIFY: srt works inside an unprivileged LXC container with the default
user-namespace settings. Needs a live test before this is recommended.]`

## Summary

| Question | Use Containarium | Use srt |
|---|---|---|
| Persistent workspace for a team | Yes | No |
| Run an agent on a laptop | No | Yes |
| Restrict an agent's domains and files | Partly, outer layer only | Yes, per process |
| Separate tenants on shared hardware | Yes | No |
| Protect the user's own machine from an agent | Yes, if the agent runs in a box | Yes, locally |

## License

Both permissive: Containarium is Apache-2.0. srt is Apache-2.0.
