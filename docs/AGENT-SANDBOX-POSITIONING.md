# Containarium × agent-sandbox: Positioning

**One line:** Containarium is a distribution of
[kubernetes-sigs/agent-sandbox](https://github.com/kubernetes-sigs/agent-sandbox)
— agent-sandbox is the kernel, Containarium is the distro.

This doc is the canonical statement of how the two projects relate. Every
future contribution in either direction (upstream PRs, examples, KEP
comments, talks, marketing copy) should be consistent with — and ideally
link back to — this framing.

## The stack

| Layer | Owner | What lives there |
|---|---|---|
| Product / UX | **Containarium** | SSH + MCP access, users & auth, secrets, backups, autosleep, GPU management, recipes/compose, billing surface |
| Orchestration primitives | **agent-sandbox** | `Sandbox` CRD, `SandboxClaim`/`SandboxWarmPool`, `sandbox-router` data plane |
| Runtime contract | **agent-sandbox (KEP-539.2)** | `sandboxd`: gRPC `ProcessService` + REST `FilesystemService` |
| Runtime implementations | reference pod runtime / **Containarium `agent-box`** | The contract's proof of portability: same suite, two implementations |

The analogy to use everywhere: agent-sandbox is to Containarium what
containerd is to Docker. The SIG project deliberately ships primitives, not
a product — no user management, no backups, no access UX. Containarium is
the product layer that a kubernetes-sigs project structurally cannot be.

Integration is **bidirectional**, and that's the point:

1. **Downward (Containarium consumes agent-sandbox).** On the k8s runtime,
   every Containarium box *is* a `Sandbox` CR (`pkg/core/box/k8s/`),
   warm-pool-accelerated, reached through `sandbox-router` with
   per-sandbox scoped tokens minted by the Containarium daemon.
2. **Upward (Containarium validates agent-sandbox).** `agent-box`
   implements the `sandboxd` runtime contract and passes the same
   conformance suite as the reference runtime — including on the
   LXC/incus backend, off k8s. A contract with one implementation is not a
   contract; Containarium is the second data point that proves the
   abstraction is portable.

## Why this framing (and not the alternatives)

- **Silent consumer** (status quo): we use the CRD internally; upstream
  neither knows nor cares. No traffic flows either way.
- **Examples-only:** merged examples earn discovery traffic but position
  us as "a thing someone sandboxed," not an architectural peer.
- **Distro + second runtime** (this doc): we appear at three upstream
  layers — examples (discovery), router/data-plane code (contributor
  standing), runtime contract (peer implementation). That is what makes
  "distribution of agent-sandbox" a defensible claim instead of a slide.

Each project becomes the other's answer to its most common objection:

- agent-sandbox's objection — *"these are just primitives; where's the
  product?"* → Containarium.
- Containarium's objection — *"is this k8s-native or a vendor bolt-on?"*
  → built on the kubernetes-sigs standard, conformance-tested.

"As good as k8s" is never asserted; it is demonstrated in falsifiable
form: the same conformance suite, passed by both runtimes, plus the same
upstream examples runnable on either.

## Current state of the bricks (2026-07)

| Brick | State |
|---|---|
| `examples/containarium-ssh-sandbox` upstream | **Merged** (kubernetes-sigs/agent-sandbox#1185) |
| `sandbox-router` scoped-token authorizer + vendor-neutral example | Built on fork branch `authz-scoped-token`; to be split into two upstream PRs |
| KEP-539.2 / PR #1151 review (incl. conformance-suite offer) | Drafted, not yet posted |
| Daemon mints scoped tokens for k8s-runtime boxes | Not started (closes the gap the upstream example documents) |
| `SandboxClaim`/`SandboxWarmPool` adoption | Not started (zero references today; biggest box-startup UX win) |
| `agent-box` speaks `sandboxd` (gRPC/REST contract) | Not started; gated on KEP-539.2 going `implementable` |
| Conformance suite passing on both runtimes | Not started; the endgame artifact |

## Rules of engagement upstream

- Contribute vendor-neutral first, reference Containarium second.
  Precedent: the vendor-marketing framing was rejected on #1185; the
  vendor-descriptive framing was kept.
- Upstream the pattern, keep the product. Anything another runtime vendor
  would also need (authorizers, examples, conformance tests) goes
  upstream; the daemon, gateway UX, and ops features stay in Containarium.
- Review others' PRs, not just our own — standing (org membership,
  eventual OWNERS on `sandbox-router/` or `examples/`) is what compounds.
- Never claim conformance ahead of the suite actually passing.

## Related docs

- [K8S-AGENT-BOX-RUNTIME-DESIGN.md](K8S-AGENT-BOX-RUNTIME-DESIGN.md) —
  mechanics of the k8s runtime backend this positioning builds on.
