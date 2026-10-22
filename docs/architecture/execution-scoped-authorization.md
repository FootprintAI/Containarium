# Design: execution-scoped authorization

**Date:** 2026-09-28
**Status:** accepted — D1 below is implemented by the fix for #2125; D2 by the
fix for #2140
**Stack:** Go 1.26 (daemon, `internal/auth`, `internal/server`); TypeScript 5.6 /
Node ≥ 20 (`agent-runtime`). No new languages, no new deployables, no new
operator configuration.

## What "execution-scoped" means here

A platform credential says *who* you are. A run credential also says *which
execution you are part of*. Agent runs need the second kind, because the
interesting blast radius is not "can this caller use the API" but "can this
caller act inside **another run**".

The pieces that exist today:

| Piece | Where | Scope carried |
| --- | --- | --- |
| Per-run platform JWT | `provisionSkillBoxWith` → `GenerateDelegatedTokenWithRun` (`internal/server/agent_server.go`) | `run_id`, `act` (dispatching human), `tracker_conn`, scopes ∩ manifest |
| Per-run gateway token | `mintGatewayToken` (`internal/server/agent_gateway.go`) | tenant, skill, provider, `run_id` (#1817) |
| Run lease | `internal/runlease` | every credential a run was given, so its exit revokes exactly that set |
| Per-run seed dir / workspace | `seedDirFor(runID)`, `workspaceDirFor(runID)` (#1860) | filesystem |
| Per-run journal | `/var/log/agent-runtime/runs/<run_id>/<skill_id>.jsonl` (#2095) | filesystem, read back by `TailRunLog` (#2096) |
| Run-claim enforcement on delegation | `taskRunID` in `SendAgentTask`, run-bound read check in `TailRunLog` (#2112) | `run_id` claim vs. request `run_id` |
| No delegation out of a run | `runForbiddenScopes` strips `tokens:delegate` at mint; `ExchangeDelegatedToken` refuses a run-bound caller (#2069) | a run token cannot obtain a token without its `run_id` |

The rule those add up to: **a run-bound caller may only name its own run.** An
absent `run_id` on a run-bound caller's request is stamped from the claim; a
different one is refused with `PermissionDenied`. Every one of these checks
applies only to a token that carries a `run_id`, so the last row is what keeps
them load-bearing: a run token cannot exchange itself for a `run_id`-less one
(#2069, `TestExchangeDelegatedToken_RunTokenCannotMintRunlessToken`,
`TestMintedAgentTokenScopes_TokensDelegateNeverGranted`).

## D1 (2026-09-28): the in-box A2A server trusts only the daemon

### Problem (#2125)

The in-box A2A server (`agent-runtime/src/a2a.ts`, `POST /tasks`) authenticated
nobody. It ran whatever task arrived and journaled it under whatever `run_id`
the body carried. `TailRunLog` then serves that journal to the *named* run's
viewer, so a box that could reach a peer's port 8674 could write attacker-chosen
output into a third party's run log. The daemon-side check added by #2112 does
not cover it: the daemon is not on that path at all.

Reachability is real, not hypothetical. `compileAllowedPeersPolicy`
(`internal/server/agent_server.go`) turns each running `allowed_peers` box into
an egress `/32` for the calling box, and that policy ships
`NETWORK_POLICY_MODE_LOG_ONLY` unless `CONTAINARIUM_NETWORK_POLICY_ENFORCE` is
armed — so on a default deployment nothing at the network layer stops the hop
either.

### Options considered

**(a) The peer verifies the caller's run-scoped credential.** The calling box
presents its own run token; the peer checks the token's `run_id` against the
body's `run_id`.

**(b) The A2A server is reachable only from the daemon; boxes never call peers
directly.**

### Decision: (b), enforced in-box by a per-box daemon credential

The trust model is (b): **`POST /tasks` is a daemon-only endpoint.** Every hop
goes through `SendAgentTask`, which is where run scoping already lives (#2112).

It is enforced at the application layer, not only at the network layer: the
daemon derives a **per-box secret** and presents it as
`Authorization: Bearer <secret>` on every `POST /tasks`; the box compares it
against the secret it was seeded with, in constant time, and refuses a missing
(401) or wrong (403) credential **before** the body is parsed, the engine is
invoked, or a journal line is written.

Why the application layer carries it:

- The eBPF egress policy is `LOG_ONLY` by default, so a network-policy-only
  answer leaves the hole open on every deployment that has not armed
  enforcement. An in-box check fails closed regardless of network posture — and
  on lab/BYOC hosts that never arm the enforcer at all.
- The network policy deliberately *opens* peer `/32`s today. Making the network
  layer the boundary means changing what `allowed_peers` compiles to, which is a
  different feature's contract (see "Not closed here").

Why the credential is **per-box** and not one shared daemon secret: the boxes
are the untrusted party. A single daemon→box secret would be known to every box,
and box A could replay it at box B — the exact hop being closed.

### Why not (a)

(a) needs the peer to *verify* a credential minted by the daemon. Platform
tokens are HMAC-SHA256 (`internal/auth/token.go`), so the verification key **is**
the signing key: handing it to a box would let that box mint a token for any
`run_id` and post it to any peer, which is strictly worse than the hole being
closed. The alternatives are an asymmetric key pair for run tokens
(new key distribution, new rotation story, JWT verification inside the runtime)
or a daemon introspection callback on every hop — and a callback puts the daemon
back on the path, at which point routing the task through the daemon is less
surface than adding a second daemon round trip to keep a direct path alive.

(a) also buys nothing that (b) does not, because no legitimate box→peer path
exists: the only A2A sender in the tree is `sendA2ATask`, called only from
`SendAgentTask`; the in-box agent reaches peers through the `call_agent` MCP
tool, i.e. through the daemon. (b) matches what the system already does.

### Mechanism

1. `auth.(*TokenManager).DeriveSharedSecret(purpose, id)` —
   `hex(HMAC-SHA256(jwtSecret, purpose "\n" id))`. Deterministic and
   domain-separated, so the daemon can recompute a box's secret after a restart
   with no new state and no new operator configuration, and no box can derive
   another box's.
2. `agentA2ASecret(skillID)` (`internal/server/a2a_client.go`) is that
   derivation at `a2aSecretPurpose`. The daemon computes the **peer's** secret in
   `SendAgentTask` and `sendA2ATask` sends it as a bearer token.
3. `serveModeCommand` exports `CONTAINARIUM_A2A_TOKEN=<the box's own secret>`
   into the serve-mode process, alongside `CONTAINARIUM_SKILL_ID`. It is added to
   `SECRET_ENV_VARS` in `agent-runtime/src/journal.ts`, so it is redacted out of
   journals like every other credential the box holds.
4. `startA2AServer` takes the expected token. Empty (an old daemon, or a
   hand-started runtime) refuses every task with 401 and logs why — fail closed,
   never fail open.
5. `GET /agent-card` stays unauthenticated: it is the discovery surface, it is
   seeded from the skill manifest, and it neither runs an engine nor writes a
   journal.

### Invariants, and the tests that hold them

| Invariant | Test |
| --- | --- |
| A task with the box's own bearer token runs | `a2a.test.ts` — "accepts a task from the daemon" |
| A wrong bearer is refused 403, a missing/malformed one 401 | `a2a.test.ts` table — "refuses" cases |
| A refused task never reaches the engine and never writes a journal line | same table: engine call count 0, journal root has no file |
| A box's own secret is not its peer's, so the hop cannot be replayed | `TestAgentA2ASecret_PerBoxAndStable` |
| The daemon sends the **peer's** secret, so daemon-originated crew hops work | `TestSendA2ATask_SendsBearerToken`, `TestSendAgentTask_SendsPeerA2ASecret` |
| Serve mode is launched with the box's secret in its environment | `TestServeModeCommand_ExportsA2AToken` |

## D2 (2026-09-29): the network layer denies a box its peers' A2A port

### Problem (#2140)

D1 closed the hop at the application layer but left it reachable:
`compileAllowedPeersPolicy` still turned each running `allowed_peers` box into
an egress `/32` for the calling box, so a box could open TCP to a peer's `:8674`
and get a 401/403 back. D1's in-box check is then the only layer. If it ever
regresses — an older agent-runtime image, a box launched without its
credential, a future refactor — nothing else says no.

`allowed_peers` means two things at once: "may delegate to this peer through
the daemon" (`peerAllowed`, `validateCrewTopology`) and "may open TCP to this
peer's box" (the compiled `/32`). Narrowing the second changes what the field
means.

### Options considered

1. Stop emitting peer `/32`s: `allowed_peers` becomes purely an API-boundary
   concept.
2. Keep the `/32` and add a `NetworkPolicyDenyRule` for tcp/8674 on it.
3. Change nothing and rely on D1's in-box credential alone.

### Decision: option 2 — keep the `/32`, deny tcp/8674 on it

Decided on the sprint's open-questions table (2026-09-29).

- **No legitimate box→peer A2A path exists.** The only A2A sender in the tree
  is `sendA2ATask`, called only from `SendAgentTask`; the in-box agent reaches
  peers through the `call_agent` MCP tool, i.e. through the daemon. The deny
  removes a hop nothing makes.
- **Over option 1:** keeping the `/32` leaves a peer reachable for anything else
  a skill legitimately does box-to-box, so this narrows exactly the A2A port and
  needs no audit of non-A2A peer traffic first.
- **Over option 3:** two independent layers is the point of defense in depth.
- **The daemon is unaffected.** The deny rule sits on the *calling box's*
  egress (TC ingress on its host veth, checked before the allow-list — deny
  beats allow). The daemon delivers a task from the host into the peer's veth,
  a path no box policy governs, and the peer's reply leaves on a source port of
  8674, not a destination port.

### Mechanism

1. `compileAllowedPeersPolicy` emits, next to each resolved peer `/32`, a deny
   rule `{cidr: <peer>/32, port: 8674, proto: tcp}` noted with `a2aDenyNote`.
   Operator/platform CIDRs and the gateway CIDR get no deny.
2. `NetworkPolicyStore.Set` deliberately never writes deny rules (they are
   owned by `MutateDenyRules`, #660), so `storeAgentSkillPolicy` writes the
   allow-policy with `Set` and merges the denies with `MutateDenyRules`.
   `mergeA2ADenyRules` replaces only rules carrying `a2aDenyNote` (a relaunch
   with fewer peers drops the stale ones) and never overwrites an operator
   rule already on a peer's CIDR — the kernel holds one deny per CIDR, and
   replacing a whole-host block with a one-port one would weaken it.
3. Like every agent-skill policy it is `LOG_ONLY` (a would-deny audit event with
   reason `virtual_patch`) until `CONTAINARIUM_AGENT_NETWORK_POLICY_ENFORCE` and
   the daemon-wide enforcer are armed; under ENFORCE the SYN is dropped.

### Invariants, and the tests that hold them

| Invariant | Test |
| --- | --- |
| Every resolved peer `/32` is still allowed and carries a tcp/8674 deny | `TestCompileAllowedPeersPolicy` |
| The deny survives compilation into a port-scoped kernel entry, on peers only | `TestCompileAllowedPeersPolicy_A2ADenySurvivesCompile` |
| The denies reach the store; a relaunch drops stale ones, keeps operator rules | `TestStoreAgentSkillPolicy_PersistsA2ADenies` |
| An operator rule on a peer's CIDR is not overwritten | `TestMergeA2ADenyRules_OperatorRuleOnSameHostWins` |
| On a real kernel under ENFORCE: box → peer `:8674` is dropped, box → peer other port connects, host (daemon) → box `:8674` connects | `TestAttachedProgram_BoxCannotReachPeerA2APort` (`-tags=ebpf_load`, the `ebpf-load` CI lane) |

`cmd/netpolicy-smoke` drives the full enforcer against a live container and is
the manual place to watch the would-deny events on a backend.

## Not closed here

- **A box naming another run on itself.** A box knows its own secret, so it can
  post to its own A2A port under any `run_id`. `TailRunLog` bounds the damage:
  it only reads the journal of a box that is a member of the named run. Closing
  it fully needs the run-to-box binding checked in-box, which needs a per-run
  credential the box cannot forge — the same asymmetric-key work (a) needs.
- **The network layer on a default install.** D2 (#2140) denies a box its
  peers' 8674, but agent-skill policies ship `LOG_ONLY`, so on a deployment that
  has not armed enforcement that deny is observed, not dropped — D1's in-box
  credential is then the layer that holds.
