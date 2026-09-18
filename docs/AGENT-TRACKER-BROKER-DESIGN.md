# Agent Tracker Broker — Design Note

> Status: **Exploration / not yet approved.** This proposes a daemon-side
> *tracker broker* that lets an agent running in a box read and update issues
> and open change requests on GitHub or GitLab **without the tracker
> credential ever entering the box**. Nothing here is built yet. It applies
> the custody model of the model gateway
> (`docs/AGENT-MODEL-GATEWAY-DESIGN.md`) to a second kind of upstream, and
> builds on the agent-skills mechanism (`docs/AGENT-SKILLS-CREWS-DESIGN.md`)
> and run-scoped credentials (`internal/runlease`).

## What this closes

Agents that do engineering work report their status where the humans are
looking: they claim an issue with a comment, link the change request they
opened, and post what stalled. Today that only works when the agent process
has a tracker CLI and a tracker credential in its own environment, which
bakes in four problems:

1. **The credential has to live in the box.** The only ways to hand a box a
   tracker token are the existing secret delivery modes
   (`SECRET_DELIVERY_ENV` / `_FILE` / `_COMPOSE` in
   `proto/containarium/v1/secrets.proto`) — all three place the value inside
   the box, readable by the agent and by anything that prompt-injects it.
   Tracker tokens are coarse (a GitLab `api`-scope token or a classic GitHub
   PAT can do everything the account's role allows, including deleting
   branches and editing CI), so the blast radius of one compromised box is
   the whole project.
2. **Provider knowledge leaks into every agent prompt.** An agent has to know
   whether the repo is on GitHub or GitLab, which CLI to call, that a merge
   request is `!N` but an issue is `#N`, which features the tracker's tier
   lacks. That is per-deployment configuration, and it does not belong in a
   skill.
3. **Identity is self-asserted.** Concurrent agents share one tracker
   account, so they tell each other apart with an id they type into the
   comment themselves. Nothing stops one run from signing as another.
4. **No audit, no off switch.** The platform cannot say which run posted
   which comment, and stopping a misbehaving agent means rotating the token
   at the tracker and re-delivering it everywhere.

The **tracker broker** moves the credential, the provider knowledge, and the
identity stamp to the daemon. The box keeps only what it already has: its
run-scoped platform JWT.

## Goals / non-goals

**Goals**

- The tracker credential lives in **exactly one place** (the daemon-side
  secrets store), is **never delivered** to a box, and is **not readable
  back** through the API once set.
- Agents speak **provider-neutral verbs**; GitHub vs GitLab is resolved by
  the daemon from the tenant's tracker connection.
- Every tracker write is **attributed by the platform** to
  `(tenant, skill, run, model)` and recorded in the audit log.
- **Two independent off switches**: the operator disconnects or rotates the
  tracker connection (all runs lose access at once), and ending a run's
  lease revokes that run's access immediately.
- **Least privilege by verb.** A run can do what its skill manifest's scopes
  allow (comment, claim, open a change request) and nothing else the
  upstream token happens to permit.
- Opening a change request works **without a push credential in the box**.

**Non-goals**

- Not a general-purpose tracker API proxy. The verb set is deliberately
  small; anything outside it stays a human or operator action.
- Not a replacement for process. Rules such as "claim before coding" or "one
  standup comment per run" stay in the skills that own them — this removes
  *provider and credential* knowledge from skills, not workflow.
- Not a CI-runner integration. Provisioning CI runners for a second provider
  (`internal/runner`) is separate work.
- No merge, no branch deletion, no repository administration through the
  broker.

## Relationship to earlier decisions

This note changes direction on two things that were written down
deliberately, so it says so rather than leaving a reviewer to find it.

**The remote-coding-agent journey (`docs/product/remote-coding-agent.md`,
Story 4).** That story decided the agent's work returns to the developer
over the existing SSH path (`containarium push` / pull) and that *"the agent
cannot open a PR on its own, and that is the deliberate price of adding no
credential."* That decision stands for its case: a developer's own box, with
a developer at the other end to review and push. The broker targets the case
that story left open — **unattended skill runs**, where no developer's
laptop is in the loop and the status trail on the tracker *is* the product.
The PRD's follow-ups were an in-box per-repo deploy key (P1) and GitHub App
installation tokens (P2). The broker replaces the P1 idea — a repo-scoped
key in the box is still a key in the box — and composes with P2: a
short-lived installation token is the preferred *daemon-held* credential
where the provider offers one.

**"No forge PAT inside the daemon."** `containarium runner reconcile` runs
as an ordinary client precisely *"so no GitHub PAT or privileged auth context
has to live inside the daemon."* The broker does place a forge credential in
the daemon's custody. The argument for accepting that here:

- The alternative on the table is not "no credential" but "credential in
  the box". The model gateway already settled that daemon custody is the
  lesser exposure for an upstream key an agent must be able to *use* but
  never *read*.
- It is opt-in per tenant. A daemon with no tracker connections holds
  nothing, and the runner controller's arrangement is untouched.
- Custody is narrowed as far as each provider allows (next section), and the
  credential is broker-only and write-only.

This is a reversal-in-part of a stated principle and needs an explicit
decision at review — it is Open question 1.

### Preferred credential types

The broker's verb set bounds what a *box* can do. The credential's own scope
bounds what a *daemon compromise* can do, so `tracker connect` should steer
toward the narrowest type and say plainly when it was given a broad one:

| Provider | Preferred | Accepted with a warning |
| --- | --- | --- |
| GitLab | **Project access token** — one project, a role, mandatory expiry | Group or personal access token |
| GitHub | **GitHub App installation token** (minted on demand, ~1h, repo-scoped) or a **fine-grained PAT** limited to the one repository | Classic PAT |

Both providers let a token describe itself (scopes, expiry), so
`tracker connect` and `tracker status` populate `credential_expires_at` and
the breadth warning from the upstream rather than asking the operator.

## Architecture

```
  agent box                          daemon (backend host)              tracker
 ┌──────────────────┐   platform   ┌───────────────────────────┐      ┌─────────┐
 │ in-box runtime   │   JWT with   │ TrackerService (gRPC/REST)│      │ GitHub  │
 │  platform MCP    │──run_id + ──▶│  1. authn: platform JWT   │      │   or    │
 │  (tracker tools) │  tracker:*   │  2. authz: scope + verb   │─────▶│ GitLab  │
 │                  │   scopes     │  3. resolve connection    │ real │ (SaaS or│
 │ no tracker token │              │  4. stamp identity        │ cred │  self-  │
 │ no tracker egress│◀─────────────│  5. provider adapter      │      │ managed)│
 └──────────────────┘   neutral    │  6. audit event           │      └─────────┘
                        result     └───────────────────────────┘
                                     credential: secrets store,
                                     broker-only, write-only
```

The broker runs **in the daemon on the backend host**, not in a central
control plane. A self-managed tracker is frequently reachable only from the
network the backend sits in (notably for bring-your-own-compute hosts); the
daemon is the one component guaranteed to share that network with the box.

### What the box holds

Nothing new. `provisionSkillBox` already mints a platform JWT carrying the
run's `run_id` claim and exactly the skill manifest's `allowed_scopes`, and
`runlease.End` already revokes it when the run ends. The broker adds
**scopes**, not a token kind:

- `tracker:read` — get / list issues and their comments, read a change
  request's CI verdict.
- `tracker:write` — comment, claim, label, open a change request.

A skill that must not touch the tracker simply does not list them. This
differs from the model gateway, which needs its own token because the
provider SDK — not our client — presents it; here the caller is our own
client code (the platform MCP in-box, the CLI outside it).

### Tracker connection

A tenant-scoped record naming *where* the tracker is and *which* stored
credential to use:

```proto
enum TrackerProvider {
  TRACKER_PROVIDER_UNSPECIFIED = 0;
  TRACKER_PROVIDER_GITHUB = 1;   // github.com or GitHub Enterprise Server
  TRACKER_PROVIDER_GITLAB = 2;   // gitlab.com or self-managed
}

message TrackerConnection {
  string username = 1;           // owning tenant, as in SecretMetadata
  string name = 2;               // e.g. "default"
  TrackerProvider provider = 3;
  string base_url = 4;           // empty = the provider's SaaS endpoint
  string project = 5;            // "owner/repo" or "group/subgroup/project"
  string credential_secret = 6;  // name of a broker-only secret
  google.protobuf.Timestamp credential_expires_at = 7; // surfaced, not enforced
}
```

`provider` is an enum, never inferred from the hostname: a host named
`git.<company>` can be either product.

`credential_expires_at` exists because tracker tokens expire on a schedule
the platform does not control. Status and list calls surface it so an
approaching expiry is visible before agents start failing.

### Broker-only secrets

Every existing delivery mode places the value in the box, and `GetSecret`
returns the value to any caller holding `secrets:read` — which an agent's
JWT may legitimately carry. A brokered credential needs both doors closed:

```proto
// Held by the daemon for brokered upstream calls. Never delivered to any
// box, and write-only: GetSecret returns metadata with an empty value.
SECRET_DELIVERY_BROKER_ONLY = 4;
```

Rotation is `SetSecret` again; the next brokered call uses the new value.
There is nothing to re-stamp, because nothing was stamped.

### Verb set

| RPC | Scope | Notes |
| --- | --- | --- |
| `GetTrackerIssue` | `tracker:read` | Body, state, assignee, labels, comments — normalized fields |
| `ListTrackerIssues` | `tracker:read` | Filter by state / label / search text |
| `GetTrackerChange` | `tracker:read` | Change request state + normalized CI verdict |
| `CommentOnTrackerIssue` | `tracker:write` | Platform-stamped signature (below) |
| `ClaimTrackerIssue` | `tracker:write` | Comment + assign-if-unassigned as one operation |
| `SetTrackerIssueLabels` | `tracker:write` | Add / remove within an operator-defined allow-list |
| `SubmitTrackerChange` | `tracker:write` | Push + open a change request (own section below) |

Responses use one normalized shape regardless of provider — a
`TrackerIssueState` enum rather than `OPEN` vs `opened`, one `number` rather
than `number` vs `iid`, a `TrackerCiVerdict` enum rather than a
provider-specific rollup. Provider differences that cannot be hidden (GitLab
Free allows a single assignee; task-list checkboxes never tick themselves on
either provider) are encoded in the adapter's behavior and documented on the
RPC, not pushed back onto the caller.

`ClaimTrackerIssue` is a first-class verb because it is the one status write
with a correctness requirement: it must detect a live claim by a different
run and refuse. The daemon serializes claims per `(connection, issue)`, which
closes the race two agents hit today when both comment within the same
second — inside one daemon. Across daemons the residual race is resolved by
re-reading after the write and yielding to the earliest claim.

### Platform-stamped identity

The daemon, not the agent, writes the signature line. It knows the run id,
the skill, and the model tier the run was dispatched under, so a comment
posted through the broker ends with:

```
— <skill>/<run-id-short> (<model tier>) via Containarium
```

An agent cannot sign as another run, and an operator can take any comment's
run id straight to the audit log. Because attribution lives in the platform,
**one tracker credential per connection is sufficient** — a bot account per
agent adds rotation burden and no information. On the tracker itself every
brokered comment appears under that one account; the per-run truth is the
signature line plus the audit log.

## Submitting a change without a push credential

Opening a change request needs a pushed branch, and this is the step where
"the token never enters the box" is easiest to lose.

The existing *fetch* path is not a template for it. `FetchGitSource`
(`pkg/core/container/git_source.go`) runs the fetch **inside the box**,
passing the credential as a one-shot `http.extraHeader` argument. That is
acceptable for a fetch: it happens before the agent starts, and the
credential is never persisted. A push happens **after** the agent has had
write access to the workspace, so the repository itself is untrusted input:
a `pre-push` hook, a `credential.helper`, `core.sshCommand`,
`url.<x>.insteadOf`, or `http.proxy` written into `.git/config` would all
capture a credential injected into an in-box push.

`SubmitTrackerChange` therefore never runs git with a credential inside the
box:

1. The agent commits locally and calls
   `SubmitTrackerChange{issue, title, description, draft}`. It names no
   remote and no target ref.
2. The daemon execs `git bundle create` in the box for the workspace's HEAD
   against the fetched base commit (already recorded as `git_commit` on the
   run), and pulls the bundle file out. No credential is involved.
3. On the host, in a fresh temporary bare repository — no hooks, no
   inherited config, `transfer.fsckObjects=true` — the daemon fetches from
   the bundle and pushes the single commit range to a **daemon-chosen**
   branch, `agent/<run-id>/<issue>-<slug>`. The credential is supplied
   through the process environment, not argv.
4. The daemon opens the change request through the provider adapter with
   the closing reference to the issue, stamps the signature, and returns the
   neutral `change` handle.

The agent never chooses the ref, so it cannot push to a default or protected
branch, and it cannot force-push over someone else's work: the branch
namespace belongs to its run.

A credential-injecting git smart-HTTP proxy (the box runs plain `git push`
against the daemon) is the alternative. It is more transparent to the agent
but requires parsing receive-pack ref updates to enforce the same branch
rule; it is deferred unless the bundle path proves too restrictive.

## CLI-first surface (proto → everything else)

Per repo convention the RPCs land in `proto/containarium/v1/tracker.proto`
first, with `(google.api.http)` mappings, and everything else regenerates or
wraps:

- Operator: `containarium tracker connect --provider gitlab --base-url <url>
  --project <group/project> --credential-secret <name>`, `tracker list`,
  `tracker status` (reachability, token validity, expiry), `tracker
  disconnect`.
- Human / CI: `containarium tracker issue view|list|comment|claim|label`,
  `containarium tracker change view|submit`.
- The platform MCP server (`cmd/mcp-server/`) wraps the same client
  functions. **This is also how an in-box agent reaches the verbs:** skill
  boxes carry no `containarium` CLI, so the engine mounts the platform MCP
  in-box — pointed at the run's seeded token file and restricted to the
  tracker tools — beside `agent-box`. Nothing tracker-related goes in
  `cmd/agent-box/` itself; the in-box MCP has no business holding upstream
  reach. See `docs/architecture/agent-tracker-broker.md` (D4).
- A hosted control plane's web UI is one more client of `tracker connect`;
  it adds a form, not a mechanism.

## Security model

- **Custody.** Tracker credential: secrets store only, broker-only,
  write-only, under the store's existing at-rest protection (KMS envelope
  where configured). Box: its existing run-scoped JWT.
- **Least privilege.** The upstream token is coarse; the verb set is not. A
  compromised box can comment, claim, label within the allow-list, and open
  a change request on its own branch namespace — for one tenant's one
  project, until its run ends.
- **Revocation.** Run end → `runlease.End` revokes the JWT → the next broker
  call fails closed. Operator disconnect or rotation → every run loses
  upstream reach at once, with no box touched.
- **Egress.** Agent boxes need no route to the tracker. Where the fetch is
  also brokered, the egress allow-list for an agent box stays "the daemon and
  the model gateway".
- **Untrusted content in both directions.** Issue bodies and comments are
  attacker-influenced text that reaches the agent's prompt; the broker
  returns them as data fields and never interprets them. In the other
  direction the broker strips provider command syntax from agent-supplied
  text (for example GitLab quick-action lines such as `/assign` or `/close`)
  so a comment cannot smuggle a state change the verb did not authorize.
- **Rate limiting.** Per-run and per-connection write budgets, so a looping
  agent cannot flood an issue or exhaust the upstream API quota shared with
  humans.
- **Audit.** Each write is an event
  `(tenant, skill, run, model, verb, project, issue|change, upstream status)`.

## Phasing

| Phase | Deliverable |
| --- | --- |
| 0 | `SECRET_DELIVERY_BROKER_ONLY` + `TrackerConnection` CRUD + `tracker connect/list/status/disconnect` |
| 1 | Read + status verbs (`Get`/`List`/`Comment`/`Claim`/`SetLabels`), GitHub and GitLab adapters, scopes, identity stamp, audit |
| 2 | `SubmitTrackerChange` (bundle → host push → change request) |
| 3 | Rate limits, label allow-list policy, expiry surfacing in status |

Phase 1 alone already removes the credential from the box for every
status-only agent (triage, standup, review-comment roles). Phase 2 is what
an implementing agent needs.

## Open questions

1. **Forge credential in daemon custody — accept or not?** See
   "Relationship to earlier decisions". If the answer is no, the fallback is
   a separate broker process running as an ordinary client beside the daemon
   (the `runner reconcile` arrangement), at the cost of a second component
   to deploy on every backend host.
2. **Host git dependency.** Step 3 of the submit path needs git on the
   backend host, or a pure-Go implementation. Today git runs on the host
   only client-side (`internal/transfer`, behind `containarium push` /
   `sync` on the operator's machine); the daemon itself runs git only
   inside boxes.
3. **Multiple projects per tenant.** One connection names one project. Is a
   connection-per-project list enough, or does a run need to address several
   projects (issue in one, code in another)?
4. **Brokering the fetch too.** Moving `git_credential` behind a connection
   would remove the last per-request tracker credential from the API surface
   and the brief in-box argv exposure during fetch. Worth doing, but
   independent of this note.
5. **Review verbs.** Approve / request-changes are deliberately absent. An
   agent reviewer needs them eventually; whether an agent's approval should
   ever count toward a merge rule is a policy question first.
6. **Webhooks.** Pull is sufficient for the verbs above. Event-driven roles
   would want tracker webhooks delivered to the daemon — inbound reach that
   a private backend host may not have.
