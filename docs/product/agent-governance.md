# PRD: Agent governance — identity chaining, scope inheritance, attributable audit

**Date:** 2026-09-02
**Status:** draft
**Owner:** hsinhoyeh

## Problem

Containarium can run an AI agent with a shell, a credential, and network access
inside a tenant's infrastructure. An enterprise security reviewer asks three
questions about that, and today we cannot answer any of them:

1. *"Can the agent do more than the engineer who dispatched it?"* — **Yes, it
   can.** See G3; this is a live privilege-escalation path, not a gap.
2. *"Who authorized this action?"* — For anything an agent did, the audit row
   names the **agent**, not the human. The dispatching identity is discarded at
   token-mint time and appears nowhere downstream.
3. *"This token leaked. What did it do?"* — **Unanswerable.** Audit rows carry
   no token identifier, so there is no way to enumerate a credential's actions.

This is the difference between a developer tool and something deployable inside
a regulated organization. It is not a feature customers ask for by name; it is
the review that blocks the purchase.

**What already exists (a genuinely strong base — this epic is not a rewrite):**

- A 25-scope `<resource>:<action>` model with per-RPC enforcement
  (`internal/auth/scopes.go`, `auth.RequireScope`).
- Roles, tenant authorization (`auth.AuthorizeTenant`), access/refresh token
  split with expiry caps (`internal/auth/token.go`).
- **Tamper-evident audit** — SHA-256 `row_hash` over (row fields ‖ `prev_hash`)
  with `VerifyChain` reporting the first bad row
  (`internal/audit/hash_chain.go`). A row edit invalidates every subsequent row.
- Scoped agent tokens minted per skill (`internal/server/agent_server.go:236`).
- Token revocation.

The gap is **not** tamper-evidence. It is **attribution**: who acted, on whose
authority, with which credential.

## The gaps, with evidence

| ID | Gap | Evidence |
|---|---|---|
| **G1** | **Scopes fail *open*.** A token with a missing/nil `scopes` claim is treated as *unrestricted*. Any legacy or unscoped token is omnipotent. | `internal/auth/scopes.go:17-22` — *"treating a missing or nil `scopes` claim as 'no scope restriction'"* |
| **G2** | **No delegation chain.** `Claims{Username, Roles, Scopes, TokenType}` has no actor/on-behalf-of field. When an agent token is minted its subject is `agent-<skill-id>`, so the dispatching human is **erased** from every downstream call and audit row. | `internal/auth/token.go:51`; subject prefix at `agent_server.go` (`agentBoxPrefix`) |
| **G3** | **Agent tokens are not bounded by the caller's own grant.** `RunAgentSkill` gates on `agents:run` alone, then mints the **skill manifest's** `allowed_scopes` with no intersection against the caller's scopes. `agents:run` is therefore a universal upgrade to any scope any installed skill declares — and catalogs load at runtime via `CONTAINARIUM_SKILLS_DIR`, so that set is not fixed at build time. `auth.ScopesFromContext` exists and is simply not consulted here; no subset helper exists in `internal/auth`. | `agent_server.go:130` (gate), `:236` (mint), `internal/auth/token.go:390` (unused) |
| **G4** | **Audit rows cannot be tied to a credential, a tenant, or a session.** No `token_id`/`jti`, no `org_id`, no `run_id`. | `internal/audit/store.go:14` (`AuditEntry`), `:62` (schema) |
| **G5** | **One identity field.** `Username` conflates actor and subject; there is no way to query "everything done under engineer X's authority." | `internal/audit/store.go:14` |
| **G6** | **The chain is verifiable but not anchored.** Rows live in Postgres; a privileged operator with DB access can rewrite every row *and* recompute the whole chain undetectably. Tamper-evident against row edits, not against a privileged rewrite. | `internal/audit/hash_chain.go` — chain root is never published outside the DB |

## Target user

**The security reviewer or compliance officer evaluating Containarium**, not the
developer using it. They do not use the product; they decide whether it may be
deployed.

**JTBD:** *"Prove to my auditor that an AI agent acting in our infrastructure
can do no more than the human who dispatched it, and that I can reconstruct
exactly what it did, on whose authority, with which credential."*

Secondary: the **operator responding to an incident** — "a token leaked at 14:20;
what did it touch?"

## Success metrics

| Metric | Baseline | Target |
| --- | --- | --- |
| Privileged actions attributable to a **human** principal | **0%** for agent-dispatched actions — the agent's subject replaces the dispatcher's (G2) | 100% |
| Agent tokens whose scopes are a **subset** of the dispatcher's | **0%** — no intersection is performed (G3) | 100% |
| Time to answer *"what did this credential do?"* | **Unanswerable** — no `jti` in `audit_logs` (G4) | One indexed query |
| API calls made by scope-restricted tokens | unknown — instrument first; unscoped currently means unrestricted (G1) | 100%, with unscoped rejected |

## MVP scope — the core journey

> A security reviewer takes one agent-performed action from the audit log and
> traces it back to the human who authorized it, the credential used, and the
> scopes that bounded it — and confirms the agent could not have exceeded that
> human's own permissions.

---

**Story 1 — bound agent tokens by the dispatcher's grant** *(security fix)*

**Story:** As a security reviewer, I want an agent's token to carry no scope its
dispatcher lacks, so that dispatching an agent cannot escalate privilege.

**Acceptance criteria:**
- [ ] Token mint uses `intersect(caller.scopes, skill.allowed_scopes)`, not the
      manifest alone.
- [ ] A caller holding only `agents:run` receives an agent token with **no**
      resource scopes, and the skill fails closed rather than running unbounded.
- [ ] A wildcard (`*`) caller still intersects to the manifest's scopes — the
      manifest remains a ceiling, never a floor.
- [ ] A named `auth.IntersectScopes` helper with table-driven tests covering
      wildcard, empty, disjoint, and subset cases.
- [ ] Regression test: a skill manifest declaring a scope the caller lacks
      cannot produce a token carrying it.

**Priority:** P0 — file and fix as a **security issue** independently of this
epic's schedule.

---

**Story 2 — the delegation claim**

**Story:** As a security reviewer, I want every derived token to name the
principal it acts for, so that the human authority survives every hop.

**Acceptance criteria:**
- [ ] `Claims` gains an actor/delegation field (RFC 8693 `act` shape: the
      immediate actor, nested for multi-hop) recording the dispatching subject.
- [ ] `RunAgentSkill` and A2A peer calls (`SendAgentTask`) populate and
      **propagate** it; a second hop nests rather than overwrites.
- [ ] Chain depth is bounded and a token exceeding it is rejected.
- [ ] Absent `act` remains valid (backward compatible) but is reported as
      unattributed by the metric in Story 3.
- [ ] A token cannot forge `act` — it is set only by the minting server from the
      authenticated context, never from request input.

**Priority:** P0

---

**Story 3 — attributable audit rows**

**Story:** As an incident responder, I want to query the audit log by human
principal, credential, and session, so that I can scope a breach in one query.

**Acceptance criteria:**
- [ ] `AuditEntry` and `audit_logs` gain `actor` (the human principal from
      `act`), `token_id` (`jti`), `org_id`, and `run_id`, added with
      `ADD COLUMN IF NOT EXISTS` as the existing schema does.
- [ ] New columns are included in `computeRowHash` — **and the version bump is
      handled**, so rows written before the change still verify. The chain must
      not break on migration; a test proves an old-format row and a new-format
      row verify in one chain.
- [ ] `QueryParams` supports filtering by `actor`, `token_id`, and `org_id`,
      each indexed.
- [ ] Every agent-performed action records both the agent (subject) and the
      dispatching human (actor).
- [ ] Revoking a token yields the list of actions it performed.

**Priority:** P0

---

**Story 4 — fail-closed scope enforcement**

**Story:** As an operator, I want to require that every token is explicitly
scoped, so that an unscoped credential cannot silently hold full authority.

**Acceptance criteria:**
- [ ] A daemon setting enables strict mode: a token with a missing/nil `scopes`
      claim is **rejected**, not treated as unrestricted.
- [ ] Default remains permissive for backward compatibility; strict mode is
      opt-in and documented as the recommended posture.
- [ ] Before enabling, an operator can report how many recent calls used
      unscoped tokens — so the switch is a measured decision, not a gamble.
- [ ] The daemon's own service tokens are explicitly scoped (or explicitly
      wildcard) so strict mode does not break the platform.

**Priority:** P0

## Later phases

- **P1 — external anchoring of the chain root.** Periodically publish the chain
  root outside the database (append-only object store, or a co-signed
  timestamp), closing G6. Deferred, not dismissed: the chain already detects row
  edits; anchoring closes the narrower privileged-insider hole and lands without
  reworking Stories 1-4.
- **P1 — actor on the detached run record.** `RunRecord`
  (`docs/architecture/remote-coding-agent.md`) has no actor field. A run that
  outlives its dispatching connection with no recorded identity is this epic's
  problem appearing in the other sprint. **Add the field before that format
  ships** — free now, a migration later. Tracked on #1672.
- **P1 — scope inheritance across the tenant boundary.** `SchedulerRequest` has
  no org field (OSS #1102/#1103), so placement decisions cannot be org-attributed.
- **P2 — permission inheritance into *external* systems** (the git forge, cloud
  providers). Devin's full claim; requires per-system credential exchange and is
  a much larger surface than the platform's own API.
- **P2 — a compliance export.** Once rows are attributable, an auditor-facing
  export is mostly formatting. Pairs with the ISO 27001 mapping.

## Out of scope

- **Rebuilding the audit hash chain.** It exists, it is correct, and it is not
  the gap. This epic adds columns to it.
- **Rebuilding the scope model.** 25 well-factored scopes with per-RPC
  enforcement is a good foundation; G1 and G3 are about how tokens are *minted
  and defaulted*, not how scopes are *defined*.
- **A policy engine (OPA/Rego).** The scope model already expresses what is
  needed; adding a policy language is a language, a lane, and a new failure mode
  for a problem four fields solve.
- **SSO/SCIM identity provisioning.** Real enterprise requirements, but they are
  about *establishing* identity; this epic is about *propagating* it.
- **Warm pools and declarative blueprints.** Considered alongside this and cut:
  warm pools are already phased under #1488, and blueprints are blocked on the
  ZFS snapshot RPC (#1160). Neither is a governance concern.

## Open questions & assumptions

1. **Does the cloud control plane mint its own tokens?** If so, Stories 1-2 must
   land there too or the OSS fix is bypassed by the cloud path (cf. project
   memory: the cloud fronts OSS via a *partial* shim). *Validate before
   estimating.*
2. **Hash-chain migration is the schedule risk in Story 3.** Adding fields to
   `computeRowHash` changes every future row's hash. Old rows must keep
   verifying, which means a versioned hash function. This is the one place in
   the epic where a wrong move corrupts existing evidence — design it first.
3. **How many live tokens are unscoped?** Story 4's rollout depends on the
   answer and nobody has measured it. The measurement is itself an acceptance
   criterion.
4. **Is `act` the right shape, or a flat `on_behalf_of`?** RFC 8693 nesting
   supports multi-hop A2A, which crews need; a flat field is simpler and
   sufficient for single-hop. *Decide in design.*
5. **Demand is inferred, not evidenced.** No customer has filed this. It is
   derived from a competitor's published enterprise posture and from the review
   questions an enterprise buyer typically asks. *Validate:* put G1-G3 in front
   of one enterprise prospect and confirm they are blockers before scheduling
   the P1s.
