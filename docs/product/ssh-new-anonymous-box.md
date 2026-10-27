# PRD: `ssh new.<cloud-domain>`: a Linux box in one command, no signup

**Date:** 2026-10-01
**Status:** draft
**Owner:** hsinhoyeh

## Problem

A developer who wants to try Containarium Cloud has to sign up, verify an
email or connect OAuth, find the create flow, wait for the box, and then
learn our SSH config before they ever reach a shell. That path stands
between "I heard about this" and "I'm typing in a Linux box". Every step is
a place where people drop off, and today we have no measurement of how many
do.

Competitors have started to remove that path completely. Railway now offers
a VM with no registration: you run `ssh railway.new` and they identify you
by your SSH public key. The pitch that circulated reads, roughly, "someone
finally turned 'I need a Linux box for a minute' into a single command."
For a product whose core surface is *SSH into a box*, this is the obvious
thing to demo, and today we can't do it.

The hard part isn't the SSH entry point. It's who ends up on the other end.
`docs/security/SECURITY-FAQ.md` ("Does this apply to the Containarium Cloud
offering too?") already calls the free tier an **open gap**: shared-kernel
LXC is a poor fit for anonymous, possibly hostile tenants. A no-signup box
is the most anonymous tier we could offer. It must not ship on that
substrate.

**Evidence (honest inventory):**

- Competitor signal: Railway's no-signup `ssh railway.new` (secondhand,
  from a social post). We have not measured their adoption.
- In-repo: the SECURITY-FAQ gap above. The same section states that
  Cloud's free tier has no card or identity check.
- **No user quotes, tickets, or funnel data exist for Containarium.** The
  belief that signup friction is our biggest acquisition drop-off is an
  **assumption**. Validating it is metric #1 below.

**Why now:** the competitor has defined the category ("Linux in one
command"), and we already have most of the pieces: sshpiper on the
sentinel, `internal/ttlsweeper`, `internal/sandbox/{pool,ratelimit}`, and
Incus VMs (used today only for `OS_TYPE_WINDOWS_2022`).

## Target user

A **developer evaluating Containarium Cloud** who has an SSH key and a
terminal and doesn't yet want an account. Their job-to-be-done: *"get a
throwaway Linux shell right now, see if it's good, and keep it if it is."*

Not the target for this MVP: existing Cloud tenants (they already have
`containarium create`), OSS operators (that comes later), or agents that
need a sandbox API (see `docs/EPHEMERAL-SANDBOX-DESIGN.md`).

## Success metrics

| Metric | Baseline | Target (hypothesis, revisit after 4 weeks of data) |
|--------|----------|--------|
| **Trial → claimed account**: distinct key fingerprints that complete signup + claim ÷ distinct fingerprints that reached a shell | unknown, instrument first | ≥ 5% |
| **Time to shell**: `ssh` invocation → first prompt, p50 / p95 | unknown (Linux VMs aren't built yet) | p50 ≤ 30 s, p95 ≤ 60 s |
| **Abuse rate**: anonymous boxes force-killed for abuse ÷ anonymous boxes created; plus host escapes | n/a | < 2% killed; **0** host escapes (hard gate) |

The 5% conversion target is a guess. No evidence supports it. Its purpose
is to give the feature a kill/keep threshold, not to forecast anything.

## MVP scope: the core journey

> A developer runs `ssh new.<cloud-domain>` with any SSH key. Within about
> 30 s they land in a fresh Ubuntu VM. A banner shows the box's lifetime
> and how to keep it. They work. If they run `containarium claim`, they get
> a signup link. After they sign up, the same box (same key, same files)
> becomes a normal owned box in their account. If they never claim it, the
> box and its disk are destroyed when the TTL ends.

This journey is the happy path for `/qa-e2e-test`.

### P0 stories

**1. Anonymous SSH entry**

**Story:** As an evaluating developer, I want to `ssh new.<cloud-domain>`
with no account so that I get a Linux shell without signing up.
**Acceptance criteria:**
- [ ] `ssh new.<cloud-domain>` with an ed25519 or RSA key that has never
      been seen before lands in a shell on a fresh Ubuntu 24.04 box, with
      no password and no prompt.
- [ ] The login banner shows the box's expiry time (absolute and
      remaining), its resource limits, and the `containarium claim` hint.
- [ ] The public key fingerprint is the only identity. No email, no name,
      and no other key material is stored.
- [ ] The user has passwordless `sudo` inside the box.
- [ ] Keyboard-interactive or password auth is rejected with a message
      telling the user to use an SSH key.

**Priority:** P0

**2. VM isolation for anonymous boxes**

**Story:** As the platform operator, I want every anonymous box to run as
an Incus VM, not an LXC, so that an anonymous tenant who gets root in the
guest kernel still doesn't have the host.
**Acceptance criteria:**
- [ ] Every box created through the anonymous path has Incus instance type
      `virtual-machine`. An e2e test fails if it is ever a container.
- [ ] Anonymous VMs are placed only on backends flagged for anonymous
      workloads and are never co-scheduled on a backend that hosts core
      service LXCs.
- [ ] `docs/security/SECURITY-FAQ.md` is updated to state that the
      anonymous tier is VM-isolated and the email-signup free tier is not
      (the gap stays open there).

**Priority:** P0

**3. One box per key, reconnectable, hard TTL**

**Story:** As an evaluating developer, I want reconnecting with the same
key to return me to my box so that a dropped connection doesn't lose my
work, and I accept that the box dies at TTL if I don't claim it.
**Acceptance criteria:**
- [ ] A second `ssh new.<cloud-domain>` with the same key, before expiry,
      lands in the **same** box (a file written in session 1 is visible in
      session 2).
- [ ] At most one live anonymous box exists per key fingerprint.
- [ ] At TTL the VM and its disk are destroyed. The sweeper verifies the
      instance and volume no longer exist.
- [ ] Sessions still open get a wall message 10 min and 1 min before
      expiry.
- [ ] Connecting after expiry creates a new, empty box. The banner says so
      explicitly ("your previous box expired").

**Priority:** P0

**4. Abuse guardrails**

**Story:** As the platform operator, I want hard limits on what an
anonymous box can do and how many can exist so that the tier can't be used
for mining, spam, or attacks, or to drain capacity.
**Acceptance criteria:**
- [ ] Fixed caps per box: vCPU, RAM, disk, and TTL. Exact values are in
      open questions. Exceeding the disk cap fails writes, and the host is
      unaffected.
- [ ] Egress is deny-by-default except DNS, HTTP, and HTTPS. A test proves
      that outbound TCP/25 and an arbitrary high port are dropped.
- [ ] No port exposure, routes, or public URLs for anonymous boxes.
      `expose`/route calls against them are rejected.
- [ ] Per-fingerprint and per-source-IP rate limits on box creation. The
      (N+1)th create inside the window gets a clear "slow down" message,
      not a hang.
- [ ] A global cap on concurrent anonymous boxes. At the cap, new users
      get a "we're full, sign up for a guaranteed box" message and the
      connection closes cleanly.
- [ ] Operator controls: a global kill switch that disables the
      anonymous door, and a per-fingerprint ban. Both take effect without
      a redeploy.

**Priority:** P0

**5. Claim: keep the box by signing up**

**Story:** As an evaluating developer who likes the box, I want to run one
command and sign up so that my box (files intact) becomes mine and stops
expiring.
**Acceptance criteria:**
- [ ] `containarium claim`, run inside the anonymous box, prints a
      single-use signup URL bound to the box and the key fingerprint. It
      expires with the box.
- [ ] After the user completes signup through that URL, the box shows up
      in their account's `containarium list` with the same name, files,
      and authorized key.
- [ ] The TTL is removed (or replaced by the account plan's lifecycle),
      and the anonymous egress/expose restrictions are lifted to the
      plan's defaults.
- [ ] A claim URL used a second time, or after expiry, fails with a clear
      error and doesn't attach the box to the second account.
- [ ] Per the CLI-first rule, `claim` is a cobra subcommand. Any MCP
      exposure wraps the same Go function.

**Priority:** P0

**6. Funnel instrumentation**

**Story:** As the product owner, I want each step of the journey recorded
so that I can tell whether this feature converts and where people drop
off.
**Acceptance criteria:**
- [ ] Events are emitted, each keyed by a hashed key fingerprint:
      `anon_connect`, `anon_shell_ready` (with time-to-shell),
      `anon_reconnect`, `claim_link_issued`, `claim_completed`,
      `anon_expired`, `anon_killed_abuse`, `anon_rejected_capacity`,
      `anon_rejected_ratelimit`.
- [ ] One query or dashboard shows all three success metrics for a chosen
      date range.

**Priority:** P0

Six P0 stories. Each of 1–5 is needed for the journey to work end to end
and be safe. Story 6 is needed for us to know whether it worked.

## Later phases

- **P1: warm VM pool.** Pre-booted anonymous VMs bring time-to-shell from
  boot time down to a few seconds. Defer until the p50 data shows boot
  time is what makes people abandon.
- **P1: OSS opt-in.** A sentinel flag that lets self-hosted operators run
  their own `new.<their-domain>` door, reusing the same mechanism.
- **P1: GitHub-key bonus tier.** If the presented key matches
  `github.com/<user>.keys`, offer a longer TTL or bigger caps in exchange
  for the light identity.
- **P2: choice of image** (`ssh rocky9@new.<cloud-domain>`), and **P2:
  `scp`/`sftp` and port-forwarding** into anonymous boxes, once abuse data
  exists.
- **P2: agent-friendly variant.** A JSON banner or `ssh new.<cloud-domain> -- <cmd>`
  one-shot exec for agents. It overlaps with the ephemeral-sandbox design,
  so reconcile the two first.

## Out of scope

- **Anonymous LXC boxes.** Cut on purpose. Shared-kernel isolation for
  anonymous users is the documented gap. A faster LXC version is not an
  acceptable trade.
- **Public URLs / port exposure for anonymous boxes.** Anonymous hosting
  is the main source of phishing and malware abuse. It stays behind claim.
- **GPU or large-shape anonymous boxes.** The cost and abuse surface are
  out of proportion to a trial.
- **Closing the email-signup free-tier gap.** Related but separate. This
  PRD only makes sure the new tier doesn't widen it.
- **Persistence for unclaimed boxes past TTL.** "Keep it" means claim.
  There is no anonymous extension.

## Open questions & assumptions

| # | Question / assumption | Proposed default | How to validate |
|---|---|---|---|
| 1 | **Assumption:** signup friction is a meaningful acquisition drop-off. | Ship and measure metric #1. | Kill or rethink if conversion < 1% after 4 weeks. |
| 2 | SSH has no SNI, so `new.<cloud-domain>` needs its own IP (or port) on the sentinel to tell it apart from normal sshpiper routing. Dedicated IP or username-based (`ssh new@<cloud-domain>`)? | Dedicated IP + hostname. That matches the one-command UX. | `/architect-design` |
| 3 | Per-box caps and TTL values. | 2 vCPU, 4 GiB RAM, 20 GiB disk, 4 h TTL | Cost model × global cap; adjust on abuse data |
| 4 | Global concurrent cap and monthly budget for anonymous VMs. | Needs a number from the owner. | Owner decision |
| 5 | Can our current backends run Linux Incus VMs (nested virt / KVM available)? Only Windows uses VMs today. | Assume a dedicated KVM-capable backend pool. | Spike on one backend |
| 6 | Cold VM boot time with our image. Does p50 ≤ 30 s hold without a warm pool? | Assume yes; warm pool is P1. | Measure in the spike for #5 |
| 7 | Does keying identity on a fingerprint create privacy or legal obligations (abuse-report handling, logs of source IPs)? | Retain source IP + fingerprint hash for 30 days for abuse only. | Check against the ToS / privacy policy |
| 8 | Does claim migrate the VM into the tenant's normal pool (LXC), or stay a VM? | Stays a VM on the claimed plan. Migration is later. | `/architect-design` |
| 9 | Product domain for the door (`new.<cloud-domain>`). | Owner's call. | Owner decision |
