# Security scanning & the operator-visibility boundary — design

**Status:** Draft (RFC)
**Last updated:** 2026-06-19
**Related:**
- [`docs/ZFS-PER-CONTAINER-ENCRYPTION-DESIGN.md`](ZFS-PER-CONTAINER-ENCRYPTION-DESIGN.md) — per-tenant at-rest encryption (Approved)
- [`docs/SECURITY-ENCRYPTION-AT-REST.md`](SECURITY-ENCRYPTION-AT-REST.md) — current at-rest posture (shipped)
- `internal/security/scanner.go` — the current host-mount ClamAV scanner
- `Containarium-cloud` `ContainerSecurityService` + webui `SecuritySection` — the cloud read surface (verdict viewer)

## Context

We are about to surface a per-container ClamAV security report in the cloud
console. Building it exposed a tension worth resolving before we ship the data
path: **what does the platform actually see, and what can we honestly promise a
customer?**

The trigger question from review: *"Ideally the customer's disk has an
encryption key so they think it's unseeable from any party — but the platform's
security scanner can see my box's data. Shouldn't scanning run per-tenant
isolated?"*

That instinct is correct. This doc separates three different guarantees that
are easy to conflate, shows where today's mechanisms actually sit, and proposes
moving the scanner from a **host-mount** model to a **per-tenant, verdict-only**
model so the scanner stops being a platform-side data-access path.

## The core misconception: at-rest encryption is not operator-blindness

Containarium runs tenant workloads as **LXC system containers on a shared host
kernel**. There is no memory boundary between a running container and host
root — that is the design, and it is what makes boxes cheap and fast. The
consequence is unavoidable:

> Anything encrypted **at rest** must be **decrypted in the host kernel** to
> run. While a box runs, host root can read its plaintext memory and its
> mounted rootfs. Disk encryption protects cold disk and co-tenants; it does
> **not** make a running box invisible to the platform operator.

The approved per-tenant ZFS design already states this in its non-goals
("kernel decryption necessarily exposes plaintext in RAM"). So:

| Box state | With per-tenant ZFS encryption | Operator can read? |
|---|---|---|
| **Stopped** | key unloaded → ciphertext on disk and in `zfs list` | No (good) |
| **Running** | key in kernel → rootfs mounted plaintext | **Yes** |

And the current scanner (`internal/security/scanner.go`) leans directly on the
running-state plaintext: it mounts
`/var/lib/incus/storage-pools/<pool>/containers/<box>/rootfs` (read-only) into
the host-side `containarium-core-security` container and runs `clamdscan` over
it. **That is the platform reading every tenant's files.** Correct for a
single-tenant self-host (operator == owner); a privacy contradiction on
platform-shared compute.

Marketing at-rest encryption as "unseeable from all parties" would therefore be
a **false claim**. True operator-blindness needs a hardware memory boundary
(confidential computing), which LXC does not have.

## The three honest tiers

| Tier | Mechanism | Protects against | Operator sees plaintext at runtime? | Scan model that is *consistent* with the claim |
|---|---|---|---|---|
| **A — Encryption at rest** | per-tenant ZFS key, loaded only while running | co-tenants, cold-disk theft, backup exfil | **Yes** | host-mount scan is consistent (operator already sees plaintext) |
| **B — Per-tenant isolated scanning** | scan runs *inside* the tenant boundary; only a signed **verdict** leaves | removes the **scanner** as an operator data-access path | Yes via other host vectors, but **not via scanning** | in-box scanner, verdict-only egress |
| **C — Confidential compute (TEE)** | AMD SEV-SNP / Intel TDX confidential VM + remote attestation | **the operator itself** | **No** — genuine "unseeable from all parties" | scanning *must* be in-guest; host cannot mount |

The reviewer's "per-tenant isolation makes more sense" is **Tier B**. It is the
right move **independent of whether Tier C ever ships**, because it closes the
specific contradiction we are about to introduce: a platform-run scanner
mounting tenant plaintext while we tell customers their data is private.

Tier C is the only thing that delivers the full "unseeable" promise. It is a
much larger lift (a VM boundary, attested boot, a confidential-VM runtime such
as Kata + SEV-SNP) and is already parked as a future confidential-compute item
(Compute Exchange Phase 2). This doc does **not** propose building Tier C now —
it proposes making Tier B the default so our claims stay honest until Tier C
exists.

## Goals / non-goals

**Goals**
- Stop the security scanner from being a platform-side plaintext-access path on
  shared compute (move host-mount → in-box).
- Keep the cloud verdict surface (the report panel) unchanged: it consumes a
  **verdict** (clean / infected + finding metadata), not raw tenant files, so
  it does not care which scanner produced it.
- Define a **claim matrix**: exactly what privacy statement is truthful at each
  tier, so sales/marketing/docs never overstate.
- Map the at-rest (`encrypted`) and scanning (`scan_mode`) controls onto the
  tier-gating epic (cloud #606) cleanly.

**Non-goals (this doc)**
- Building confidential VMs / TEE (Tier C). Designed elsewhere; referenced only
  as the eventual ceiling.
- Changing the at-rest encryption design — Tier A is approved as-is.
- The org-wide CVE/dependency-findings surface (a separate, currently-unwired
  cloud dashboard). This doc is about the per-box AV scan only.

## Proposed change: in-box, verdict-only scanning

### Today (host-mount)
```
        ┌── host kernel (operator trust domain) ───────────────┐
        │                                                       │
 tenant box rootfs ──mount(ro)──►  containarium-core-security   │
 (decrypted plaintext)             runs clamdscan over the       │
        │                          tenant's FILES                │
        └───────────────────────────────────────────────────────┘
   Platform reads tenant plaintext.  ✗ contradicts the privacy story
```

### Proposed (in-box)
```
        ┌── tenant box (tenant trust domain) ──────────────────┐
        │  scan agent runs INSIDE the box's namespace           │
        │  (key already loaded for THIS box only)               │
        │  reads only this box's files                          │
        │            │                                          │
        │            ▼  emits a SIGNED VERDICT (no file bytes)  │
        └────────────┼──────────────────────────────────────────┘
                     ▼
         daemon collects verdict ──► cloud ContainerSecurityService ──► panel
   Platform sees {clean|infected, count, finding metadata, signature}.
   Platform never mounts the rootfs.  ✓ consistent with the privacy story
```

**The verdict contract.** What leaves the tenant boundary is a structured,
signed result — never file contents:
- `status` (clean | infected), `findings_count`
- per-finding **metadata only**: signature name, path, severity — *not* the
  infected file's bytes
- `scanned_at`, `scan_duration`, scanner/signature-DB version
- a signature so the daemon (and cloud) can trust the verdict came from the
  sanctioned in-box agent, not a tenant forging "clean"

**Where the scan runs.** Options, to be decided in implementation:
1. A short-lived sidecar process the daemon injects into the box's namespace at
   scan time (has the box's mounted view, nothing else).
2. A per-tenant scanner instance (one security context per org, not one shared
   `containarium-core-security` for the whole host).

Either way the invariant is: **the scanner's data access is scoped to one
tenant, and only a verdict crosses the boundary.**

### What stays the same
The cloud `ContainerSecurityService` and the webui `SecuritySection` already
display a verdict (badge + finding metadata + scan time). They are agnostic to
the producer, so **the read surface needs no change** — only the OSS scanner's
data path moves. This is why the viewer can ship behind the same contract once
the data path is corrected.

### BYOC is exempt
On a customer's own enrolled host (BYOC), operator == customer, so a host-mount
scan reads the customer's *own* data — no contradiction. The host-mount model
may remain for BYOC; the in-box model is required for **platform-shared
compute**. The daemon should pick the model by deployment context, not ship two
incompatible claims.

## The claim matrix (what we may truthfully say)

| Tier active | Truthful customer-facing claim | Must NOT claim |
|---|---|---|
| A only | "Encrypted at rest with a per-tenant key; co-tenants and cold disks see ciphertext." | "Operator cannot see your data" / "unseeable" |
| A + B | A's claim **plus** "Security scanning runs in your container's boundary; only a clean/infected verdict leaves it — the platform's scanner never reads your files." | "The platform cannot technically access your running data" (other host paths remain) |
| A + B + C | "Runs in a confidential VM; data is unreadable to the platform operator, hardware-attested." | (this is the strong claim; only valid with attestation live) |

This matrix is the load-bearing output of the doc: it ties each mechanism to
the exact sentence it licenses.

## Mapping onto tier-gating (cloud #606)

#606 proposes gating resource-heavy per-box features (monitoring, security
scanning) to paid tiers. With the tiers above, the gate has a natural shape:

- **`scan_mode`** becomes a typed control (`off` | `host` | `in_box`), not a
  bare bool. Free: `off`. Pro+: `in_box` on shared compute.
- The viewer (verdict panel) is the surface that gets tier-gated; the in-box
  scanner is the data path beneath it.
- Tier C (`confidential`) is a future placement class, gated separately when it
  exists.

The viewer ships **first** (you cannot gate a paid feature customers can't
see), the in-box data-path correction lands **before** we advertise privacy,
and the gate is the last layer.

## Open questions

1. **Sidecar vs per-tenant scanner instance** for the in-box model — which has
   the smaller blast radius and lower per-scan cost?
2. **Verdict signing key custody** — reuse the daemon JWT secret, or a
   dedicated scan-attestation key?
3. **Scheduling** — keep the 24h sweep, but per-box in-box instead of a host
   loop? Cost of N short-lived scanners vs one long-lived host scanner.
4. **Stopped boxes** — at-rest = ciphertext, so a stopped encrypted box cannot
   be scanned without loading its key. Scan only running boxes? Scan-on-stop
   before `unload-key`?
5. **Do we want Tier C on the roadmap explicitly**, or keep it as a deferred
   exchange item? Affects how strong a privacy claim we can make near-term.

## Phased rollout

| Phase | Scope | Repo |
|---|---|---|
| 0. This RFC accepted + claim matrix signed off | doc | OSS |
| 1. Verdict contract: signed result struct, no file bytes | OSS |
| 2. In-box scanner (sidecar or per-tenant instance), shared-compute default | OSS |
| 3. Host-mount retained for BYOC; deployment-context switch | OSS |
| 4. Cloud `scan_mode` typed control + verdict surface (panel already built) | cloud |
| 5. Tier-gate per #606 (free `off`, Pro+ `in_box`) | cloud |
| 6. (future) Tier C confidential-VM placement class + attestation | both |

## History

| Date | Author | Change |
|---|---|---|
| 2026-06-19 | hsinhoyeh, drafted with Claude | Initial RFC. Separated at-rest (Tier A) from operator-blindness; proposed in-box verdict-only scanning (Tier B) to stop the scanner being a platform data-access path; claim matrix; TEE (Tier C) as the future ceiling; mapping onto #606. Status: Draft. |
