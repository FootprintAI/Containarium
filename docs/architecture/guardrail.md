# Guardrails: scan, redact, gate and attest a dataset before it leaves your side

**Status:** skeleton shipped — contract, CLI, reference engine, attestation.
A production detection engine is a separate deliverable that plugs in
behind the contract (see *What is in-tree and what is not*).

## Problem

A tenant wants to train a model, or let a coding agent loose, on data that
contains PII or secrets. The raw data must never reach the training
environment; the environment must be able to refuse data that was not
stripped and checked; and the agent must only ever see stripped data.

Two deployments were considered:

| | Where stripping happens | Raw data crosses the boundary? |
| --- | --- | --- |
| **A. Strip locally, ship stripped** | the data owner's side | No |
| B. Ship raw, strip in the cloud | cloud side | Yes — the cloud becomes a PII store |

This design is **A**. The guardrail runs where the data already is; what
crosses the boundary is the stripped copy plus a signed record of what
judged it.

## Flow

```
DATA OWNER'S SIDE (deny-all egress except the ship target)        CONSUMER (GPU sandbox, CI job)
raw ─► scan ─► redact ─► re-scan (gate) ─► attest ──► ship ──► verify ─► use
          │                                   │
          └─ engine (separate process)        └─ vault + keys stay here
```

1. **Scan.** Every regular file becomes a text unit; an *engine* reports
   findings as `(unit, start, end, kind, type, confidence)` with offsets in
   Unicode code points. The run asks for **exactly the kinds its policy
   covers** — never an empty list, which by contract means "whatever the
   engine has enabled". An engine that cannot scan one of them answers
   `FAILED_PRECONDITION` and the run stops before writing anything: a
   policy that says REDACT SECRET against a PII-only detector fails, it does
   not attest a PASS that never looked (#2362).
2. **Redact.** Each finding is replaced by a stable placeholder,
   `[[EMAIL:1a2b3c4d5e6f]]`: the engine's type name and 12 hex characters of
   an HMAC over (kind, type, value) under a key that stays local. Same value,
   same token, so joins across documents survive while the token says
   nothing about the value. PII tokens are recorded in a vault (token →
   original); secrets are redacted but never vaulted.
3. **Gate.** The redacted output is scanned again. PASS requires no coverage
   gap (a file the engine could not scan, an undecodable file), no finding of
   a kind the policy marks BLOCK, and residual findings within each rule's
   `max_residual` (default 0). A finding that lies inside a placeholder token
   is ignored: in measurement, the only residuals left after a good redaction
   were the detector reading the placeholder itself, and a gate that can
   never reach PASS is not a gate.
4. **Attest.** The run writes a `GuardrailAttestation`: subject digest,
   engine id + version, policy hash, **the kinds scanned**, per-kind counts
   before and after, gaps, verdict, timestamp — signed with the data owner's
   ed25519 key.
5. **Verify.** The consumer checks the signature with the owner's public key,
   recomputes the digest over the bytes it actually received, requires PASS,
   and states what it needs covered (`--require-kind pii,secret`): an
   attestation whose `kinds_scanned` lacks a required kind is refused by
   name. Only then is the data used.

## Contract (proto first)

`proto/containarium/v1/guardrail.proto`:

- `GuardrailEngineService.Scan(units, kinds) → findings, gaps, engine_id,
  engine_version` — implemented by an **engine**, not by the daemon. Stateless.
  No REST mapping: it is a plug point between two processes on the same side
  of a trust boundary, not a product endpoint.
- `GuardrailKind` (`PII`, `SECRET`), `GuardrailAction` (`ALLOW` / `REDACT` /
  `BLOCK`), `GuardrailVerdict` (`PASS` / `FAIL`) — enums, per the repo's
  strong-typing rule. The engine's finer-grained `type` is free text:
  Containarium reports it and never branches on it.
- `GuardrailPolicy` — one `GuardrailRule` per kind. Its deterministic encoding
  is hashed into the attestation, so a verifier knows which policy a PASS was
  measured against.
- `GuardrailAttestation` — the signed record. The signature covers the
  message's deterministic proto encoding with the signature field cleared.

Offsets are code points by contract so an engine written on a runtime with
a different string model (UTF-16 units, bytes) converts at its adapter and
Containarium slices one way.

## CLI

```
containarium guardrail keygen --out ./tenant
containarium guardrail scan   ./export [--engine host:port] [--kind pii,secret] [--json]
containarium guardrail apply  ./export --out ./export-clean --sign-key ./tenant.key [--policy policy.json]
containarium guardrail verify ./export-clean --attestation ./export-clean.attestation.json --public-key ./tenant.pub [--require-kind pii,secret]
```

`apply` writes the vault, the redaction key and the attestation **beside**
`--out`, never inside it — they would otherwise be hashed into the subject,
and the vault is the one thing that must not ship. `scan --json` prints
offsets and types, never the flagged text, so it is safe to log. `apply`
exits non-zero on FAIL but still writes the attestation, so a FAIL is on
record.

With no `--engine`, the in-tree **reference rules engine** runs: a handful
of regular expressions (email, US phone, SSN, IPv4, Luhn-checked card
numbers, PEM private-key headers, one cloud access-key shape). It exists so
the flow is runnable and testable on a fresh checkout. It is not a detector
anyone should ship data on, and the CLI says so on stderr every time it is
used.

## What is in-tree and what is not

| In this repository | Behind the contract (separate deliverable) |
| --- | --- |
| the proto contract | a real detection engine: rules packs, NER models, checksum-verified identifiers, per-language recognizers |
| the CLI: scan / apply / verify / keygen | the engine's own vault semantics if it keeps one (this flow's vault is a local JSON file) |
| redaction, token-aware gate, attestation, verification | distribution and licensing of the engine |
| the reference rules engine | curated recipes/skills that run the flow unattended |

This mirrors how the rest of the platform is built: the OSS repository
carries the mechanism and a neutral reference implementation; opinionated
or licensed components plug in at runtime.

## Enforcement on the consumer side

Verified against what the recipe mechanism gives us today
(`proto/containarium/v1/recipe.proto`, `internal/server/recipe_server.go`):

| Control | Mechanism | Limit |
| --- | --- | --- |
| No use without a valid attestation | `containarium guardrail verify` as the first line of the recipe's `post_start` (runs under `set -euo pipefail`; a failing **synchronous** deploy returns `Internal`) | an **async** deploy only logs the failure — gated recipes must deploy synchronously; the box still exists, only the workload never starts |
| Gate holds per dataset | one fresh consumer box per attested dataset | `post_start` runs once at deploy, not on restart |
| Dataset read-only to the workload | `podman run -v …:ro` inside `post_start` | recipes have no read-only-mount field |
| Consumer reaches nothing else | the skill's `allowed_peers: []` / operator egress allow-list | confirm kernel enforcement has shipped before relying on it |

The gate is code in the recipe, never a system-prompt instruction.

## What this does and does not prove

The attestation proves that *these bytes* are the ones *this engine* scanned
under *this policy*, and what the gate concluded. It does **not** prove the
engine was any good: detectors have recall below 100%, and "no findings" is
a measured result, not a proof. For sensitive datasets add a sampled human
review before a tenant's first ship and a configurable threshold rather than
assuming zero.

The signing key must stay with the data owner. If the consumer held it, the
consumer could attest its own input.

## Measured

A synthetic dataset (English and Traditional Chinese: payroll notes, a
support ticket, a CRM export, a call log, release notes as a hard negative)
was run through this flow with an external engine combining rules, NER and
a semantic layer. Mechanics held: zero offset mismatches across 51 findings,
stable tokens, and the re-scan converged to zero residual once the gate was
made token-aware. Recall was a function of the engine's rules pack — one
release behind, it missed every Traditional-Chinese identifier; one release
ahead, it caught all of them and still missed international phone formats,
passports and a spaced IBAN. The architecture did not change between the
two runs; the engine did. That is the division of labour this design
depends on.

## Open

- Attestation key custody beyond a file: the owner's KMS, or the platform's
  KMS broker (`docs/security/KMS-BROKER-DESIGN.md`) for operators who want
  it brokered. Key rotation and revocation have no story yet.
- A `ship` verb composing apply → transfer, and the consumer recipe, once a
  real engine is available to measure against.
- TLS on the engine link for an engine that is not on loopback.
