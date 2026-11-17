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
containarium guardrail verify ./export-clean --attestation ./export-clean.attestation.json --trust-bundle ./bundle.json [--require-kind pii,secret]
```

`apply` writes the vault, the redaction key and the attestation **beside**
`--out`, never inside it — they would otherwise be hashed into the subject,
and the vault is the one thing that must not ship. `scan --json` prints
offsets and types, never the flagged text, so it is safe to log. `apply`
exits non-zero on FAIL but still writes the attestation, so a FAIL is on
record. `verify --trust-bundle` takes the file from `guardrail signer
bundle` in place of a single `--public-key`, so a rotated key still
verifies and a revoked one fails naming the revocation; see "Signer
rotation and revocation" in `guardrail-inbound-and-server-policy.md`.

With no `--engine`, the in-tree **reference rules engine** runs: a handful
of regular expressions (email, US phone, SSN, IPv4, Luhn-checked card
numbers, PEM private-key blocks, one cloud access-key shape). It exists so
the flow is runnable and testable on a fresh checkout. It is not a detector
anyone should ship data on, and the CLI says so on stderr every time it is
used.

## Coding-agent hooks

`containarium guardrail hook <event>` (#3761) applies the same engine
contract and the same markers to a different subject: what a coding agent
gives the model while it works. It is a Claude Code
[hook](https://code.claude.com/docs/en/hooks) handler. The agent runs it for
each event with the event as JSON on stdin, and the handler answers on
stdout. It covers the agent that talks to its model provider directly, which
gateway-side redaction cannot see. Detection, the marker key and the marker
map all stay on the machine the agent runs on; no credential is read.

| Event | What the handler does |
| --- | --- |
| `SessionStart` | Adds context for the model: what a marker is, that an edit with a secret marker is refused, and that a marker cannot be used as the text an edit replaces. |
| `PreToolUse` | The gate. Denies the call when the engine does not answer within `--engine-wait` (3 s). Denies `WebFetch`. Denies a file tool or a command that names the handler's own state directory (best effort for commands). Restores **personal-data** markers in local file-path arguments and in the new content of `Edit` / `Write` / `NotebookEdit`, and returns the changed input with no permission decision, so the user's own permission rules decide. A **secret** marker, or one this machine did not issue, denies the call: a marker is never written literally into a file. No other tool input is ever restored. |
| `PostToolUse` | Replaces the tool's result with a redacted copy of the same shape. Every string is content, for every tool including ones the handler has never seen; only a short per-tool list of enum-like fields is skipped, and never a path. An array of strings is scanned joined, so a key held as lines is seen whole, and keeps its length. A result that is one JSON string (how MCP results arrive) is decoded first. Binary and base64 strings are skipped and counted. |
| `PostToolBatch` | Rescans what is about to reach the model, with no memory of `PostToolUse`, and records anything still unredacted. |
| `UserPromptSubmit` | Blocks a prompt that has a finding, naming the type and never the value. A prompt cannot be rewritten. Background events (`<task-notification>`) arrive here too and are dropped whole. |
| `InstructionsLoaded` | Scans the instruction file and records; this event cannot change anything. |

Markers are the dataset flow's, `[[EMAIL:1a2b3c4d5e6f]]`, under a per-user key
created on first use. The state directory
(`$XDG_STATE_HOME/containarium-guardrail`, default
`~/.local/state/containarium-guardrail`, mode 0700 with 0600 files) holds:

- `marker.key`, the HMAC key;
- `markers.jsonl`, the marker map. A personal-data marker is stored with its
  value. A secret marker is stored with no value, only so it can be told
  apart from an unknown one. Secrets are never stored and never restored;
- `findings.jsonl`, a bounded spool of `GuardrailHookRecord` rows (protojson,
  `proto/containarium/v1/guardrail_hook.proto`): event, tool, source,
  outcome, type and a short excerpt of the already-redacted text. A full
  spool drops rows and never blocks the agent;
- `stamps/<pid>`, touched on every invocation and named after the agent
  process, so an operator can tell whether hooks are firing.

**Engine and size limit.** `--engine` names a `GuardrailEngineService` on a
unix socket or a loopback address; anything else is refused. With no
`--engine` the reference rules engine runs in-process. A result up to
`--full-scan-max-bytes` (16 KiB) gets the engine's scan. A larger one gets
the in-process pattern pass only and is recorded as `PARTIALLY_SCANNED`, so
one large file cannot hold every tool call for seconds. The same fallback
applies when the engine fails in `PostToolUse`: by then the tool has run, and
a degraded scan beats none.

**Failure.** A denial or a block is an answer and exits 0. Every internal
error exits **2** with nothing on stdout, never 0: `onFailure: "block"` does
not catch a hook that exits 0 with unusable output. Configure every hook in
exec form with `onFailure: "block"` and a short `timeout`:

```json
{ "type": "command", "command": "containarium", "args": ["guardrail", "hook", "PreToolUse"], "onFailure": "block", "timeout": 10 }
```

Installing the hooks is a separate change (#3762). Behaviour was checked
against Claude Code 2.1.326; `onFailure` needs 2.1.295 or later.

### What the hooks do not cover

The hooks protect against **accidental disclosure by a cooperative agent**.
They do not stop an agent that deliberately transforms a value, or the user,
who owns the machine.

- **A typed prompt** can be blocked, not redacted, and its text stays in the
  agent's local transcript.
- **After the tool has run**, a handler that crashes or times out in
  `PostToolUse` cannot stop the original result. `PostToolBatch` records it.
- **A `PostToolBatch` block stops the turn but does not remove the result**
  from the conversation. `--block-on-batch-finding` (off by default, not yet
  proven against a live agent, #3765) stops the turn and then refuses later prompts
  in that session until `/clear` or a new session.
- **A failing command's output** is redacted like any other result only where
  the agent accepts a replacement for a failed call. Wrapping shell commands
  so they report their exit status and always succeed is a follow-up (#3765).
- **An edit that must match a redacted value** is not possible: the agent
  checks the text to replace against the file before any hook runs.
- **Another hook's input rewrite can replace this one**, so a marker can end
  up written literally. `PostToolUse` records a marker still present in the
  input (`MARKER_IN_TOOL_INPUT`).
- **Context the agent loads by itself**: instruction and memory files are
  recorded, never rewritten; file names in the version-control status the
  agent adds at session start pass no hook; `@`-mentioned files are inlined
  with no tool call unless the agent is run with
  `CLAUDE_CODE_DISABLE_FILE_MENTIONS=1`.
- **`WebFetch`** hands the page to the model inside the tool, so it is denied
  rather than redacted. A fetch through a shell command is covered.
- **Binary and base64 content** is not scanned.
- **Detection is only as good as the engine.** With the reference engine it
  is a handful of regular expressions.

## What is in-tree and what is not

| In this repository | Behind the contract (separate deliverable) |
| --- | --- |
| the proto contract | a real detection engine: rules packs, NER models, checksum-verified identifiers, per-language recognizers |
| the CLI: scan / apply / verify / keygen / hook | the engine's own vault semantics if it keeps one (this flow's vault is a local JSON file) |
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
