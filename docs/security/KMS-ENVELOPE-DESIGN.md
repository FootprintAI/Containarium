# KMS Envelope Encryption (Audit C-HIGH-6)

This is a design note for replacing Containarium's
single-master-key secret encryption with a KMS-backed envelope
scheme. Documentation lands ahead of implementation; the audit
finding stays open with `[~]` until the code follows.

The audit finding C-HIGH-6 flagged the on-host master key as a
single point of compromise. This doc covers what's protected
today, what isn't, and how the envelope approach changes the
threat model.

## Today: master key on the daemon host

`pkg/core/secrets/crypto.go` encrypts every tenant secret with
AES-256-GCM using a single 32-byte master key loaded from
`/etc/containarium/secrets.key` (mode `0400`, root-only). The
key is generated once on first daemon startup and reused for
every subsequent encrypt / decrypt.

What this gets us:

- **Confidentiality at rest in Postgres.** A row exfiltrated
  from the database without the key is opaque ciphertext.
- **Integrity + binding.** AAD ties the ciphertext to
  `(username, name)` — a row moved to a different name fails
  GCM authentication on decrypt.
- **Forward security per-secret.** Each row uses a fresh
  12-byte random nonce so the same plaintext stored twice
  produces different ciphertext.

What this doesn't get us:

- **Host-compromise resilience.** Root on the daemon host
  reads the master key (`cat /etc/containarium/secrets.key`)
  and can decrypt every secret. The operator with shell
  access, an attacker who exploits the daemon and escalates
  to root, a backup that includes `/etc/containarium/`, a
  kernel-level forensic dump — all of these expose every
  tenant's secrets.
- **Cryptographic operation auditability.** There's no
  external log of who decrypted what. Application code that
  reads many secrets in succession is indistinguishable from
  an attacker doing the same.

The fix the audit named is **envelope encryption** — the
master key sits in an external KMS that performs the
cryptographic operations on demand, never exposing the key
material itself.

## Target architecture

```
                        ┌─────────────────────────┐
                        │   External KMS          │
                        │  (GCP KMS / Vault /     │
                        │   AWS KMS / HashiCorp)  │
                        │                         │
                        │  Wrap-key (KEK) lives   │
                        │  here, never exported.  │
                        └────────────┬────────────┘
                                     │ Encrypt(DEK) → wrapped_DEK
                                     │ Decrypt(wrapped_DEK) → DEK
                                     ▼
┌──────────────────────────────────────────────────────────┐
│  Containarium daemon                                     │
│                                                          │
│  On secret write:                                        │
│    1. dek = rand(32)              # Data Encryption Key  │
│    2. ct = AES-GCM(dek, plaintext, AAD=user||name)       │
│    3. wrapped_dek = KMS.Encrypt(KEK, dek)                │
│    4. INSERT (ciphertext=ct, wrapped_key=wrapped_dek,    │
│               kek_id=<kms_key_resource_id>)              │
│    5. zero out dek in memory                             │
│                                                          │
│  On secret read:                                         │
│    1. SELECT ciphertext, wrapped_key, kek_id FROM ...    │
│    2. dek = KMS.Decrypt(kek_id, wrapped_key)             │
│    3. plaintext = AES-GCM-Open(dek, ct, AAD=user||name)  │
│    4. zero out dek                                       │
│                                                          │
│  Master key file at /etc/containarium/secrets.key:       │
│    REMOVED. Daemon authenticates to the KMS via          │
│    Workload Identity / Vault Agent / SDK creds.          │
└──────────────────────────────────────────────────────────┘
```

The KEK (Key Encryption Key) is the "master key" — it lives
in the KMS and is never exported. The DEK (Data Encryption
Key) is per-secret: generated in daemon memory, used once to
encrypt the plaintext, and immediately encrypted to the KEK
for storage. The DEK is regenerated for every write.

## What envelope encryption gets us

| Attack                                | Today | With envelope |
| ------------------------------------- | :---: | :-----------: |
| Postgres row exfiltration             | safe  | safe          |
| Tape backup of `/etc/containarium/`   | **EXPOSED** | safe    |
| Root on daemon host                   | **EXPOSED** | requires KMS access on top |
| Daemon RCE + privilege escalation     | **EXPOSED** | KMS still mediates each decrypt |
| Operator with `cat` on the keyfile    | **EXPOSED** | safe (no keyfile) |
| Per-decrypt audit trail               | none  | KMS provides one |
| Coordinated key rotation              | manual, all-or-nothing | KMS-native, per-tenant possible |

The big wins are #2-#5 (host compromise stops being a
secrets compromise) and the audit trail. The KMS becomes the
new trust root; if the KMS is compromised, secrets are
compromised, but that's a much smaller blast radius than "any
shell on the daemon host."

## Implementation outline

A multi-PR rollout, mirroring how the audit doc's other
multi-PR items broke down:

### Phase A — Interface + no-op impl
- `pkg/core/secrets/kms.go`: `KMSClient` interface with
  `Wrap(plaintextDEK) (wrappedDEK, kekID, error)` and
  `Unwrap(wrappedDEK, kekID) (plaintextDEK, error)`.
- `pkg/core/secrets/kms_inproc.go`: in-process impl using the
  existing master key — preserves current behavior. Daemon
  defaults to this impl so the rollout is zero-disruption.
- Schema migration adds `wrapped_key BYTEA` and `kek_id TEXT`
  columns to the secrets table, default empty.

### Phase B — Two-write path
- Every Set writes BOTH the old single-key ciphertext (for
  decrypt-side compatibility with rows that haven't been
  rotated) AND the new envelope-style row.
- Every Get prefers the envelope path; falls back to the
  legacy path when `wrapped_key IS NULL`.

### Phase C — GCP KMS impl
- `pkg/core/secrets/kms_gcp.go` using GCP's `cloudkms.v1` API.
- Daemon flag `--kms-key-resource=projects/.../keys/...`
  selects the active KEK.
- Workload Identity is the authentication path; no service-
  account keyfile.

### Phase D — Migration tool
- `containarium secrets migrate-to-envelope`: re-reads every
  row's ciphertext, decrypts under the master key, re-encrypts
  through the new envelope path. Idempotent — already-wrapped
  rows are skipped.

### Phase E — Master-key retirement
- Operator-driven. Once `containarium secrets verify-envelope`
  reports 100% of rows wrapped, operator deletes
  `/etc/containarium/secrets.key`. Daemon refuses to start
  without the KMS resource on the next boot. The legacy
  decrypt path is removed in a subsequent release.

### Phase F — Other KMS backends
- Vault Transit, AWS KMS, HashiCorp KMS — each is one
  KMSClient implementation. Daemon picks via the
  `--kms-backend` flag.

## Operator concerns

- **Per-decrypt latency.** A KMS call adds ~10-50ms per secret
  read. For containers reading 5-20 secrets at start time,
  that's tolerable; for hot-path lookups, the daemon should
  cache DEKs in memory with bounded TTL.
- **KMS availability.** If the KMS is unreachable, the daemon
  can't decrypt new secrets. Existing in-memory DEKs work
  until they expire. Operators should monitor KMS health the
  same way they monitor Postgres.
- **Cost.** GCP KMS pricing is per-decrypt-operation;
  Containarium-scale usage is rounding error vs the
  daemon's compute bill. Vault Transit is free with the
  operator's existing Vault.
- **Coordinated key rotation.** Rotating the KEK no longer
  requires re-encrypting every row at the daemon — only
  KMS-side rewrap is needed, and the daemon transparently
  uses whichever KEK version each row was wrapped against.

## Out of scope

- **Hardware Security Module (HSM) backing.** Most cloud KMS
  offerings already use FIPS-140 HSMs under the hood; we
  don't need a separate HSM tier.
- **Per-tenant KEK.** The first cut uses a single KEK for the
  deployment. Per-tenant KEKs are a possible future
  refinement but multiply KMS calls and complicate migration.

## References

- Audit finding **C-HIGH-6** in
  [`ZERO-TRUST-AUDIT.md`](ZERO-TRUST-AUDIT.md).
- Current implementation in `pkg/core/secrets/crypto.go`.
- Operator-facing rotation guidance in
  [`OPERATOR-SECURITY-RUNBOOK.md`](OPERATOR-SECURITY-RUNBOOK.md).
- Related: PR for Phase 4.3 documented the in-container env-
  var introspection risk — envelope encryption protects
  secrets *at rest in the daemon's storage path*; the
  tmpfs alternative protects them *at delivery to the
  container*. Both are part of the C-HIGH-6 + C-MED-4 cluster.
