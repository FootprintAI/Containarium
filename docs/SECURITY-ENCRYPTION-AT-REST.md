# At-Rest Encryption Posture

This document is the canonical answer to "is Containarium data encrypted
at rest?" Use it when filling out vendor security questionnaires or
explaining the encryption story to a customer.

The TL;DR: **on GCP, yes by default; on bare-metal, only if the operator
configured disk encryption themselves**. The platform does not encrypt
container data itself — protection comes from the underlying disk layer
(GCP PD encryption, or operator-configured LUKS/ZFS native on bare-metal).

## What IS encrypted at rest

| Surface | Encrypted? | Key custody | Notes |
|---|---|---|---|
| GCP persistent disks (sentinel boot, backend boot, backend data PD) | Yes | Google-managed (default) or **CMEK** if `kms_key_self_link` is set in the terraform module | See "Customer-managed keys (CMEK)" below |
| GCS bucket for terraform state | Yes | Google-managed (default); CMEK opt-in via `encryption_key` on the `backend "gcs"` block | Example wiring in `terraform/gce/backend-prod.tf.example` |
| JWT signing secret | At-rest on the backend's PD only; in-process plaintext | File at `/etc/containarium/jwt.secret`, mode `0600` | Protected only by the PD encryption layer |
| Container rootfs and data | At-rest on the backend's data PD only | Inherits the PD's encryption | **No per-container key**: container data is plaintext to any privileged process on the backend |
| mTLS / ACME private keys | At-rest on the backend's PD only | File-system permissions | Same caveat as JWT secret |

## What is NOT encrypted at rest

- **Bare-metal peers** (e.g. the `fts-5900x` and `fts-13700k` GPU
  nodes). These hosts have no PD layer between Containarium and the
  physical disks. If the operator did not configure LUKS, dm-crypt,
  or ZFS native encryption on the underlying storage themselves, the
  data is plaintext on disk. See "Self-hoster options" below.
- **ZFS pool on the backend** (`incus-pool/containers/...`) — by
  default. The pool is created without `encryption=on` unless the
  operator opts in by setting `zfs_encryption_keyfile` (terraform)
  or `--zfs-encryption-keyfile` (bare-metal). See "Self-hoster
  options" below for the opt-in path.
- **Container memory, swap, and tmpfs** — at-rest encryption protects
  cold disk; live memory and swap are not in scope here. Standard
  Linux memory hardening (kernel ASLR, etc.) applies.
- **Backups produced by `gcloud compute snapshots`** — these inherit
  the source disk's encryption posture. If the source uses CMEK, the
  snapshot uses CMEK. If not, Google-managed.

## Customer-managed keys (CMEK)

The terraform module accepts a `kms_key_self_link` variable that wires
a customer-managed KMS key through to every disk it creates. Default
empty string = no behavior change (Google-managed keys, the GCP
default).

Example wiring in a consumer module call:

```hcl
module "containarium" {
  source = "../modules/containarium"

  kms_key_self_link = "projects/my-project/locations/us-central1/keyRings/my-ring/cryptoKeys/my-key"
  # ... other variables ...
}
```

Coverage:

- Backend boot disk
- Backend data PD (where ZFS lives)
- Sentinel boot disk
- (If `use_spot_instance = false`) non-spot instance boot disk

The compute service account on the project must have
`roles/cloudkms.cryptoKeyEncrypterDecrypter` on the named key before
`terraform apply` succeeds; otherwise disk creation fails with a
permission error.

**Rotation**: not automated. Triggering a key rotation on the
referenced KMS key version invalidates the existing disks — replace
the disks (`terraform apply -replace=...`) to re-encrypt under the new
version.

**Code path**: `terraform/modules/containarium/variables.tf` →
`spot-instance.tf` / `sentinel.tf` / `main.tf`. Wired via
`google_compute_instance.boot_disk.kms_key_self_link` and
`google_compute_disk.disk_encryption_key` blocks.

## Per-tenant keys (cloud-only, planned)

Per-tenant keys — every org's container data encrypted with a distinct
KMS key, so a co-tenant on the same host can't read foreign data even
with host access — is a **cloud-product feature**, not OSS. The design
lives in the Containarium-cloud repo's PRD set:

- `prd/cloud/at-rest-encryption.md` — Phase 2 plan (per-org ZFS native
  encryption, keys held in GCP KMS, daemon mounts datasets on demand).
- Depends on the multi-tenancy PRD landing first
  (`prd/cloud/multi-tenancy.md`), since per-tenant keys are scoped by
  `org_id` which doesn't exist as a first-class entity in the OSS
  daemon.

If you're self-hosting and want per-container encryption today, see
"Self-hoster options" below.

## Self-hoster options

If you run Containarium on bare-metal or want stronger isolation than
the GCP default, the OSS install scripts now have first-class
support for ZFS native encryption on the data pool. Other layers
remain operator concerns:

- **LUKS / dm-crypt** on the data disk before ZFS is created on top.
  Standard Linux distro tooling; Containarium doesn't care about the
  layer beneath the ZFS pool.
- **ZFS native encryption** on the pool — supported by the install
  scripts via a keyfile flag (see next section).
- **Hardware encryption** (TCG Opal SEDs, BitLocker on Windows) —
  transparent to Containarium.

### Pool-level ZFS native encryption (operator-managed keyfile)

Both install paths accept an opt-in flag that creates the `incus-pool`
(GCE) or `incus-local` (bare-metal) data pool with `encryption=on`,
`keyformat=raw`, and `keylocation=file://<path>`. Every container
dataset inherits encryption from the parent pool. The daemon doesn't
need to know — the kernel decrypts transparently as long as the key
is loaded.

**GCE (terraform module):**

```hcl
module "containarium" {
  source                  = "../modules/containarium"
  zfs_encryption_keyfile  = "/etc/containarium/zfs.key"
  # ... other variables ...
}
```

**Bare-metal:**

```bash
sudo ./scripts/setup-gpu-host.sh \
  --data-disk nvme0n1 \
  --zfs-encryption-keyfile /etc/containarium/zfs.key
```

On first boot the install script generates a random 32-byte keyfile
(`dd if=/dev/urandom bs=32 count=1`, chmod `0400`). On subsequent
boots ZFS reads the keyfile via `keylocation=file://`, so the pool
mounts automatically with no operator intervention.

**Threat model and limits.** The keyfile lives on the **boot disk**;
the encrypted pool lives on the **data disk**. This protects:

- Disk replacement / RMA — pulling the data disk and reading it on
  another host yields ciphertext.
- Cloud snapshot exfiltration of *only* the data PD.
- Lost / stolen bare-metal data disks.

It does **not** protect against:

- Full-VM exfiltration (attacker gets both boot and data disks).
- A privileged process on the running host — the kernel sees plaintext.
- Memory / swap (out of scope for at-rest encryption).

Pair with GCP CMEK on the boot disk (the `kms_key_self_link`
variable) for defense in depth: an attacker now needs the GCP key
to read the boot disk *and* the keyfile to decrypt the data disk.

**Operator responsibilities — read before enabling:**

- **Back the keyfile up off-host.** Losing it makes the pool
  unrecoverable; ZFS does not store the key anywhere else.
- **Restrict access** to the keyfile (`chmod 0400`, root-owned;
  the install script enforces this on creation but won't fix it
  later).
- **Rotate** by destroying + recreating the pool (in-place rekeying
  via `zfs change-key` is supported but operationally tricky;
  out-of-scope here).
- **Don't enable on an existing pool.** ZFS native encryption is a
  pool-creation-time setting; flipping it later requires destroying
  the pool. The install scripts skip the encryption block when the
  pool already exists.

## Answering vendor security questionnaires

| Question | Answer |
|---|---|
| Is customer data encrypted at rest? | Yes when deployed on GCP (default Google-managed keys on persistent disks). On bare-metal, depends on operator-configured disk encryption. |
| Can customers bring their own keys (BYOK)? | On GCP: yes via CMEK (`kms_key_self_link` in the terraform module). Hosted/cloud product: yes via dashboard (Q3 2026). |
| Are keys customer-controlled or vendor-controlled? | OSS: customer-controlled (you own the KMS key, you set the variable). Hosted/cloud product: vendor-controlled by default (cloud-managed in GCP KMS), customer-controlled BYOK on enterprise tier (planned Q4 2026). |
| Per-tenant encryption keys? | Not in OSS (single-tenant). Hosted/cloud product: planned for Q4 2026 (`prd/cloud/at-rest-encryption.md`). |
| Encryption algorithm? | AES-256 via GCP KMS (CMEK and Google-managed). XTS-AES-256 if using ZFS native encryption. |
| Key rotation? | Manual (re-`terraform apply -replace`). Automatic rotation is a cloud-product feature, not in OSS. |
| What about backups? | GCP disk snapshots inherit the source disk's encryption. If you use CMEK on the live disks, snapshots use CMEK. |
| Are memory or swap encrypted? | No. At-rest scope is cold disk only. |
| What's not encrypted? | Bare-metal peer disks (unless operator opts into `--zfs-encryption-keyfile`); ZFS pool itself by default (operator opt-in via `zfs_encryption_keyfile` terraform variable or the bare-metal flag). |

## References

- `terraform/modules/containarium/variables.tf` — the
  `kms_key_self_link` variable.
- `Containarium-cloud/prd/cloud/at-rest-encryption.md` — full cloud-side
  plan.
- `Containarium-cloud/prd/cloud/multi-tenancy.md` — prerequisite for
  per-tenant encryption.
- `docs/ISO27001-COMPLIANCE.md` — broader cryptography control (A.8.24)
  covering in-transit + at-rest + key management.
- `docs/SECURITY-CHECKLIST.md` — public-repo hardening checklist.
