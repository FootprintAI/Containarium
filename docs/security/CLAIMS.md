# Security claims and the evidence behind them

Every security statement in the README and the product docs should be backed by
code, a test, or a design note that says so. This table lists the claims the
README makes, what actually backs each one, and what is **not** true by default.
It is the place to check before repeating a claim in a deck, a questionnaire or
a README edit.

Status values:

- **Backed**: on by default and enforced in code; the evidence column says where.
- **Opt-in**: real and shipped, but off until an operator turns it on.
- **Scoped**: true for a narrower thing than the wording suggests.
- **Not verified**: no evidence was found in the pass that produced this page.
  That is not a statement that it is false; it means do not repeat it without
  checking.

Last reviewed against `main` for #2558. When you add a claim anywhere, add a row
here with a link, or word the claim so it does not need one.

## Isolation

| Claim | Status | Evidence and caveats |
| --- | --- | --- |
| Boxes run in unprivileged LXC containers, so container root is not host root. | **Scoped** | Unprivileged is the default. `enable_podman=true` makes the container privileged with an unconfined AppArmor profile, and the default authorization policy (`CONTAINARIUM_PRIVILEGED_PODMAN_POLICY=all`) lets any caller with create permission request it. Set it to `admin-only` or `disabled` on a multi-tenant backend. `internal/server/privileged_policy.go`. |
| Tenants are isolated from each other on the network. | **Not true by default** | Tenants share one bridge with no isolation keys set. Tenant-to-tenant isolation exists only where the operator has armed the eBPF enforcer **and** authored an enforce-mode policy for each tenant. [`multi-tenant-isolation.md`](multi-tenant-isolation.md) records the assessment and the default state per layer. |
| Tenants cannot reach core infrastructure (platform Postgres, metrics). | **Opt-in** | Core-infra guard (`internal/coreguard`). Since #2347 it is on unless `CONTAINARIUM_CORE_GUARD=off`; whether it is in `enforce` mode depends on the deployment. See the status table in `multi-tenant-isolation.md`. |
| Per-tenant eBPF egress policy. | **Opt-in** | `internal/server/network_policy_enforcer.go`; needs the BPF object and enforce mode. The default egress posture for tenant boxes is not defined or proven yet (#2577). |
| Denied egress is logged. | **Not verified** | Deny events feed the threat-detection rules (`internal/threatdetect`). This pass did not trace them into the audit log; do not claim "audit-logged denials" until that is checked. |
| Kubernetes boxes get no kube-apiserver token. | **Not verified** | The chart sets `automountServiceAccountToken: true` on the daemon and gateway service accounts, which they need. The box pod's own setting is created by the sandbox controller and was not checked here. |
| fail2ban per-user bans; AppArmor profiles per container. | **Not verified** | Not traced in this pass. |

## Secrets and keys

| Claim | Status | Evidence and caveats |
| --- | --- | --- |
| A model gateway keeps provider API keys out of the box. | **Opt-in** | `internal/modelgateway`, `cmd/model-gateway`. Only for boxes configured to call the gateway; a box that still receives a provider key as an environment variable holds it. [`../AGENT-MODEL-GATEWAY-DESIGN.md`](../AGENT-MODEL-GATEWAY-DESIGN.md) states the problem it closes. |
| Tenant secrets use KMS envelope encryption. | **Opt-in** | Needs Vault Transit or GCP Cloud KMS configured. [`KMS-ENVELOPE-DESIGN.md`](KMS-ENVELOPE-DESIGN.md). |
| JWTs carry `iss`/`aud`/`jti`/`tt`/`scopes`, a 32-byte minimum secret, single-use refresh tokens, jti revocation. | **Not verified** | Only the 32-byte HMAC key guidance was seen in code (`internal/auth/token.go`). The other properties were not traced here. |
| Secrets can be delivered through tmpfs files instead of environment variables. | **Opt-in** | `--delivery=file`; the environment-variable risk is in [`SECRETS-ENV-VAR-RISK.md`](SECRETS-ENV-VAR-RISK.md). |

## Audit and detection

| Claim | Status | Evidence and caveats |
| --- | --- | --- |
| The audit log is tamper-evident (SHA-256 hash chain, `audit verify`). | **Scoped** | Against an application- or database-level attacker only. Someone who can write the database can rewrite the rows and recompute every later hash. `internal/audit/hash_chain.go`. |
| The chain root can be anchored outside the database. | **Opt-in, scoped** | Two copies. A local append-only file by default (`internal/audit/anchor.go`), which a database credential does not reach; a host-root attacker could still edit both. With `CONTAINARIUM_AUDIT_ANCHOR_BUCKET` set, each anchor is also written to a GCS bucket, and `audit verify-anchor --anchor-bucket` checks the database and the local file against it (`internal/audit/anchor_gcs.go`, `anchor_verify.go`). That copy is only immutable if the bucket's retention policy is **locked**; without it the check warns and the bucket proves nothing against a host-root attacker. What it does and does not cover is in the [operator runbook](OPERATOR-SECURITY-RUNBOOK.md#what-the-bucket-check-does-and-does-not-prove). An RFC 3161 timestamp sink and key rotation are separate follow-ups of #2560. |
| Threat detection finds mining and abuse behaviour. | **Opt-in** | Needs `CONTAINARIUM_THREAT_SENTRY=1` and the eBPF object. Limits are listed in [`../architecture/continuous-threat-detection.md`](../architecture/continuous-threat-detection.md); the process guardrail rule can be evaded by a miner that stays under its CPU bar. |

## Supply chain and scanning

| Claim | Status | Evidence and caveats |
| --- | --- | --- |
| Image-registry allow-list and digest verification. | **Opt-in** | `CONTAINARIUM_REQUIRE_IMAGE_DIGEST` and the registry allow-list (`internal/server/image_digest.go`). Registry-side verification is a design note, not shipped: [`IMAGE-DIGEST-VERIFY-DESIGN.md`](IMAGE-DIGEST-VERIFY-DESIGN.md). |
| Trivy image and dependency scanning. | **Backed** (scanner), **Scoped** (coverage) | Run in CI and as a scanner module; coverage is what the scan job covers, not every image on every backend. |
| ClamAV malware scanning. | **Scoped** | A tenant-run capability: the scan runs inside a box on its owner's request and the verdict is self-reported. It is not a platform-wide control. [`TENANT-MALWARE-SCAN.md`](TENANT-MALWARE-SCAN.md), #2631. |
| `gosec`, `govulncheck`, `trivy` run in CI. | **Backed, not gating** | Present in the workflows. Making the gosec findings gating is tracked in #2564. |
| Coordinated-disclosure policy. | **Backed** | `SECURITY.md`. |

## Deployment

| Claim | Status | Evidence and caveats |
| --- | --- | --- |
| An air-gapped install is possible. | **Scoped** | The install bundle (`make build-bundle`, `offline-install.sh`) carries the packages the **installer** needs, so installing needs no internet. Running features still call out: model gateway to the provider, image pulls, scanner signature updates. |
| Release binaries are signed and have an SBOM. | **Not true yet** | Tracked in #2561. Verify downloads against `SHA256SUMS.txt`. |

## Design documents

A design note's status line must match the code. A note that says "not yet
built" for something that has shipped misleads in the other direction, so when a
note's work lands, update its header in the same change. The model gateway,
tracker broker and inbound-guardrail notes were corrected in #2558.
