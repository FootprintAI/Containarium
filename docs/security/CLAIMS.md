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
- **Design only**: a design note specifies it; no code or test in this
  repository enforces it. Do not state it as shipped.
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
| Per-tenant eBPF egress policy. | **Opt-in** | `internal/server/network_policy_enforcer.go`; needs the BPF object and enforce mode. The default posture is staged default-deny (#2577): a tenant with no stored policy now runs a default allow-list in `log_only` (observe-only, nothing is dropped), and `enforce` is armed per tenant later. Do not claim "default-deny egress" until the CI proof from stage 4 exists. |
| Denied egress is audit-logged. | **Opt-in, scoped** | Every deny event the enforcer receives is written to the audit log as `network_policy.deny_dropped` or `network_policy.deny_logged` (observe-only), with `network_policy.signature_match` and `network_policy.virtual_patch` for the other reasons (`denyAuditEntry` in `internal/server/network_policy_enforcer.go`). Covered by `TestOnDenyEvent_FollowsProgramVerdict` and `TestDenyAuditEntry_SignatureRecordsVerdict` (`internal/server/network_policy_deny_verdict_test.go`), which check the action, resource and recorded verdict of the audit entry. Caveats: only for tenants whose eBPF enforcer is armed (see the previous row); the write is skipped when the enforcer has no audit store and a failed write is logged, not retried; no test drives the write into a real audit store. Deny events also feed `internal/threatdetect`. |
| Kubernetes boxes get no kube-apiserver token. | **Design only** | The design specifies `automountServiceAccountToken: false` for the box pod ([`../K8S-AGENT-BOX-RUNTIME-DESIGN.md`](../K8S-AGENT-BOX-RUNTIME-DESIGN.md)). Nothing in this repository sets or tests it on the box pod: the pod is created by the sandbox controller, outside this tree. The chart sets `automountServiceAccountToken: true` on the daemon and gateway service accounts, which they need (`charts/containarium-k8s/templates/serviceaccount.yaml`). Do not state it as a shipped property of the product. |
| Kubernetes boxes get a default-deny NetworkPolicy. | **Scoped** | The reconciler creates a per-tenant NetworkPolicy; its ingress and DNS-egress shape is pinned by `TestNetworkPolicyIngressRestrictedToGateway`, `TestNetworkPolicyEgressDNSRestrictedToClusterDNS` and `TestNetworkPolicySelectorAndPolicyTypesUnchanged` (`pkg/core/box/k8s/networkpolicy_test.go`), and a removed tenant policy reverts to the floor, never to allow-all (`internal/server/k8s_netpolicy_reconciler.go`, `TestK8sNetPolicyReconcile_RemovedPolicyRevertsToTheFloor`). A NetworkPolicy only takes effect if the cluster's CNI enforces it. The kind end-to-end test is `TestE2E_NetworkPolicyIsolation` (`pkg/core/box/k8s/e2e_netpol_test.go`, `k8s` build tag). |
| SSH session audit logs per user. | **Not verified** | The sentinel-to-backend audit ingest is a proposal ([`../architecture/sentinel-ssh-session-audit-ingest.md`](../architecture/sentinel-ssh-session-audit-ingest.md), status "proposed"). The Kubernetes backend records control-plane API audit but not in-box SSH sessions (#1189). Do not repeat this claim without checking what the sentinel records today. |
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
| The chain root can be anchored outside the database. | **Opt-in, scoped** | Two copies. A local append-only file by default (`internal/audit/anchor.go`), which a database credential does not reach; a host-root attacker could still edit both. With `CONTAINARIUM_AUDIT_ANCHOR_BUCKET` set, each anchor is also written to a GCS bucket, and `audit verify-anchor --anchor-bucket` checks every bucket checkpoint against the database and the local file (checkpoints only the local file holds are still compared with the database, but the bucket does not vouch for them) (`internal/audit/anchor_gcs.go`, `anchor_verify.go`). That copy is only immutable if the bucket's retention policy is **locked**; without it the check warns and the bucket proves nothing against a host-root attacker. What it does and does not cover is in the [operator runbook](OPERATOR-SECURITY-RUNBOOK.md#what-the-bucket-check-does-and-does-not-prove). After a retention purge of the oldest rows (#2878) verification starts from a stored chain base, which records where it starts, not why the earlier rows are gone; see the runbook. With `CONTAINARIUM_AUDIT_ANCHOR_TSA_URL` and `CONTAINARIUM_AUDIT_ANCHOR_TSA_TRUST_BUNDLE` set, each anchor is also stamped by an operator-chosen RFC 3161 timestamp authority, and `audit verify-anchor --anchor-tsa-trust-bundle` checks every stored token against the bundle and the local file (`internal/audit/anchor_tsa.go`, `anchor_tsa_verify.go`). The tokens catch an edited local record but are stored on the host, so their deletion is only warned about; no revocation check is made ([runbook](OPERATOR-SECURITY-RUNBOOK.md#what-a-tsa-timestamp-does-and-does-not-prove)). Anchors hold chain hashes, not signatures, so guardrail attestation key rotation and revocation (#2729) do not affect them. |
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
