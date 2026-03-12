# ISO 27001:2022 Compliance Assessment

This document assesses Containarium against ISO 27001:2022 Annex A controls, tracking what is implemented, what has gaps, and what needs organizational action beyond the codebase.

## Scope

- **Product**: Containarium — multi-tenant LXC container platform
- **Infrastructure**: GCP (Compute Engine, Cloud NAT, Cloud DNS)
- **Assessment date**: 2026-03-12
- **Standard**: ISO/IEC 27001:2022

## Legend

| Status | Meaning |
|--------|---------|
| Present | Evidence found in codebase/infrastructure |
| Partial | Some implementation, gaps remain |
| Missing | No evidence in the repository |
| N/A | Cannot be assessed from code (organizational/people controls) |

---

## A.5 — Organizational Controls

| Control | Description | Status | Evidence / Gap | Traceability |
|---------|-------------|--------|----------------|--------------|
| A.5.1 | Information security policies | Missing | No ISMS policy document | Needs: `docs/ISMS-POLICY.md` |
| A.5.2 | Information security roles | Missing | No RACI or role definitions | Needs: organizational doc |
| A.5.3 | Segregation of duties | Partial | Admin/user roles in JWT claims (`internal/auth/token.go`) | Gap: no formal SoD policy |
| A.5.7 | Threat intelligence | Missing | No threat model | Needs: STRIDE/DREAD analysis |
| A.5.8 | Info security in project management | Missing | No security requirements in issue templates | Needs: `.github/ISSUE_TEMPLATE/` with security section |
| A.5.9 | Inventory of information assets | Missing | No asset register | Needs: asset inventory doc |
| A.5.10 | Acceptable use of information | Missing | No acceptable use policy | Needs: organizational doc |
| A.5.14 | Information transfer | Partial | mTLS for gRPC (`internal/mtls/`), TLS for HTTP (`internal/hosting/caddy.go`) | Gap: no data classification policy |
| A.5.23 | Info security for cloud services | Partial | Terraform GCP config (`terraform/modules/containarium/`) | Gap: no cloud security policy doc |
| A.5.24 | Incident management planning | Missing | No incident response plan | Needs: `docs/INCIDENT-RESPONSE.md` |
| A.5.25 | Assessment of info security events | Missing | No triage criteria | Needs: event classification doc |
| A.5.28 | Collection of evidence | Partial | Traffic monitoring (`internal/traffic/collector.go`) | Gap: no forensic procedures |
| A.5.29 | Info security during disruption | Partial | Sentinel HA (`internal/sentinel/manager.go`, `docs/SENTINEL-DESIGN.md`) | Gap: no formal BCP document |
| A.5.30 | ICT readiness for business continuity | Partial | Auto-recovery ~85s, ZFS snapshots | Gap: no documented RTO/RPO targets |
| A.5.35 | Independent review of info security | Missing | No audit/review process | Needs: organizational process |
| A.5.36 | Compliance with policies/standards | Missing | No compliance tracking | This document is a start |

---

## A.6 — People Controls

| Control | Description | Status | Notes |
|---------|-------------|--------|-------|
| A.6.1 | Screening | N/A | Organizational/HR control |
| A.6.2 | Terms and conditions of employment | N/A | Organizational/HR control |
| A.6.3 | Information security awareness | N/A | Organizational/HR control |
| A.6.4 | Disciplinary process | N/A | Organizational/HR control |
| A.6.5 | Responsibilities after termination | N/A | Organizational/HR control |
| A.6.6 | Confidentiality agreements | N/A | Organizational/HR control |
| A.6.7 | Remote working | N/A | Organizational/HR control |
| A.6.8 | Information security event reporting | N/A | Organizational/HR control |

---

## A.7 — Physical Controls

| Control | Description | Status | Notes |
|---------|-------------|--------|-------|
| A.7.1–A.7.14 | Physical security perimeters, entry controls, etc. | N/A | Cloud-hosted on GCP; physical security delegated to Google (SOC 2 / ISO 27001 certified) |

---

## A.8 — Technological Controls

| Control | Description | Status | Evidence / Gap | Traceability |
|---------|-------------|--------|----------------|--------------|
| A.8.1 | User endpoint devices | N/A | Server-side platform | — |
| A.8.2 | Privileged access rights | Partial | Admin role in JWT, SSH jump `nologin` shell (`internal/container/jump_server.go`) | Gap: no MFA, no privilege escalation protections documented |
| A.8.3 | Information access restriction | Partial | JWT role-based access, container isolation (`internal/auth/middleware.go`) | Gap: only admin/user roles, no fine-grained RBAC |
| A.8.4 | Access to source code | Partial | `.gitignore` excludes secrets | Gap: no branch protection rules documented |
| A.8.5 | Secure authentication | Partial | JWT+mTLS, 30-day max expiry (`internal/auth/token.go`) | Gap: **no MFA**, tokens in browser localStorage (XSS risk) |
| A.8.6 | Capacity management | Partial | CPU/memory/disk quotas per container (`internal/container/manager.go`) | Gap: no capacity monitoring alerts |
| A.8.7 | Protection against malware | Present | ClamAV scanning with job queue (`internal/security/scanner.go`, `internal/security/store.go`) | 90-day retention, async workers |
| A.8.8 | Technical vulnerability management | Present | Dependabot for Go modules + GitHub Actions (`.github/dependabot.yml`), Trivy filesystem scan (`.github/workflows/security.yml`), govulncheck for Go-specific CVEs | — |
| A.8.9 | Configuration management | Partial | Terraform IaC (`terraform/`), `tfvars.example` pattern | Gap: no config baseline or drift detection |
| A.8.10 | Information deletion | Partial | Container cleanup on deletion, 90-day scan retention | Gap: no data retention policy document |
| A.8.11 | Data masking | Missing | No PII masking in logs or API responses | Needs: review API responses for PII |
| A.8.12 | Data leakage prevention | Partial | `.gitignore` for secrets, file-based secret storage | Gap: no DLP tooling |
| A.8.13 | Information backup | Partial | ZFS snapshots, GCP disk persistence on STOP | Gap: no documented backup schedule or restore testing |
| A.8.14 | Redundancy | Present | Sentinel HA with auto-recovery (`internal/sentinel/`, `docs/SENTINEL-DESIGN.md`) | ~85s recovery time |
| A.8.15 | Logging | Present | stdout/stderr via systemd, OpenTelemetry (`internal/metrics/otel.go`), conntrack (`internal/traffic/`), centralized audit log in PostgreSQL (`internal/audit/`) with HTTP request + event bus persistence | — |
| A.8.16 | Monitoring activities | Partial | OpenTelemetry metrics, Grafana dashboards, traffic monitoring | Gap: no SIEM integration, no alerting rules |
| A.8.17 | Clock synchronization | Missing | No NTP configuration documented | Needs: document NTP/chrony setup on VMs |
| A.8.20 | Network security | Present | GCP firewall rules (`terraform/modules/containarium/main.tf`), source IP restrictions, SSH jump architecture | Well implemented |
| A.8.21 | Security of network services | Present | mTLS for gRPC (`internal/mtls/`), auto TLS via Caddy/ACME (`internal/hosting/`), IAP support | Well implemented |
| A.8.22 | Segregation of networks | Present | Containers on Incus bridge (10.0.3.0/24), jump host architecture, GCP firewall segmentation | Well implemented |
| A.8.23 | Web filtering | Missing | No egress filtering for containers | Needs: container egress rules |
| A.8.24 | Use of cryptography | Present | TLS 1.2+, mTLS, HMAC-SHA256 JWT, SSH ed25519 keys, ACME cert management | Well implemented |
| A.8.25 | Secure development lifecycle | Present | `Makefile` with lint/test/race detection, gosec SAST in CI with SARIF upload (`.github/workflows/security.yml`) | — |
| A.8.26 | Application security requirements | Missing | No documented security requirements | Needs: security requirements spec |
| A.8.27 | Secure system architecture | Partial | Architecture docs: `SENTINEL-DESIGN.md`, `SSH-JUMP-SERVER-SETUP.md` | Gap: no formal threat model |
| A.8.28 | Secure coding | Present | Race detection (`go test -race`), golangci-lint, gosec SAST (`.github/workflows/security.yml`) | — |
| A.8.29 | Security testing | Partial | Integration/E2E tests (`test/`, `Makefile`) | Gap: no penetration testing, no fuzzing |
| A.8.30 | Outsourced development | N/A | In-house development | — |
| A.8.31 | Separation of environments | Partial | Terraform module separates dev/prod (`terraform/gce/` vs kafeido-infra) | Same binary used everywhere (acceptable) |
| A.8.32 | Change management | Partial | Git-based, GitHub releases with SHA256 checksums (`.github/workflows/release-mcp.yml`) | Gap: no formal change approval process |
| A.8.33 | Test information | Missing | No test data management policy | Needs: policy for test data handling |
| A.8.34 | Protection during audit testing | N/A | No audit testing process yet | — |

---

## Remediation Roadmap

### Priority 1 — High (required for certification)

| Item | Control | Action | Owner | Files to Create/Modify |
|------|---------|--------|-------|------------------------|
| H1 | A.5.1 | Write ISMS policy and scope | — | `docs/ISMS-POLICY.md` |
| H2 | A.5.1 | Conduct risk assessment, produce risk register | — | `docs/RISK-REGISTER.md` |
| H3 | A.8.5 | Implement MFA for admin access | — | `internal/auth/` |
| ~~H4~~ | ~~A.8.15~~ | ~~Add centralized, tamper-proof audit logging~~ | Done | `internal/audit/` (store, HTTP middleware, event subscriber) |
| H5 | A.5.24 | Write incident response plan | — | `docs/INCIDENT-RESPONSE.md` |
| ~~H6~~ | ~~A.8.8~~ | ~~Add automated dependency scanning to CI~~ | Done | `.github/dependabot.yml`, `.github/workflows/security.yml` (Trivy + govulncheck) |
| ~~H7~~ | ~~A.8.25~~ | ~~Add SAST to CI pipeline~~ | Done | `.github/workflows/security.yml` (gosec with SARIF upload) |

### Priority 2 — Medium

| Item | Control | Action | Owner | Files to Create/Modify |
|------|---------|--------|-------|------------------------|
| M1 | A.8.5 | Move token storage from localStorage to httpOnly cookies | — | `web-ui/`, `internal/gateway/` |
| M2 | A.8.23 | Implement container egress filtering | — | `internal/network/`, Incus firewall rules |
| M3 | A.8.16 | Integrate with SIEM / set up alerting | — | Infrastructure config |
| M4 | A.5.29 | Document BCP with RTO/RPO targets | — | `docs/BUSINESS-CONTINUITY.md` |
| M5 | A.8.13 | Document backup schedule, test restore procedures | — | `docs/BACKUP-RESTORE.md` |
| M6 | A.8.9 | Implement infrastructure drift detection | — | Terraform Cloud or CI drift checks |
| M7 | A.8.32 | Document change approval process | — | `docs/CHANGE-MANAGEMENT.md` |
| M8 | — | Fix default PostgreSQL password (`changeme`) | — | `deployments/docker-compose.yml` |

### Priority 3 — Low

| Item | Control | Action | Owner | Files to Create/Modify |
|------|---------|--------|-------|------------------------|
| L1 | A.8.4 | Document branch protection rules | — | `.github/` settings or doc |
| L2 | A.8.17 | Document NTP/chrony configuration on VMs | — | `docs/DEPLOYMENT-GUIDE.md` |
| L3 | A.8.11 | Review API responses for PII leakage | — | `internal/server/`, `internal/gateway/` |
| L4 | A.8.29 | Add fuzz testing for parsers/input handlers | — | `test/fuzz/` |
| L5 | A.5.7 | Create threat model (STRIDE) | — | `docs/THREAT-MODEL.md` |

---

## What's Already Well Implemented

These controls are strong evidence toward Annex A compliance:

| Area | Implementation | Key Files |
|------|---------------|-----------|
| Container isolation | Unprivileged LXC by default | `internal/container/manager.go` |
| Transport encryption | mTLS (gRPC) + auto TLS (Caddy/ACME) | `internal/mtls/`, `internal/hosting/caddy.go` |
| Network architecture | SSH jump host, sentinel HA | `internal/container/jump_server.go`, `internal/sentinel/` |
| Malware scanning | ClamAV with async job queue | `internal/security/scanner.go` |
| Infrastructure as Code | Terraform with parameterized modules | `terraform/modules/containarium/` |
| Secret hygiene | `.gitignore` excludes keys/state/env files | `.gitignore` |
| Token expiry | Max 30-day enforcement | `internal/auth/token.go` |
| Network segmentation | GCP firewall + Incus bridge isolation | `terraform/modules/containarium/main.tf` |
| Build integrity | SHA256 checksums on releases | `.github/workflows/release-mcp.yml` |
| HA / Resilience | Sentinel auto-recovery (~85s) | `internal/sentinel/manager.go`, `docs/SENTINEL-DESIGN.md` |
| Resource limits | CPU/memory/disk quotas per container | `internal/container/manager.go` |

---

## Important Note

ISO 27001 is an **organizational certification** (ISMS), not a product certification. Even with all code-level controls addressed, the organization must establish:

1. **ISMS scope and policy** (clause 4–5)
2. **Risk assessment methodology** (clause 6.1.2)
3. **Statement of Applicability** (clause 6.1.3)
4. **Internal audit program** (clause 9.2)
5. **Management review** (clause 9.3)
6. **Continual improvement process** (clause 10)

This document covers Annex A (controls). The management system clauses (4–10) require organizational processes beyond the codebase.
