# Atomic cross-Tenant ingress edits

The existing NetworkPolicy.allow_from_tenants is the source of truth. Source A
may initiate toward B when B lists A. This change adds an ingress-only mutation
contract; it does not add Tenant CRUD, a network stack, table migrations or routes.

GET /v1/network-policies/{tenant} now includes a SHA256 revision of the entire
current protobuf policy. POST /v1/network-policies/tenant-access takes 1-32
destination changes, each with addSources/removeSources and expectedRevision
(the complete observed revision or absent). Self/duplicate/contradictory sources
and invalid native keys are rejected. Two destination changes grant/revoke both
directions in one transaction. Any revision conflict aborts the entire batch.

PostgreSQL locks destinations in sorted order and updates only allow_from_tenants
and updated_at. Egress CIDRs/domains, mode, egress_mode, metadata, source, preset
and independently managed deny rules are preserved. The in-memory implementation
has matching all-or-none behavior under its existing mutex. A missing policy may be created only by a grant; an absent-policy revoke is
rejected before insertion, and CLI revoke previews omit absent destinations.
A missing policy created by a grant starts with the existing unspecified/log-only defaults. Existing full-policy
writers retain their own replacement semantics; new previews cannot overwrite
an intervening edit silently, and no automatic snapshot rollback is performed.

Admin plus network-policy:write is required. Existing full-policy writes and
deny/signature writes also honor that scope, closing alternate scoped-token
write paths; legacy admin credentials without a scopes restriction retain the
existing convention. Read scope remains network-policy:read.

CLI: network-policy access preview SOURCE DEST [--both] [--revoke] writes a
reviewable JSON plan. access apply FILE --confirm submits only that plan.
Host MCP adds list_network_policies, get_network_policy and patch_tenant_access.
Generated gRPC exposes PatchTenantAccess. All use the same fixed Provider
contract. Unknown outcomes must be inspected before a fresh preview, not replayed.

GetNetworkTenantCapabilities retains contract native-network-tenant/v1
(incus.NativeTenantContractID). A's shared create, B's atomic support and
current policy-write permission are reported independently. B support requires
local wiring and a durable store. Grants require fresh supported ENFORCE Guard;
revokes can be recorded while degraded. The typed TenantAccessApplicationState
reports PENDING, GUARD_VERIFIED or DEGRADED. A commit, ACL reconciliation and a
TCP connectivity test are distinct; connectivityTested is always false. Do not
infer immediate enforcement of a degraded revocation.

Scopes are exact membership checks. Use the admin role plus:

| Operation | Scopes |
| --- | --- |
| Explicit create, including capability preflight | containers:read, containers:write |
| Policy preview/read | network-policy:read |
| Reviewed policy-only apply | network-policy:write |
| Complete create and preview/apply workflow | containers:read, containers:write, network-policy:read, network-policy:write |

On the daemon host, mint the complete workflow credential with the existing
protected signing-secret file (substitute your configured path):

```bash
containarium token generate --username operator --roles admin --expiry 2h \
  --secret-file /path/to/jwt.secret \
  --scopes containers:read,containers:write,network-policy:read,network-policy:write
```

Do not put the signing secret on the command line. Legacy unrestricted admin
credentials retain their existing behavior. Explicit-scope tokens that omit
network-policy:write lose Set, Patch, Delete and signature mutations on upgrade;
re-mint them before relying on those writes. The cloud adopt credential must
also carry admin plus containers:write because cloud attribution affects
network identity; tenant credentials cannot re-attribute their own boxes.

The network-policy access subcommands use the same HTTP --server address as
the rest of network-policy; --http is not required.

Tests cover direction, exact preservation including egress_mode/deny rules,
revision conflicts, concurrent previews, all-or-none absent-row rollback, signed
JWT REST scope checks, generated gRPC/REST and actual MCP stdio calls. PostgreSQL
tests use the shared CONTAINARIUM_TEST_DSN (the store-integration lane provides it;
TestMain scopes every package process to its own schema), still create a
unique schema, and drop that schema afterward. No production Box/ACL was changed.
