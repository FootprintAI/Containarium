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

Minting a token with the required scope: create an admin token whose scope list
includes network-policy:write alongside containers:write (legacy unrestricted
admin credentials keep working). A token minted before this change with an
explicit scope list that omits network-policy:write loses every policy write —
Set, Patch, Delete and the signature mutations — on upgrade; re-mint it before
relying on those writes.

Tests cover direction, exact preservation including egress_mode/deny rules,
revision conflicts, concurrent previews, all-or-none absent-row rollback, signed
JWT REST scope checks, generated gRPC/REST and actual MCP stdio calls. PostgreSQL
tests use TEST_TENANT_PG_DSN pointing only to a disposable test database, create a
unique schema, and drop that schema afterward. No production Box/ACL was changed.
