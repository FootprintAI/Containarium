# Native network Tenant creation

This change extends the guarded local Linux LXC create path with an explicit
network security-domain identifier. It does not add Tenant CRUD, user/account
management, a Web UI or another network stack. Existing
NetworkPolicy.allow_from_tenants and its storage/enforcement are unchanged.

## API and transport contract

CreateContainerRequest.network_tenant is field 30. It is independent of the
existing encryption tenant_id (25) and dry_run (29). Container.network_tenant
(31) and typed NetworkTenantSource network_tenant_source (32) are read from
current Provider state; Container.tool_access (30) is unchanged.

| Surface | Create | Query |
| --- | --- | --- |
| CLI | create --network-tenant <network-key>, daemon mode only | list/get --format json; get table includes identity/source |
| gRPC | CreateContainerRequest.network_tenant | Container fields from ListContainers/GetContainer |
| REST | POST /v1/containers with networkTenant | GET /v1/containers and /v1/containers/{username} |
| Host MCP | create_container.network_tenant | list_containers/get_container |

Native membership resolves current user.containarium.tenant first, then the
official cloud_org_id attribution, then the instance-name fallback. The source
is a protobuf enum: NATIVE, CLOUD_ORG_ID, NAME or UNSPECIFIED (with the
NETWORK_TENANT_SOURCE_ prefix). A generic labels.tenant is not native config.
The routing/SSH username is retained independently. VMs do not advertise this
local LXC membership contract. Pending async responses do not echo intent as
observed membership; poll the actual state.

## Authorization and supported placement

The daemon enforces containers:write and normal ownership authorization.
Explicit network_tenant requires an administrator. Generic tenant/native config
labels are rejected; non-admin cloud_org_id attribution is denied both at create
and at the existing post-create attribution endpoint. Conflicting cloud/native
inputs are rejected.

Non-admin new local Linux LXC creates with an omitted field use reserved
account:<username> membership. This intentional security compatibility change
prevents a username matching an administrator-created network from joining it.
An admin cannot explicitly allocate account: through this new parameter. Existing
Boxes are never changed. Recreating a non-admin Box uses the new account key;
policies referring to its former name-based key are not rewritten automatically
and require operator review. Admin omitted-field creation retains the legacy
cloud/name resolver and existing optional Guard behavior. Non-admin VM or peer-placement requests through the local LXC server are also
rejected, rather than allowing an omitted option to bypass account scoping.
Unmodified K8s-only omitted-field requests retain their separate runtime path. No network boundary is
derived from a display name, encryption tenant_id or arbitrary user label.

Explicit VM/Windows, K8s/operator, backend, pool and region placement requests are
rejected before allocation/forwarding. Direct local CLI mode cannot honor the
daemon's authorization and required Guard hook, and rejects --network-tenant
before any --force deletion. No backend silently drops the field.

## Birth lifecycle and failure handling

1. Validate explicit identity and authority before storage/placement side effects.
2. Persist the native key in the initial Incus create config. Defer requested
   boot.autostart until required attachment succeeds.
3. Invoke PrepareNetworkTenant with that identical key. It requires ENFORCE,
   supported nftables/NIC ACLs and a readable policy source. Compute the existing
   Tenant ACL and attach it with default-drop ingress before the first Start.
4. Only after attachment succeeds, restore requested autostart and call Start.
5. Guard/autostart failure never starts the instance. Attempt deletion once. If
   deletion fails, retain both errors and identify the stopped resource requiring
   inspection before retry. Do not claim cleanup succeeded or force-recreate it.

The daemon also checks current Guard readiness for explicit/automatic-account
preflight, so create --force does not delete an old Box for a known-unavailable
native path. A later synchronous attachment still fails closed if readiness
changes. ACL attachment is not a TCP/listener/application reachability test.

## Capability and older clients/servers

Authenticated admin plus containers:read may query
GET /v1/network-tenants/capabilities, gRPC GetNetworkTenantCapabilities,
CLI network-tenant capabilities, or MCP network_tenant_capabilities.

The response uses contract boxweave.tenant-network/v1 and backendScope local-lxc:
nativeMembershipRead identifies local read support; sharedTenantCreate requires
a local LXC create backend, durable policy source, fresh supported enforced Guard
and containers:write authorization. A pass older than 180 seconds or more than
30 seconds into the future is not accepted.

atomicTenantAccess and networkPolicyWrite are always false in this change.
They describe B's revision-checked ingress-only editing contract, which is not
implemented here. Existing full-policy methods do not imply that capability.
BoxWeave can enable A independently without enabling B or broad policy writes.

Updated CLI/typed clients/Host MCP perform this authenticated capability check
before an explicit create (and before CLI force preflight). An old gRPC daemon
could otherwise ignore the additive field and create an unshared Box. Missing,
unknown or unready capability fails before the write. Omitted requests require
no new handshake and keep old-server compatibility. External gRPC consumers must
perform the same capability check before relying on the new field; additive
protobuf compatibility alone cannot make an old server enforce new semantics.

## Validation and remaining limits

All validation ran as an ordinary user in an isolated development environment.
No deployed Provider, existing Box, production ACL, host configuration or network
route was changed. Tests use fake Incus/Kubernetes backends, an isolated HTTP
server, in-process gRPC and an actual MCP stdio subprocess.

The lifecycle regression composes the real container Manager with the real
Tenant Guard reconciler over fake Incus, and asserts native config and the
computed default-drop NIC ACL are present at the first Start. Attachment and
cleanup failures cover the same composition. Independent tests cover auth,
unsupported placement, namespace bypass, attributed-label bypass, observed
list/get identity, request reuse, legacy protobuf fields and old-server no-write.

Reproduce from a checkout of this change:

```bash
export BUF=/absolute/path/to/pinned/buf
make proto
make proto-lint
make proto-breaking PROTO_AGAINST='.git#ref=df7e8a8cef3c1b90ac943a3fd610048a3a638fa3'
go test -p 2 ./pkg/core/container ./pkg/core/incus ./pkg/core/box/lxc \
  ./pkg/core/box/k8s ./internal/tenantguard ./internal/server \
  ./internal/client ./internal/cmd ./internal/mcp ./internal/auth -count=1
```

Actual final command outputs and artifact hashes are delivered with the review
bundle. No real Incus lifecycle, inter-Box TCP path, external LAN reachability
or production upgrade is claimed. Existing Box reassignment is not added.
Stale Guard/durable-store failures deliberately prevent new shared creation.
Non-admin account normalization requires supported enforced Guard even when the
caller omits the field; operators must review this change before upgrading.
