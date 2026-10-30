# Native network Tenant creation

This feature extends the guarded local Linux LXC create path with an explicit
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
NETWORK_TENANT_SOURCE_ prefix); the UNSPECIFIED zero value is reported as
empty by the typed clients. A generic labels.tenant is not native config.
The routing/SSH username is retained independently. VMs do not advertise this
local LXC membership contract. Pending async responses do not echo intent as
observed membership; poll the actual state.

## Authorization and supported placement

The daemon enforces containers:write and normal ownership authorization.
Explicit network_tenant requires an administrator. Generic tenant/native config
labels are rejected; non-admin cloud_org_id attribution is denied both at create
and at the existing post-create attribution endpoint (which also requires the
admin role: cloud_org_id feeds tenant resolution, so the control plane's adopt
token must carry it, and a tenant can never re-attribute its own box).
Conflicting cloud/native inputs are rejected.

Whether a non-admin create that names no network Tenant is automatically
tenanted is the operator's choice, via `CONTAINARIUM_NATIVE_ACCOUNT_TENANCY`:

- Unset (the default): the omitted-field create takes the legacy un-tenanted
  path — no tenancy precondition can block it, on any host state.
- Set: the create is placed in the reserved `account:<username>` namespace, so
  choosing a username cannot join an administrator-created shared network. A
  non-admin may never name a Tenant (not even an `account:` key). The tenancy
  still refuses VM/Windows and resolved remote placements explicitly, and region
  remains the accepted no-op hint it is on a standalone daemon.

A non-admin create that resolves to a remote peer (via pool/backend) is refused
with a clear error while account tenancy is armed; it is never silently
downgraded to an un-tenanted box on the peer. An admin cannot explicitly
allocate `account:` through this parameter. Existing Boxes are never relabeled.
Guard ACLs, membership readback and eBPF tenant IDs retain the complete
`account:<user>` key, distinct from an administrator's `<user>` shared domain.
Ingress policies and source lists use these exact identities. For egress-only
upgrade compatibility, an account without an explicit egress policy inherits
its bare user's stored policy, including ENFORCE, metadata and deny settings,
under its own tenant ID. An account record containing only ingress edits keeps
that inheritance. An explicit account egress policy overrides it; ingress
permissions are never inherited from the shared domain. Existing instances and
stored policies are not rewritten.
Admin omitted-field creation retains the legacy cloud/name resolver and existing
optional Guard behavior. No network boundary is derived from a display name,
encryption tenant_id or arbitrary user label.

Explicit VM/Windows, K8s and resolved remote placement requests with a named
Tenant are rejected before allocation/forwarding. Pool resolution runs first;
an explicit local backend or pool resolving locally remains supported. Direct local CLI mode cannot
honor the daemon's authorization and required Guard hook, and rejects
--network-tenant before any --force deletion. No backend silently drops the
field.

## Birth lifecycle and failure handling

1. Validate explicit identity and authority before storage/placement side effects.
2. Persist the native key in the initial Incus create config. Defer requested
   boot.autostart until required attachment succeeds.
3. Invoke PrepareNetworkTenant with that identical key. It requires ENFORCE, supported
   nftables/NIC ACLs and a readable policy source. Compute the existing Tenant
   ACL and attach it with default-drop ingress before the first Start.
4. Only after attachment succeeds, restore requested autostart and call Start.
5. Guard/autostart failure never starts the instance. Attempt deletion once. If
   deletion fails, retain both errors and identify the stopped resource requiring
   inspection before retry. Do not claim cleanup succeeded or force-recreate it.

The daemon also checks current Guard readiness before an explicitly tenanted
create, so create --force does not delete an old Box for a known-unavailable
native path. Creation readiness checks mode, driver and pass freshness; another box
with a failed NIC attachment does not remove host capability. A stale gather
or unsupported host still refuses creation. The later synchronous attachment
fails closed if readiness changes. ACL attachment is not a TCP/listener/application reachability test.

## Capability and older clients/servers

Authenticated admin plus containers:read may query
GET /v1/network-tenants/capabilities, gRPC GetNetworkTenantCapabilities,
CLI network-tenant capabilities, or MCP network_tenant_capabilities.

The response contract is `native-network-tenant/v1`
(incus.NativeTenantContractID) with backendScope `local-lxc`
(incus.NativeTenantBackendScope): nativeMembershipRead identifies local read
support; sharedTenantCreate requires a local LXC create backend, durable policy
source, fresh supported enforced Guard and containers:write authorization. A
pass older than 180 seconds or more than 30 seconds into the future is not
accepted.

atomicTenantAccess reports configured local ingress-only transaction support with
a durable policy source; networkPolicyWrite additionally requires the explicit
network-policy:write scope. These are independent of shared creation readiness.
Grants require fresh enforced Guard; revokes can be stored while Guard is degraded,
with enforcement reported separately. See [Tenant access](TENANT-ACCESS.md).

A client may rely on `atomicTenantAccess` without implying shared-creation
readiness or broad policy writes, and the other way round.

Updated CLI/typed clients/Host MCP perform this authenticated capability check
before an explicit create (and before CLI force preflight). An old gRPC daemon
could otherwise ignore the additive field and create an unshared Box. Missing,
unknown or unready capability fails before the write. Omitted requests require
no new handshake and keep old-server compatibility. External gRPC consumers must
perform the same capability check before relying on the new field; additive
protobuf compatibility alone cannot make an old server enforce new semantics.

## Scope and remaining limits

Tests use fake Incus/Kubernetes backends, an isolated HTTP server, in-process
gRPC and an actual MCP stdio subprocess. The lifecycle regression composes the
real container Manager with the real Tenant Guard reconciler over fake Incus,
and asserts native config and the computed default-drop NIC ACL are present at
the first Start. Attachment and cleanup failures cover the same composition.
Independent tests cover auth, unsupported placement, namespace bypass,
attributed-label bypass, observed list/get identity, request reuse, legacy
protobuf fields and old-server no-write.

Existing Box reassignment is not added. Stale Guard/durable-store failures
deliberately prevent new shared creation.
