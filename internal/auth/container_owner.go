package auth

import (
	"context"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Phase 1.4 follow-up — container-name → owner derivation
// for handlers whose authz key is a container name (not a
// username).
//
// Tenant container names follow the convention
//
//	<username>-container
//
// established by ContainerServer.CreateContainer
// (`req.Username + "-container"`). The convention is enforced
// at create time and stable across the codebase. Several RPC
// handlers (TrafficServer.*, security_server.ClamAV-tenant
// reads) take `container_name` rather than `username`, so we
// can't call AuthorizeTenant directly — we need to derive the
// owner first.
//
// System containers (core services like Caddy, VictoriaMetrics)
// don't follow the convention. Calls naming a system container
// from a non-admin context return PermissionDenied — those are
// operator-only.

const containerSuffix = "-container"

// OwnerFromContainerName extracts the tenant username from a
// container name that follows the `<username>-container`
// convention. Returns ("", false) for system containers or
// any name without the suffix.
//
// Trivial enough that it doesn't need a Store dependency, and
// avoids a DB round-trip on every traffic-history poll.
func OwnerFromContainerName(containerName string) (username string, ok bool) {
	name := strings.TrimSpace(containerName)
	if name == "" {
		return "", false
	}
	if !strings.HasSuffix(name, containerSuffix) {
		return "", false
	}
	owner := strings.TrimSuffix(name, containerSuffix)
	if owner == "" {
		return "", false
	}
	return owner, true
}

// AuthorizeContainerAccess validates the caller's right to
// read/touch `containerName`. Admins always pass; tenants
// pass only when the container's derived owner matches the
// caller's subject. System containers (no `-container`
// suffix) require admin.
//
// Use this when a handler accepts container_name and needs
// AuthorizeTenant-style semantics. The semantics intentionally
// mirror AuthorizeTenant, so the auth surface remains uniform
// across the gRPC layer.
func AuthorizeContainerAccess(ctx context.Context, containerName string) error {
	subject, roles, ok := SubjectFromGRPCContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "no authenticated subject")
	}
	if HasRole(roles, RoleAdmin) {
		return nil
	}
	owner, ok := OwnerFromContainerName(containerName)
	if !ok {
		// System container — only admins reach the body.
		return status.Errorf(codes.PermissionDenied,
			"not authorized: container %q is not owned by a tenant", containerName)
	}
	if owner != subject {
		return status.Errorf(codes.PermissionDenied,
			"not authorized: container %q belongs to a different tenant", containerName)
	}
	return nil
}
