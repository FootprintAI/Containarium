package server

import (
	"context"
	"github.com/footprintai/containarium/internal/auth"
	appconfig "github.com/footprintai/containarium/internal/config"
	"github.com/footprintai/containarium/pkg/core/box"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"strings"
)

// Network identities and login/encryption identities are independent. Explicit
// shared boundaries are admin-only. When the operator arms
// CONTAINARIUM_NATIVE_ACCOUNT_TENANCY, a non-admin local-LXC create that names
// no network Tenant is placed in the reserved per-user account namespace, so
// choosing a username cannot join an admin-created shared domain. With the
// switch off (the default) an omitted field takes the legacy un-tenanted path.
// A non-admin may never name a Tenant — not even their own account namespace —
// because the key exists to keep caller-chosen names out of the shared domain
// space. Existing resources are never relabeled by this change.
func authorizeNetworkTenantCreate(ctx context.Context, req *pb.CreateContainerRequest, localLXC bool, accountTenancy bool) error {
	admin := auth.RequireRole(ctx, auth.RoleAdmin) == nil
	if err := authorizeNetworkTenantLabels(ctx, req.Labels); err != nil {
		return err
	}

	autoAssigned := false
	if !admin && accountTenancy && localLXC && req.NetworkTenant == "" {
		req.NetworkTenant = "account:" + req.Username
		autoAssigned = true
	}
	if req.NetworkTenant != "" {
		if !admin {
			if !autoAssigned {
				return status.Error(codes.PermissionDenied, "network Tenant assignment requires administrator authority")
			}
			// Fall through: the operator-armed account namespace is not a
			// caller-supplied assignment; the placement checks below still apply.
		} else if strings.HasPrefix(req.NetworkTenant, "account:") {
			return status.Error(codes.InvalidArgument, "account network namespace is reserved")
		}
		if !localLXC {
			return status.Error(codes.FailedPrecondition, "native network Tenant requires local LXC backend")
		}
		if err := incus.ValidateNetworkTenant(req.NetworkTenant); err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		if req.Labels[incus.CloudOrgIDLabel] != "" && req.Labels[incus.CloudOrgIDLabel] != req.NetworkTenant {
			return status.Error(codes.InvalidArgument, "conflicting cloud and network Tenant attribution")
		}
		if req.Isolation == pb.IsolationType_ISOLATION_TYPE_VM || req.OsType == pb.OSType_OS_TYPE_WINDOWS_2022 {
			return status.Error(codes.InvalidArgument, "network Tenant contract supports Linux LXC only")
		}
		if req.BackendId != "" || req.Pool != "" {
			return status.Error(codes.FailedPrecondition, "network Tenant contract requires the local LXC backend")
		}
		// req.Region is not checked: it is a documented no-op hint on a
		// standalone daemon and never selects a peer, so it cannot move an
		// assigned Tenant off this host.
	}
	return nil
}

// accountTenancyArmed reports whether the operator armed automatic per-user
// account namespaces on this daemon (CONTAINARIUM_NATIVE_ACCOUNT_TENANCY).
// Off by default: omitted-field creates keep the legacy un-tenanted path.
func accountTenancyArmed() bool {
	return appconfig.LoadNetwork().NativeAccountTenancy
}

func authorizeNetworkTenantLabels(ctx context.Context, labels map[string]string) error {
	admin := auth.RequireRole(ctx, auth.RoleAdmin) == nil
	for k := range labels {
		if k == "tenant" || k == incus.TenantLabelKey || strings.HasPrefix(k, "user.containarium.") {
			return status.Error(codes.InvalidArgument, "protected network attribution is not a generic label")
		}
		if k == incus.CloudOrgIDLabel && !admin {
			return status.Error(codes.PermissionDenied, "cloud attribution requires administrator authority")
		}
	}
	return nil
}

// A manager can also wrap UnavailableBackend on a K8s daemon. Its presence
// alone is not evidence that this server creates local LXC instances.
func (s *ContainerServer) nativeTenantLocalLXC() bool {
	return s.GetManager() != nil && s.boxWriter == nil && s.boxes().Kind() == box.KindLXC
}
