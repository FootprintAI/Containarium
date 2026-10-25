package server

import (
	"context"
	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/box"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"strings"
)

// Network identities and login/encryption identities are independent. Explicit
// shared boundaries are admin-only. Non-admin automatic boxes use a reserved
// account namespace, so choosing a username cannot join an admin-created shared
// domain. Existing resources are never relabeled by this change.
func authorizeNetworkTenantCreate(ctx context.Context, req *pb.CreateContainerRequest, localLXC bool) error {
	admin := auth.RequireRole(ctx, auth.RoleAdmin) == nil
	if err := authorizeNetworkTenantLabels(ctx, req.Labels); err != nil {
		return err
	}

	if !admin && localLXC {
		own := "account:" + req.Username
		if req.NetworkTenant != "" {
			return status.Error(codes.PermissionDenied, "shared network Tenant assignment requires administrator authority")
		}
		req.NetworkTenant = own
	} else if !admin && req.NetworkTenant != "" {
		return status.Error(codes.PermissionDenied, "shared network Tenant requires administrator authority")
	} else if strings.HasPrefix(req.NetworkTenant, "account:") {
		return status.Error(codes.InvalidArgument, "account network namespace is reserved")
	}
	if req.NetworkTenant != "" {
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
		if req.BackendId != "" || req.Pool != "" || req.Region != "" {
			return status.Error(codes.FailedPrecondition, "network Tenant contract requires the local LXC backend")
		}
	}
	return nil
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
