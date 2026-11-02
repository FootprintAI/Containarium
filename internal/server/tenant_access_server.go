package server

import (
	"context"
	"errors"
	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"log"
	"time"
)

// guardReady separates enforcement evidence from stored policy and TCP tests.
func (s *NetworkPolicyServer) guardReady() bool {
	return s.tenantGuardRead != nil && s.tenantStoreDurable != nil && s.tenantStoreDurable() && nativeTenantGuardReady(s.tenantGuardRead(), time.Now())
}
func (s *NetworkPolicyServer) atomicTenantAccessAvailable() bool {
	_, ok := s.store.(TenantAccessStore)
	return ok && s.tenantGuardRead != nil && s.tenantStoreDurable != nil && s.tenantStoreDurable()
}
func (s *NetworkPolicyServer) PatchTenantAccess(ctx context.Context, req *pb.PatchTenantAccessRequest) (*pb.PatchTenantAccessResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	if err := auth.RequireScope(ctx, auth.ScopeNetworkPolicyWrite); err != nil {
		return nil, err
	}
	if err := validateAccessChanges(req.GetChanges()); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	store, ok := s.store.(TenantAccessStore)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "atomic Tenant access unavailable")
	}
	if s.tenantGuardRead == nil || s.tenantStoreDurable == nil {
		return nil, status.Error(codes.FailedPrecondition, "local LXC Tenant Guard contract is not configured")
	}
	if !s.guardReady() {
		for _, change := range req.Changes {
			if len(change.AddSources) > 0 {
				return nil, status.Error(codes.FailedPrecondition, "grant requires fresh ENFORCE supported Tenant Guard")
			}
		}
	}
	if s.tenantStoreDurable != nil && !s.tenantStoreDurable() {
		return nil, status.Error(codes.FailedPrecondition, "durable policy store unavailable")
	}
	policies, err := store.PatchTenantAccess(ctx, req.Changes)
	if errors.Is(err, ErrTenantAccessConflict) {
		return nil, status.Error(codes.Aborted, err.Error())
	}
	if err != nil {
		// The caller gets a generic Internal (the cause could name internal
		// policy rows); the operator needs the real reason in the daemon log.
		log.Printf("[tenant-access] store failure: %v", err)
		return nil, status.Error(codes.Internal, "atomic Tenant access store failed")
	}
	// Store success is not enforcement success. Never roll back unrelated policy
	// writes or report a TCP result from an ACL reconciliation. The
	// reconciliation runs after the response is fully computed but before it is
	// returned; it takes the guard's own write lock, so a slow pass delays this
	// reply without holding any network-policy lock.
	applied := pb.TenantAccessApplicationState_TENANT_ACCESS_APPLICATION_STATE_PENDING
	if s.tenantGuardReconcile != nil {
		if err := s.tenantGuardReconcile(ctx); err != nil {
			applied = pb.TenantAccessApplicationState_TENANT_ACCESS_APPLICATION_STATE_DEGRADED
		} else if s.guardReady() {
			applied = pb.TenantAccessApplicationState_TENANT_ACCESS_APPLICATION_STATE_GUARD_VERIFIED
			for _, p := range policies {
				current, e := s.store.Get(ctx, p.Policy.Tenant)
				if e != nil || PolicyRevision(current) != p.Revision {
					applied = pb.TenantAccessApplicationState_TENANT_ACCESS_APPLICATION_STATE_PENDING
				}
			}
		}
	}
	actor, _, _ := auth.SubjectFromGRPCContext(ctx)
	for _, c := range req.Changes {
		log.Printf("[tenant-access] actor=%q destination=%q add=%q remove=%q state=%s", actor, c.Destination, c.AddSources, c.RemoveSources, applied)
	}
	return &pb.PatchTenantAccessResponse{Policies: policies, ApplicationState: applied, ConnectivityTested: false}, nil
}
