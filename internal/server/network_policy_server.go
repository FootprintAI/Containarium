package server

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/netpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// NetworkPolicyServer implements the control-plane CRUD for per-tenant network
// policies (Phase A, #315). It validates/normalizes via internal/netpolicy and
// persists through a NetworkPolicyStore. Admin-only — policies are
// fleet-shaping config, not tenant-editable. The per-veth TC_INGRESS BPF loader
// (a later increment) consumes the stored policies.
type NetworkPolicyServer struct {
	pb.UnimplementedNetworkPolicyServiceServer
	store NetworkPolicyStore
}

func NewNetworkPolicyServer(store NetworkPolicyStore) *NetworkPolicyServer {
	return &NetworkPolicyServer{store: store}
}

// SetStore swaps the backing store. Intended for startup only — called during
// NewDualServer (before the gRPC server starts serving) to upgrade the initial
// in-memory store to the Postgres-backed one once the DB connection string is
// resolved. Not safe to call concurrently with live RPCs.
func (s *NetworkPolicyServer) SetStore(store NetworkPolicyStore) {
	s.store = store
}

func (s *NetworkPolicyServer) SetNetworkPolicy(ctx context.Context, req *pb.SetNetworkPolicyRequest) (*pb.SetNetworkPolicyResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	// Validate + normalize (parse/dedup CIDRs, normalize domains, resolve mode).
	compiled, err := netpolicy.Compile(req.GetPolicy())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	stored := compiled.ToProto()
	if err := s.store.Set(ctx, stored); err != nil {
		return nil, status.Errorf(codes.Internal, "store network policy: %v", err)
	}
	return &pb.SetNetworkPolicyResponse{Policy: stored}, nil
}

func (s *NetworkPolicyServer) GetNetworkPolicy(ctx context.Context, req *pb.GetNetworkPolicyRequest) (*pb.GetNetworkPolicyResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	if req.GetTenant() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant is required")
	}
	p, err := s.store.Get(ctx, req.GetTenant())
	if err != nil {
		if errors.Is(err, ErrNetworkPolicyNotFound) {
			return nil, status.Errorf(codes.NotFound, "no network policy for tenant %q", req.GetTenant())
		}
		return nil, status.Errorf(codes.Internal, "get network policy: %v", err)
	}
	return &pb.GetNetworkPolicyResponse{Policy: p}, nil
}

func (s *NetworkPolicyServer) ListNetworkPolicies(ctx context.Context, _ *pb.ListNetworkPoliciesRequest) (*pb.ListNetworkPoliciesResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	policies, err := s.store.List(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list network policies: %v", err)
	}
	return &pb.ListNetworkPoliciesResponse{Policies: policies}, nil
}

func (s *NetworkPolicyServer) DeleteNetworkPolicy(ctx context.Context, req *pb.DeleteNetworkPolicyRequest) (*pb.DeleteNetworkPolicyResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	if req.GetTenant() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant is required")
	}
	if err := s.store.Delete(ctx, req.GetTenant()); err != nil {
		return nil, status.Errorf(codes.Internal, "delete network policy: %v", err)
	}
	return &pb.DeleteNetworkPolicyResponse{}, nil
}
