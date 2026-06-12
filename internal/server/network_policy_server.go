package server

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/netpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// errDenyRuleNotFound aborts a pure-removal patch (no adds) that matched no
// existing deny rule, so PatchNetworkPolicyDenyRules can report NotFound and the
// transaction rolls back rather than committing a no-op.
var errDenyRuleNotFound = errors.New("deny rule not found")

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

// Store returns the backing store. Used by the network-policy enforcer to read
// stored policies for reconcile; call after any startup-time SetStore swap.
func (s *NetworkPolicyServer) Store() NetworkPolicyStore {
	return s.store
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
	if err := auth.RequireRoleOrScope(ctx, auth.RoleAdmin, auth.ScopeNetworkPolicyRead); err != nil {
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
	if err := auth.RequireRoleOrScope(ctx, auth.RoleAdmin, auth.ScopeNetworkPolicyRead); err != nil {
		return nil, err
	}
	policies, err := s.store.List(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list network policies: %v", err)
	}
	return &pb.ListNetworkPoliciesResponse{Policies: policies}, nil
}

// PatchNetworkPolicyDenyRules atomically adds/removes a tenant's virtual-patch
// deny rules (#660). The add rules are validated up front; the merge (remove by
// CIDR, then add — deny rules are CIDR-keyed, so an add replaces an existing
// rule for the same CIDR) and re-normalization run inside the store's atomic
// MutateDenyRules, so concurrent patches can't lose updates.
func (s *NetworkPolicyServer) PatchNetworkPolicyDenyRules(ctx context.Context, req *pb.PatchNetworkPolicyDenyRulesRequest) (*pb.SetNetworkPolicyResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	tenant := strings.TrimSpace(req.GetTenant())
	if tenant == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant is required")
	}
	if len(req.GetAdd()) == 0 && len(req.GetRemoveCidrs()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "patch must add or remove at least one deny rule")
	}
	// Validate the add rules up front (cidr/port/proto/expiry) so a bad rule fails
	// with InvalidArgument before touching the store.
	if _, err := netpolicy.Compile(&pb.NetworkPolicy{Tenant: tenant, DenyRules: req.GetAdd()}); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	// Normalize the remove CIDRs once (so "1.2.3.4" matches stored "1.2.3.4/32").
	remove := make(map[string]bool, len(req.GetRemoveCidrs()))
	for _, c := range req.GetRemoveCidrs() {
		n, err := normalizeDenyCIDR(c)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "remove cidr %q: %v", c, err)
		}
		remove[n] = true
	}

	pureRemoval := len(req.GetAdd()) == 0
	stored, err := s.store.MutateDenyRules(ctx, tenant, func(existing []*pb.NetworkPolicyDenyRule) ([]*pb.NetworkPolicyDenyRule, error) {
		kept := make([]*pb.NetworkPolicyDenyRule, 0, len(existing))
		removed := 0
		for _, r := range existing {
			n, err := normalizeDenyCIDR(r.GetCidr())
			if err == nil && remove[n] {
				removed++
				continue
			}
			kept = append(kept, r)
		}
		if pureRemoval && removed == 0 {
			return nil, errDenyRuleNotFound
		}
		// Merge then re-normalize via Compile (dedups by CIDR — an added rule wins
		// for its CIDR — validates, sorts).
		merged := append(kept, req.GetAdd()...)
		compiled, err := netpolicy.Compile(&pb.NetworkPolicy{Tenant: tenant, DenyRules: merged})
		if err != nil {
			return nil, err
		}
		return compiled.ToProto().GetDenyRules(), nil
	})
	if err != nil {
		if errors.Is(err, errDenyRuleNotFound) {
			return nil, status.Errorf(codes.NotFound, "no matching deny rule to remove for tenant %q", tenant)
		}
		return nil, status.Errorf(codes.Internal, "patch deny rules: %v", err)
	}
	return &pb.SetNetworkPolicyResponse{Policy: stored}, nil
}

// normalizeDenyCIDR canonicalizes a deny-rule CIDR (a bare host becomes /32,
// masked to its network) so removals match stored rules regardless of input form.
func normalizeDenyCIDR(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("cidr is required")
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return "", err
		}
		return p.Masked().String(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return "", err
	}
	return netip.PrefixFrom(a, a.BitLen()).String(), nil
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
