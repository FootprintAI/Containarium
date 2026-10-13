package server

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/footprintai/containarium/internal/audit"
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
	store    NetworkPolicyStore
	sigStore NetworkPolicySignatureStore // #661 PR-B: operator exploit signatures (global)

	// auditQuery and gateway serve PlanNetworkPolicy (#2440). Both are
	// optional: without an audit store the RPC is Unavailable, and without a
	// gateway the plan simply does not subtract the preset's implicit resolver.
	auditQuery denyAuditQuerier
	gateway    netip.Addr
}

// denyAuditQuerier is the slice of *audit.Store PlanNetworkPolicy needs.
type denyAuditQuerier interface {
	Query(ctx context.Context, params audit.QueryParams) ([]audit.AuditEntry, int32, error)
}

// SetPlanSources wires what PlanNetworkPolicy reads: the audit store holding
// the enforcer's deny rows and the bridge gateway (the preset's implicit
// resolver). Startup-only. Either may be zero/nil.
func (s *NetworkPolicyServer) SetPlanSources(q denyAuditQuerier, gateway netip.Addr) {
	s.auditQuery = q
	s.gateway = gateway
}

func NewNetworkPolicyServer(store NetworkPolicyStore) *NetworkPolicyServer {
	return &NetworkPolicyServer{store: store}
}

// SetSignatureStore wires the operator-signature store (#661 PR-B). Startup-only,
// same contract as SetStore. Nil leaves the signature RPCs returning Unavailable.
func (s *NetworkPolicyServer) SetSignatureStore(store NetworkPolicySignatureStore) {
	s.sigStore = store
}

// SignatureStore returns the operator-signature store (for the enforcer to read
// during reconcile). Nil until SetSignatureStore is called.
func (s *NetworkPolicyServer) SignatureStore() NetworkPolicySignatureStore {
	return s.sigStore
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

// --- Tier 2 operator signatures (#661 PR-B) ---

func (s *NetworkPolicyServer) SetNetworkPolicySignature(ctx context.Context, req *pb.SetNetworkPolicySignatureRequest) (*pb.SetNetworkPolicySignatureResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	if s.sigStore == nil {
		return nil, status.Error(codes.Unavailable, "network-policy signatures are not configured on this daemon")
	}
	name, pattern, err := netpolicy.ValidateSignature(req.GetSignature())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	// Default enabled=true unless the caller explicitly disabled it. (The proto
	// bool defaults to false; an operator adding a signature almost always wants it
	// on, and an explicit disable is the rare case — but we honor what's sent.)
	stored, err := s.sigStore.Set(ctx, name, pattern, req.GetSignature().GetEnabled(), req.GetSignature().GetNote())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "store signature: %v", err)
	}
	return &pb.SetNetworkPolicySignatureResponse{Signature: stored}, nil
}

func (s *NetworkPolicyServer) ListNetworkPolicySignatures(ctx context.Context, _ *pb.ListNetworkPolicySignaturesRequest) (*pb.ListNetworkPolicySignaturesResponse, error) {
	if err := auth.RequireRoleOrScope(ctx, auth.RoleAdmin, auth.ScopeNetworkPolicyRead); err != nil {
		return nil, err
	}
	if s.sigStore == nil {
		return &pb.ListNetworkPolicySignaturesResponse{}, nil
	}
	sigs, err := s.sigStore.List(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list signatures: %v", err)
	}
	return &pb.ListNetworkPolicySignaturesResponse{Signatures: sigs}, nil
}

func (s *NetworkPolicyServer) DeleteNetworkPolicySignature(ctx context.Context, req *pb.DeleteNetworkPolicySignatureRequest) (*pb.DeleteNetworkPolicySignatureResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	if s.sigStore == nil {
		return nil, status.Error(codes.Unavailable, "network-policy signatures are not configured on this daemon")
	}
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if err := s.sigStore.Delete(ctx, req.GetName()); err != nil && !errors.Is(err, ErrSignatureNotFound) {
		return nil, status.Errorf(codes.Internal, "delete signature: %v", err)
	}
	return &pb.DeleteNetworkPolicySignatureResponse{}, nil
}

const (
	planDefaultMinutes = 60
	planMaxMinutes     = 7 * 24 * 60
	// planRowCap bounds how many audit rows one plan reads per action. A
	// log-only tenant with a chatty workload can write many; the response
	// says when the cap was hit.
	planRowCap = 5000
)

// PlanNetworkPolicy aggregates a tenant's recent deny audit rows into the
// destinations an allow-list would need (#2440). Read-only.
func (s *NetworkPolicyServer) PlanNetworkPolicy(ctx context.Context, req *pb.PlanNetworkPolicyRequest) (*pb.PlanNetworkPolicyResponse, error) {
	if err := auth.RequireRoleOrScope(ctx, auth.RoleAdmin, auth.ScopeNetworkPolicyRead); err != nil {
		return nil, err
	}
	tenant := strings.TrimSpace(req.GetTenant())
	if tenant == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant is required")
	}
	if s.auditQuery == nil {
		return nil, status.Error(codes.Unavailable, "network policy plan needs the audit store, which is not available on this daemon")
	}
	minutes := int(req.GetSinceMinutes())
	if minutes <= 0 {
		minutes = planDefaultMinutes
	}
	if minutes > planMaxMinutes {
		minutes = planMaxMinutes
	}
	since := time.Now().Add(-time.Duration(minutes) * time.Minute)

	// Subtract what the tenant's current policy already allows, so rows from
	// before an allow-list edit do not read as still-missing.
	var allowed func(netip.Addr) bool
	var notes []string
	if p, err := s.store.Get(ctx, tenant); err == nil {
		if c, cerr := netpolicy.Compile(p); cerr == nil {
			implicit := netpolicy.ImplicitEgress(c, s.gateway)
			allowed = func(ip netip.Addr) bool { return c.Allows(ip, implicit) }
			if len(c.EgressDomains) > 0 {
				notes = append(notes, "destinations allowed only through egress_domains are not subtracted; they may appear here even though they are allowed")
			}
		}
	} else if !errors.Is(err, ErrNetworkPolicyNotFound) {
		return nil, status.Errorf(codes.Internal, "get network policy: %v", err)
	} else {
		notes = append(notes, "the tenant has no policy yet; every outbound destination its boxes reached is listed")
	}

	var rows []netpolicy.DenyRow
	truncated := false
	for _, action := range []string{"network_policy.deny_logged", "network_policy.deny_dropped"} {
		entries, total, err := s.auditQuery.Query(ctx, audit.QueryParams{
			Action: action, ResourceType: "network_policy", ResourceID: tenant,
			From: since, Limit: planRowCap,
		})
		if err != nil {
			return nil, status.Errorf(codes.Internal, "query audit rows: %v", err)
		}
		if int(total) > len(entries) {
			truncated = true
		}
		for _, e := range entries {
			rows = append(rows, netpolicy.DenyRow{Time: e.Timestamp, Detail: e.Detail})
		}
	}
	if truncated {
		notes = append(notes, "the audit row cap was reached; the oldest flows in the window may be missing")
	}

	dests := netpolicy.AggregateDenies(rows, allowed)
	out := &pb.PlanNetworkPolicyResponse{
		Tenant: tenant, SinceMinutes: int32(minutes), // #nosec G115 -- bounded by planMaxMinutes
		RowsScanned: clampU32(len(rows)), Truncated: truncated, Notes: notes,
	}
	for _, d := range dests {
		out.Destinations = append(out.Destinations, &pb.PlanDestination{
			Ip: d.IP.String(), Port: uint32(d.Port), Protocol: d.Proto,
			Count: d.Count, Dropped: d.Dropped, LastSeen: timestamppb.New(d.LastSeen),
		})
	}
	return out, nil
}

// clampU32 converts a non-negative count to uint32, saturating.
func clampU32(n int) uint32 {
	if n < 0 {
		return 0
	}
	if int64(n) > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(n) // #nosec G115 -- bounded above
}
