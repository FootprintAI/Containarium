package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/protobuf/proto"
	"sort"
)

var ErrTenantAccessConflict = errors.New("network policy changed since preview")

type TenantAccessStore interface {
	PatchTenantAccess(context.Context, []*pb.TenantAccessChange) ([]*pb.TenantAccessPolicy, error)
}

// PolicyRevision covers the entire policy, including independently managed deny
// rules. An ingress patch can never silently discard an intervening policy edit.
func PolicyRevision(p *pb.NetworkPolicy) string {
	if p == nil {
		return "absent"
	}
	b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(p)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func validateAccessChanges(changes []*pb.TenantAccessChange) error {
	if len(changes) == 0 || len(changes) > 32 {
		return fmt.Errorf("1-32 destination changes required")
	}
	seen := map[string]bool{}
	for _, c := range changes {
		if c == nil {
			return fmt.Errorf("invalid destination change")
		}
		if err := incus.ValidateNetworkTenant(c.Destination); err != nil {
			return err
		}
		if seen[c.Destination] {
			return fmt.Errorf("duplicate destination")
		}
		seen[c.Destination] = true
		if c.ExpectedRevision == "absent" && len(c.AddSources) == 0 {
			return fmt.Errorf("no policy exists to revoke; omit this no-op destination")
		}
		if c.ExpectedRevision != "absent" {
			b, err := hex.DecodeString(c.ExpectedRevision)
			if err != nil || len(b) != 32 {
				return fmt.Errorf("expected full policy revision is required")
			}
		}
		if len(c.AddSources)+len(c.RemoveSources) == 0 || len(c.AddSources)+len(c.RemoveSources) > 100 {
			return fmt.Errorf("1-100 ingress source edits required")
		}
		sources := map[string]bool{}
		for _, src := range append(append([]string{}, c.AddSources...), c.RemoveSources...) {
			if err := incus.ValidateNetworkTenant(src); err != nil {
				return err
			}
			if src == c.Destination || sources[src] {
				return fmt.Errorf("self, duplicate or contradictory ingress source")
			}
			sources[src] = true
		}
	}
	return nil
}

func applyAccess(old *pb.NetworkPolicy, c *pb.TenantAccessChange) (*pb.NetworkPolicy, error) {
	if PolicyRevision(old) != c.ExpectedRevision {
		return nil, ErrTenantAccessConflict
	}
	var next *pb.NetworkPolicy
	if old == nil {
		// No pre-existing egress policy is reset. The new record remains log-only;
		// its allow_from_tenants is consumed independently by the NIC guard.
		next = &pb.NetworkPolicy{Tenant: c.Destination}
	} else {
		next = proto.Clone(old).(*pb.NetworkPolicy)
	}
	allowed := map[string]bool{}
	for _, src := range next.AllowFromTenants {
		allowed[src] = true
	}
	for _, src := range c.RemoveSources {
		delete(allowed, src)
	}
	for _, src := range c.AddSources {
		allowed[src] = true
	}
	next.AllowFromTenants = nil
	for src := range allowed {
		next.AllowFromTenants = append(next.AllowFromTenants, src)
	}
	sort.Strings(next.AllowFromTenants)
	return next, nil
}

func (s *MemNetworkPolicyStore) PatchTenantAccess(_ context.Context, changes []*pb.TenantAccessChange) ([]*pb.TenantAccessPolicy, error) {
	if err := validateAccessChanges(changes); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := map[string]*pb.NetworkPolicy{}
	out := []*pb.TenantAccessPolicy{}
	for _, c := range changes {
		p, err := applyAccess(s.m[c.Destination], c)
		if err != nil {
			return nil, err
		}
		next[c.Destination] = p
		out = append(out, &pb.TenantAccessPolicy{Policy: proto.Clone(p).(*pb.NetworkPolicy), Revision: PolicyRevision(p)})
	}
	for key, p := range next {
		s.m[key] = p
	}
	return out, nil
}

func (s *PostgresNetworkPolicyStore) PatchTenantAccess(ctx context.Context, changes []*pb.TenantAccessChange) ([]*pb.TenantAccessPolicy, error) {
	if err := validateAccessChanges(changes); err != nil {
		return nil, err
	}
	// Consistent lock order avoids A/B vs B/A deadlocks. No caller input mutation.
	changes = append([]*pb.TenantAccessChange(nil), changes...)
	sort.Slice(changes, func(i, j int) bool { return changes[i].Destination < changes[j].Destination })
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	out := []*pb.TenantAccessPolicy{}
	for _, c := range changes {
		tag, err := tx.Exec(ctx, `INSERT INTO network_policies (tenant) VALUES ($1) ON CONFLICT (tenant) DO NOTHING`, c.Destination)
		if err != nil {
			return nil, err
		}
		inserted := tag.RowsAffected() == 1
		p := &pb.NetworkPolicy{Tenant: c.Destination}
		var mode, preset, egressMode int32
		var deny []byte
		err = tx.QueryRow(ctx, `SELECT allow_intra_tenant,egress_cidrs,egress_domains,mode,allow_metadata,source,deny_rules,allow_from_tenants,egress_preset,egress_mode FROM network_policies WHERE tenant=$1 FOR UPDATE`, c.Destination).Scan(&p.AllowIntraTenant, &p.EgressCidrs, &p.EgressDomains, &mode, &p.AllowMetadata, &p.Source, &deny, &p.AllowFromTenants, &preset, &egressMode)
		if err != nil {
			return nil, err
		}
		p.Mode = pb.NetworkPolicyMode(mode)
		p.EgressPreset = pb.EgressPreset(preset)
		p.EgressMode = pb.NetworkPolicyMode(egressMode)
		p.DenyRules, err = decodeDenyRules(deny)
		if err != nil {
			return nil, err
		}
		if inserted {
			p = nil
		}
		next, err := applyAccess(p, c)
		if err != nil {
			return nil, err
		}
		// Only ingress sources change. Default mode for an absent record is already
		// unspecified/log-only; do not UPDATE any egress, mode, metadata or deny field.
		if inserted {
			next.Mode = pb.NetworkPolicyMode_NETWORK_POLICY_MODE_UNSPECIFIED
		}
		if _, err = tx.Exec(ctx, `UPDATE network_policies SET allow_from_tenants=$2,updated_at=NOW() WHERE tenant=$1`, c.Destination, nonNilStrings(next.AllowFromTenants)); err != nil {
			return nil, err
		}
		out = append(out, &pb.TenantAccessPolicy{Policy: next, Revision: PolicyRevision(next)})
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

var _ TenantAccessStore = (*MemNetworkPolicyStore)(nil)
var _ TenantAccessStore = (*PostgresNetworkPolicyStore)(nil)
