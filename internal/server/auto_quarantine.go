package server

import (
	"context"
	"log"
	"strings"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Auto-quarantine (#659): the honest realization of the "scanner → virtual-patch"
// capstone. When the ClamAV scanner finds malware in a container, block that
// tenant's egress (a deny-all virtual-patch rule) so a compromised container
// can't exfiltrate or call out; release it when the container scans clean again.
//
// This is the one scanner finding that maps CLEANLY onto the Tier 1 deny rules:
// a malware verdict ("infected"/"clean") ↔ a network-quarantine action. (Trivy
// package CVEs, by contrast, describe a vulnerability INSIDE the container with
// no network endpoint to block, so they are deliberately NOT wired here — see
// docs/security/AUTO-QUARANTINE.md.)
//
// Caveats (documented): deny rules are per-TENANT, so quarantining one infected
// container blocks egress for all that tenant's containers — containment over
// availability, acceptable for a malware response and opt-in. Enforcement is
// only as strong as the network-policy BPF enforcer that's enabled
// (CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT + _ENFORCE); without it the rule is
// stored but not dropped.

// quarantineCIDR is the deny target for a full egress quarantine (block all
// outbound). Deny beats allow, so this blackholes the tenant's egress.
const quarantineCIDR = "0.0.0.0/0"

// quarantineNote marks a deny rule as auto-added by quarantine, so release only
// removes OUR rule and never clobbers an operator's own 0.0.0.0/0 deny.
const quarantineNote = "auto-quarantine: clamav malware"

// defaultQuarantineTTL is a safety backstop: if scans stop entirely, an
// abandoned quarantine self-expires rather than blackholing a tenant forever.
// Refreshed on every infected scan; release on a clean scan is immediate.
const defaultQuarantineTTL = 24 * time.Hour

// denyRuleMutator is the slice of NetworkPolicyStore the hook needs — its atomic
// deny-rule mutation. *MemNetworkPolicyStore / *PostgresNetworkPolicyStore both
// satisfy it; an interface keeps the hook testable.
type denyRuleMutator interface {
	MutateDenyRules(ctx context.Context, tenant string, fn func([]*pb.NetworkPolicyDenyRule) ([]*pb.NetworkPolicyDenyRule, error)) (*pb.NetworkPolicy, error)
}

// AutoQuarantine wires a ClamAV scan result to a tenant's deny rules.
type AutoQuarantine struct {
	store denyRuleMutator
	ttl   time.Duration
	now   func() time.Time // injectable for tests
}

// NewAutoQuarantine builds the hook over a deny-rule store.
func NewAutoQuarantine(store denyRuleMutator) *AutoQuarantine {
	return &AutoQuarantine{store: store, ttl: defaultQuarantineTTL, now: time.Now}
}

// OnScanResult is the scanner callback: quarantine on "infected", release on
// "clean", ignore anything else. tenant is the container's owning username.
func (q *AutoQuarantine) OnScanResult(containerName, tenant, status string) {
	tenant = strings.TrimSpace(tenant)
	if tenant == "" {
		return
	}
	var mutate func([]*pb.NetworkPolicyDenyRule) ([]*pb.NetworkPolicyDenyRule, error)
	switch status {
	case "infected":
		expiry := q.now().Add(q.ttl)
		mutate = func(existing []*pb.NetworkPolicyDenyRule) ([]*pb.NetworkPolicyDenyRule, error) {
			return applyQuarantine(existing, expiry), nil
		}
	case "clean":
		mutate = func(existing []*pb.NetworkPolicyDenyRule) ([]*pb.NetworkPolicyDenyRule, error) {
			return releaseQuarantine(existing), nil
		}
	default:
		return
	}
	if _, err := q.store.MutateDenyRules(context.Background(), tenant, mutate); err != nil {
		log.Printf("[auto-quarantine] %s tenant=%q: %v", status, tenant, err)
		return
	}
	switch status {
	case "infected":
		log.Printf("[auto-quarantine] QUARANTINED tenant %q (egress blocked) — malware in %s", tenant, containerName)
	case "clean":
		log.Printf("[auto-quarantine] released tenant %q — %s scanned clean", tenant, containerName)
	}
}

// applyQuarantine ensures a quarantine deny rule is present, refreshing its
// expiry. If a 0.0.0.0/0 deny already exists with a DIFFERENT note (an operator's
// own block), it is left untouched — that block already achieves containment, so
// quarantine relies on it rather than overwriting it.
func applyQuarantine(rules []*pb.NetworkPolicyDenyRule, expiry time.Time) []*pb.NetworkPolicyDenyRule {
	exp := expiry.UTC().Format(time.RFC3339)
	for _, r := range rules {
		if isQuarantineCIDR(r) {
			if r.GetNote() == quarantineNote {
				r.ExpiresAt = exp // refresh our rule's expiry
			}
			// else: operator's own 0.0.0.0/0 deny — leave it, it already contains.
			return rules
		}
	}
	return append(rules, &pb.NetworkPolicyDenyRule{
		Cidr:      quarantineCIDR,
		Note:      quarantineNote,
		ExpiresAt: exp,
	})
}

// releaseQuarantine drops only the auto-added quarantine rule, preserving any
// operator-authored deny rules (including a differently-noted 0.0.0.0/0).
func releaseQuarantine(rules []*pb.NetworkPolicyDenyRule) []*pb.NetworkPolicyDenyRule {
	out := rules[:0:0]
	for _, r := range rules {
		if isQuarantineCIDR(r) && r.GetNote() == quarantineNote {
			continue // our rule — remove
		}
		out = append(out, r)
	}
	return out
}

func isQuarantineCIDR(r *pb.NetworkPolicyDenyRule) bool {
	return strings.TrimSpace(r.GetCidr()) == quarantineCIDR
}
