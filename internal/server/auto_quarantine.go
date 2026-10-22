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
// can't exfiltrate or call out.
//
// A "clean" verdict never releases it (#2631): the verdict is produced by the
// scan running inside the tenant's own box, so it is self-reported, and a
// compromised box could otherwise lift its own quarantine. Release is by an
// operator removing the rule (note quarantineNote) or by the TTL below.
//
// This is the one scanner finding that maps CLEANLY onto the Tier 1 deny rules:
// an "infected" malware verdict ↔ a network-quarantine action. (Trivy
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

// quarantineNote marks a deny rule as auto-added by quarantine, so an operator can
// tell it from their own, and quarantine never clobbers an operator's own
// 0.0.0.0/0 deny.
const quarantineNote = "auto-quarantine: clamav malware"

// defaultQuarantineTTL is a safety backstop: if scans stop entirely, an
// abandoned quarantine self-expires rather than blackholing a tenant forever.
// Refreshed on every infected scan; a clean scan does not release it.
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

// OnScanResult is the scanner callback: quarantine on "infected", ignore
// anything else. "clean" is deliberately ignored for release (self-reported
// verdict, see the file header); it is logged when a quarantine is in place. tenant is the container's owning username.
func (q *AutoQuarantine) OnScanResult(containerName, tenant, status string) {
	tenant = strings.TrimSpace(tenant)
	if tenant == "" {
		return
	}
	if status == "clean" {
		log.Printf("[auto-quarantine] clean verdict for %s (tenant %q) not used to release any quarantine (self-reported; release is operator/TTL)", containerName, tenant)
		return
	}
	if status != "infected" {
		return
	}
	expiry := q.now().Add(q.ttl)
	mutate := func(existing []*pb.NetworkPolicyDenyRule) ([]*pb.NetworkPolicyDenyRule, error) {
		return applyQuarantine(existing, expiry), nil
	}
	if _, err := q.store.MutateDenyRules(context.Background(), tenant, mutate); err != nil {
		log.Printf("[auto-quarantine] infected tenant=%q: %v", tenant, err)
		return
	}
	log.Printf("[auto-quarantine] QUARANTINED tenant %q (egress blocked) — malware in %s", tenant, containerName)
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

func isQuarantineCIDR(r *pb.NetworkPolicyDenyRule) bool {
	return strings.TrimSpace(r.GetCidr()) == quarantineCIDR
}
