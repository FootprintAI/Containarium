package threatdetect

import (
	"time"

	"github.com/footprintai/containarium/internal/netbpf"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// CrossTenantFlowRule is the continuous form of the one-shot isolation
// check: a flow whose source and destination resolve to containers in
// different tenants on the same backend means the tenant fence has been
// breached, not merely probed (see DenyBurstRule for probing). See
// docs/architecture/continuous-threat-detection.md.
type CrossTenantFlowRule struct{}

// NewCrossTenantFlowRule builds the rule. Stateless — every flow is judged
// independently, so there is nothing to construct.
func NewCrossTenantFlowRule() *CrossTenantFlowRule { return &CrossTenantFlowRule{} }

func (r *CrossTenantFlowRule) ID() pb.ThreatRuleId {
	return pb.ThreatRuleId_THREAT_RULE_ID_CROSS_TENANT_FLOW
}

// OnFlows flags a flow only when BOTH endpoints resolve to a known tenant
// and those tenants differ. An unresolved endpoint (traffic to/from
// something outside this backend's tenant fleet — a peer backend, the
// internet, the host itself) never raises a finding: guessing at an unknown
// IP's tenant would turn ordinary egress into false positives.
func (r *CrossTenantFlowRule) OnFlows(ctx RuleContext, flows []netbpf.FlowRecord) []RawFinding {
	var out []RawFinding
	for _, f := range flows {
		srcTenant, srcOK := ctx.TenantForIP(f.Src())
		if !srcOK {
			continue
		}
		dstTenant, dstOK := ctx.TenantForIP(f.Dst())
		if !dstOK || dstTenant == srcTenant {
			continue
		}
		out = append(out, RawFinding{
			Rule:     pb.ThreatRuleId_THREAT_RULE_ID_CROSS_TENANT_FLOW,
			Severity: pb.ThreatSeverity_THREAT_SEVERITY_CRITICAL,
			TenantID: srcTenant,
			// Subject is the peer tenant id — see RawFinding's dedupe-scope
			// doc. Two tenants probing each other from both sides dedupe
			// into two distinct findings (one per direction), which is
			// correct: each side's container is a separate thing to
			// investigate.
			Subject: dstTenant,
			Evidence: Evidence{Flows: []FlowEvidence{{
				SrcIP:    f.Src().String(),
				DstIP:    f.Dst().String(),
				SrcPort:  uint32(f.Sport),
				DstPort:  uint32(f.Dport),
				Protocol: protoName(f.Proto),
				Bytes:    safeInt64(f.Bytes),
				Packets:  safeInt64(f.Packets),
			}}},
		})
	}
	return out
}

// OnDeny: cross-tenant-flow is a flow-shaped rule; a policy deny means the
// enforcer already stopped the packet, so it can't be the breach this rule
// exists to catch (that's DenyBurstRule's signal instead).
func (r *CrossTenantFlowRule) OnDeny(RuleContext, netbpf.DenyEvent) []RawFinding { return nil }

// Sweep: no time-window state to evaluate.
func (r *CrossTenantFlowRule) Sweep(RuleContext, time.Time) []RawFinding { return nil }
