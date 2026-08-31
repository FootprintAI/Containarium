// Package threatdetect holds the background security-detection engine: the
// rule registry, the finding store, and delivery. See
// docs/architecture/continuous-threat-detection.md.
package threatdetect

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// timestampProto converts a zero-safe time.Time to a *timestamppb.Timestamp,
// returning nil for a zero time rather than the protobuf epoch.
func timestampProto(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

// EvidenceCap is the maximum number of flow/deny records kept per finding.
// Evidence exists to show an operator a representative sample, not a full
// trace — an unbounded finding row would grow without limit under a
// sustained attack.
const EvidenceCap = 10

// FlowEvidence is one triggering flow's 5-tuple and volume.
type FlowEvidence struct {
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	SrcPort  uint32 `json:"src_port"`
	DstPort  uint32 `json:"dst_port"`
	Protocol string `json:"protocol"`
	Bytes    int64  `json:"bytes"`
	Packets  int64  `json:"packets"`
}

// DenyEvidence is an aggregated count of policy-deny events matching one
// destination/reason pair.
type DenyEvidence struct {
	DstIP    string `json:"dst_ip"`
	DstPort  uint32 `json:"dst_port"`
	Protocol string `json:"protocol"`
	Reason   string `json:"reason"`
	Count    int64  `json:"count"`
}

// Evidence bundles the flow and deny records that triggered a finding. It is
// the named struct written into the security_findings.evidence JSONB
// column — a storage encoding, never an ad-hoc map.
type Evidence struct {
	Flows  []FlowEvidence `json:"flows,omitempty"`
	Denies []DenyEvidence `json:"denies,omitempty"`
}

// Capped returns a copy of e with Flows and Denies each truncated to the
// most recent EvidenceCap entries.
func (e Evidence) Capped() Evidence {
	out := Evidence{Flows: e.Flows, Denies: e.Denies}
	if len(out.Flows) > EvidenceCap {
		out.Flows = out.Flows[len(out.Flows)-EvidenceCap:]
	}
	if len(out.Denies) > EvidenceCap {
		out.Denies = out.Denies[len(out.Denies)-EvidenceCap:]
	}
	return out
}

// FindingState is the lifecycle state of a Finding.
type FindingState string

const (
	FindingStateOpen     FindingState = "open"
	FindingStateResolved FindingState = "resolved"
)

// Finding is a single security finding: an open or resolved instance of a
// rule firing for one tenant. Mirrors the security_findings table.
type Finding struct {
	ID        int64
	Rule      pb.ThreatRuleId
	Severity  pb.ThreatSeverity
	TenantID  string
	Container string
	BackendID string
	// Subject is the dedupe scope within (Rule, TenantID): destination IP,
	// peer tenant id, or "" — see the security_findings_open_dedupe index.
	Subject   string
	State     FindingState
	Count     int64
	Evidence  Evidence
	FirstSeen time.Time
	LastSeen  time.Time
}

// ToProto converts a Finding to its wire representation.
func (f *Finding) ToProto() *pb.Finding {
	state := pb.FindingState_FINDING_STATE_UNSPECIFIED
	switch f.State {
	case FindingStateOpen:
		state = pb.FindingState_FINDING_STATE_OPEN
	case FindingStateResolved:
		state = pb.FindingState_FINDING_STATE_RESOLVED
	}

	flows := make([]*pb.FlowEvidence, 0, len(f.Evidence.Flows))
	for _, fl := range f.Evidence.Flows {
		flows = append(flows, &pb.FlowEvidence{
			SrcIp:    fl.SrcIP,
			DstIp:    fl.DstIP,
			SrcPort:  fl.SrcPort,
			DstPort:  fl.DstPort,
			Protocol: fl.Protocol,
			Bytes:    fl.Bytes,
			Packets:  fl.Packets,
		})
	}
	denies := make([]*pb.DenyEvidence, 0, len(f.Evidence.Denies))
	for _, d := range f.Evidence.Denies {
		denies = append(denies, &pb.DenyEvidence{
			DstIp:    d.DstIP,
			DstPort:  d.DstPort,
			Protocol: d.Protocol,
			Reason:   d.Reason,
			Count:    d.Count,
		})
	}

	return &pb.Finding{
		Id:        f.ID,
		Rule:      f.Rule,
		Severity:  f.Severity,
		TenantId:  f.TenantID,
		Container: f.Container,
		BackendId: f.BackendID,
		Subject:   f.Subject,
		State:     state,
		Count:     f.Count,
		Evidence: &pb.Evidence{
			Flows:  flows,
			Denies: denies,
		},
		FirstSeen: timestampProto(f.FirstSeen),
		LastSeen:  timestampProto(f.LastSeen),
	}
}
