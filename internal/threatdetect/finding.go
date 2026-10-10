// Package threatdetect holds the background security-detection engine: the
// rule registry, the finding store, and delivery. See
// docs/architecture/continuous-threat-detection.md.
package threatdetect

import (
	"errors"
	"slices"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// ErrFindingNotFound reports that Get/Resolve was called with an id that
// doesn't exist. Both FindingStore and MemFindingStore return this exact
// sentinel (wrapped, checked with errors.Is) rather than leaking a
// backend-specific not-found signal (pgx.ErrNoRows for FindingStore) past
// the store boundary — callers like ThreatDetectionServer.ResolveFinding
// map it to codes.NotFound without knowing which backend is in play.
var ErrFindingNotFound = errors.New("finding not found")

// ErrFindingNotOpen reports that Resolve was called on a finding that
// exists but isn't currently open (already resolved). Distinct from
// ErrFindingNotFound so callers can map the two to different response
// codes (NotFound vs. FailedPrecondition).
var ErrFindingNotOpen = errors.New("finding is not open")

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

// ConfigEvidence is one configuration directive whose effective value
// violated policy (#2424): which file, which directive, what value, and
// whether the platform re-asserted its managed configuration in the same
// pass.
type ConfigEvidence struct {
	Path       string `json:"path"`
	Directive  string `json:"directive"`
	Value      string `json:"value"`
	Remediated bool   `json:"remediated"`
	Note       string `json:"note,omitempty"`
}

// ListenerEvidence is one listening socket held by an SSH server that is
// not the box's distro sshd service (#2439).
type ListenerEvidence struct {
	Port        uint32 `json:"port"`
	BindAddress string `json:"bind_address"`
	PID         uint32 `json:"pid"`
	Binary      string `json:"binary"`
	Note        string `json:"note,omitempty"`
}

// Evidence bundles the flow, deny and configuration records that triggered
// a finding. It is the named struct written into the
// security_findings.evidence JSONB column — a storage encoding, never an
// ad-hoc map.
type Evidence struct {
	Flows     []FlowEvidence     `json:"flows,omitempty"`
	Denies    []DenyEvidence     `json:"denies,omitempty"`
	Configs   []ConfigEvidence   `json:"configs,omitempty"`
	Listeners []ListenerEvidence `json:"listeners,omitempty"`
}

// Capped returns a copy of e with each evidence kind truncated to the most
// recent EvidenceCap entries.
func (e Evidence) Capped() Evidence {
	out := Evidence{Flows: e.Flows, Denies: e.Denies, Configs: e.Configs, Listeners: e.Listeners}
	if len(out.Flows) > EvidenceCap {
		out.Flows = out.Flows[len(out.Flows)-EvidenceCap:]
	}
	if len(out.Denies) > EvidenceCap {
		out.Denies = out.Denies[len(out.Denies)-EvidenceCap:]
	}
	if len(out.Configs) > EvidenceCap {
		out.Configs = out.Configs[len(out.Configs)-EvidenceCap:]
	}
	if len(out.Listeners) > EvidenceCap {
		out.Listeners = out.Listeners[len(out.Listeners)-EvidenceCap:]
	}
	return out
}

// merged returns e followed by more, for the upsert paths that append a
// re-fire's evidence onto an open finding's.
// maxSeverity returns the more severe of a and b. A deduped repeat can only
// raise an open finding's severity, never lower it: a box that was MEDIUM
// (tampering undone) and is now HIGH (still permissive) must escalate, while
// a later quieter pass must not hide that it was once worse.
func maxSeverity(a, b pb.ThreatSeverity) pb.ThreatSeverity {
	if b > a {
		return b
	}
	return a
}

func (e Evidence) merged(more Evidence) Evidence {
	return Evidence{
		Flows:     append(append([]FlowEvidence(nil), e.Flows...), more.Flows...),
		Denies:    append(append([]DenyEvidence(nil), e.Denies...), more.Denies...),
		Configs:   mergeConfigEvidence(e.Configs, more.Configs),
		Listeners: append(append([]ListenerEvidence(nil), e.Listeners...), more.Listeners...),
	}
}

// mergeConfigEvidence appends the entries of more that old does not already
// hold. Config evidence is a state snapshot, not an event: a box that stays
// permissive re-reports the identical entry every reconcile pass, and
// appending each repeat would fill the capped list with copies and push out
// anything that differs. A repeat still bumps the finding's count and
// last-seen; the evidence grows only when something changed.
func mergeConfigEvidence(old, more []ConfigEvidence) []ConfigEvidence {
	out := append([]ConfigEvidence(nil), old...)
	for _, c := range more {
		if !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	return out
}

// FindingState is the lifecycle state of a Finding.
type FindingState string

const (
	FindingStateOpen     FindingState = "open"
	FindingStateResolved FindingState = "resolved"
)

// ListFilter narrows FindingStore.List / MemFindingStore.List (#1643). Zero
// values mean "no filter on this field" — Severity's zero value is
// THREAT_SEVERITY_UNSPECIFIED, which no real finding has, so an unset
// filter matches every severity rather than none. TenantID empty means
// "every tenant" — callers enforce the RBAC scoping (admin-only for that
// case) before reaching the store, same division of responsibility
// ListPentestFindings uses.
type ListFilter struct {
	Severity pb.ThreatSeverity // exact match; unset = any severity
	TenantID string
	Since    time.Time
	State    FindingState // "" = any state
	Limit    int          // <= 0 or > 200 => default/cap 50/200
}

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

	configs := make([]*pb.ConfigEvidence, 0, len(f.Evidence.Configs))
	for _, c := range f.Evidence.Configs {
		configs = append(configs, &pb.ConfigEvidence{
			Path:       c.Path,
			Directive:  c.Directive,
			Value:      c.Value,
			Remediated: c.Remediated,
			Note:       c.Note,
		})
	}

	listeners := make([]*pb.ListenerEvidence, 0, len(f.Evidence.Listeners))
	for _, l := range f.Evidence.Listeners {
		listeners = append(listeners, &pb.ListenerEvidence{
			Port:        l.Port,
			BindAddress: l.BindAddress,
			Pid:         l.PID,
			Binary:      l.Binary,
			Note:        l.Note,
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
			Flows:     flows,
			Denies:    denies,
			Configs:   configs,
			Listeners: listeners,
		},
		FirstSeen: timestampProto(f.FirstSeen),
		LastSeen:  timestampProto(f.LastSeen),
	}
}
