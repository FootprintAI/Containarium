// Package threatdetect holds the background security-detection engine: the
// rule registry, the finding store, and delivery. See
// docs/architecture/continuous-threat-detection.md.
package threatdetect

import (
	"context"
	"encoding/json"
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
	// FirstSeen/LastSeen and Matched are set by the mining-behavior rule
	// (#2635) only; see pb.FlowEvidence.
	FirstSeen time.Time `json:"first_seen,omitzero"`
	LastSeen  time.Time `json:"last_seen,omitzero"`
	Matched   string    `json:"matched,omitempty"`
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

// CPUEvidence summarises a container's CPU usage over a detection window
// (#2635), in cores.
type CPUEvidence struct {
	MeanCores     float64 `json:"mean_cores"`
	PeakCores     float64 `json:"peak_cores"`
	WindowSeconds int64   `json:"window_seconds"`
	Samples       int32   `json:"samples"`
}

// ProcStartTicks is a process's start time as /proc/<pid>/stat field 22
// reports it: clock ticks (USER_HZ) since boot. It is constant for the life
// of a process (exec does not change it) and differs between two processes
// that held the same pid one after the other, which is what makes it the
// identity check against pid reuse (#2765). 0 means unknown. Only ever
// compared with another value read the same way, never converted to a
// wall-clock time.
type ProcStartTicks uint64

// ExecEvidence is one process exec attached to a finding (#2637, used by the
// miner-signature rule #2638): the host-side exec telemetry record,
// attributed to the container. PID/PPID are host-namespace ids.
type ExecEvidence struct {
	PID           uint32 `json:"pid"`
	PPID          uint32 `json:"ppid"`
	UID           uint32 `json:"uid"`
	Comm          string `json:"comm"`
	Filename      string `json:"filename"`
	Argv          string `json:"argv"`
	ArgvTruncated bool   `json:"argv_truncated,omitempty"`
	SHA256        string `json:"sha256,omitempty"`
	Matched       string `json:"matched,omitempty"`

	// StartTime is the process's start time read when the exec was decoded
	// (#2765); the kill refuses a pid whose start time no longer matches.
	// Not on the wire message: it is an internal identity check.
	StartTime ProcStartTicks `json:"start_time,omitempty"`
}

// ToProto renders the evidence as the wire message.
func (e ExecEvidence) ToProto() *pb.ExecEvidence {
	return &pb.ExecEvidence{
		Pid:           e.PID,
		Ppid:          e.PPID,
		Uid:           e.UID,
		Comm:          e.Comm,
		Filename:      e.Filename,
		Argv:          e.Argv,
		ArgvTruncated: e.ArgvTruncated,
		Sha256:        e.SHA256,
		Matched:       e.Matched,
	}
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
	CPU       []CPUEvidence      `json:"cpu,omitempty"`
	Execs     []ExecEvidence     `json:"execs,omitempty"`
}

// Capped returns a copy of e with each evidence kind truncated to the most
// recent EvidenceCap entries.
func (e Evidence) Capped() Evidence {
	out := Evidence{Flows: e.Flows, Denies: e.Denies, Configs: e.Configs, Listeners: e.Listeners, CPU: e.CPU, Execs: e.Execs}
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
	if len(out.CPU) > EvidenceCap {
		out.CPU = out.CPU[len(out.CPU)-EvidenceCap:]
	}
	if len(out.Execs) > EvidenceCap {
		out.Execs = out.Execs[len(out.Execs)-EvidenceCap:]
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
		CPU:       append(append([]CPUEvidence(nil), e.CPU...), more.CPU...),
		Execs:     append(append([]ExecEvidence(nil), e.Execs...), more.Execs...),
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

// FindingResponse records what the process responder (#2636) did about a
// finding: the action, its state, and when it was applied, expires and was
// released. Stored as the security_findings.response JSONB column, with
// enum names rather than numbers so the column reads in psql and survives
// the enums growing.
type FindingResponse struct {
	Action        pb.ProcessAction
	State         pb.ResponseState
	ProcessKilled bool
	// KilledPID is the host pid the responder last killed, Kills how many it
	// has killed for this finding, and KillSkipReason why the last attempted
	// kill did not happen. The webhook delivers them (#2775); see deliveryGate
	// for how a respawning miner is bounded.
	KilledPID      uint32
	Kills          uint32
	KillSkipReason pb.KillSkipReason
	AppliedAt      time.Time
	ExpiresAt      time.Time
	ReleasedAt     time.Time
	ReleasedBy     string
	Error          string
	// Container is the box this response is about (#2820): a shared
	// miner-signature finding gets one record per box, each delivered on its
	// own. See ResponseWriter for which box the stored finding shows.
	Container string
}

// findingResponseJSON is the storage encoding of FindingResponse.
type findingResponseJSON struct {
	Action        string    `json:"action"`
	State         string    `json:"state"`
	ProcessKilled bool      `json:"process_killed,omitempty"`
	KilledPID     uint32    `json:"killed_pid,omitempty"`
	Kills         uint32    `json:"kills,omitempty"`
	KillSkip      string    `json:"kill_skip_reason,omitempty"`
	AppliedAt     time.Time `json:"applied_at,omitzero"`
	ExpiresAt     time.Time `json:"expires_at,omitzero"`
	ReleasedAt    time.Time `json:"released_at,omitzero"`
	ReleasedBy    string    `json:"released_by,omitempty"`
	Error         string    `json:"error,omitempty"`
	Container     string    `json:"container,omitempty"`
}

// KeepKillOf makes the kill on record sticky (#2766, #2775): when prev has a
// kill and r (a write from a box that killed nothing, such as its release)
// has none, r takes prev's process_killed, latest pid, count and skip reason
// (or its lack of one: #2816, a skip r carries does not survive), so the
// stored response never says killed with pid 0 and a shared finding keeps
// another box's kill. A write that carries its own kill is left alone unless
// its count is lower than prev's: a stale kill (such as a release's fallback
// to its action row's pid) never rolls the count back. stickyResponseSQL
// does the same for the Postgres store in one UPDATE.
func (r *FindingResponse) KeepKillOf(prev *FindingResponse) {
	if prev == nil || !prev.ProcessKilled || r.ProcessKilled && r.Kills >= prev.Kills {
		return
	}
	r.ProcessKilled, r.KilledPID, r.Kills, r.KillSkipReason = true, prev.KilledPID, prev.Kills, prev.KillSkipReason
}

// skipName is the stored name of a skip reason; none stores nothing.
func skipName(r pb.KillSkipReason) string {
	if r == pb.KillSkipReason_KILL_SKIP_REASON_UNSPECIFIED {
		return ""
	}
	return r.String()
}

// MarshalJSON encodes enums by name.
func (r FindingResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(findingResponseJSON{
		Action: r.Action.String(), State: r.State.String(), ProcessKilled: r.ProcessKilled,
		KilledPID: r.KilledPID, Kills: r.Kills, KillSkip: skipName(r.KillSkipReason),
		AppliedAt: r.AppliedAt, ExpiresAt: r.ExpiresAt, ReleasedAt: r.ReleasedAt,
		ReleasedBy: r.ReleasedBy, Error: r.Error, Container: r.Container,
	})
}

// UnmarshalJSON decodes enums by name; an unknown name decodes to the
// UNSPECIFIED value rather than failing the whole finding read.
func (r *FindingResponse) UnmarshalJSON(b []byte) error {
	var j findingResponseJSON
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	*r = FindingResponse{
		Action:        pb.ProcessAction(pb.ProcessAction_value[j.Action]),
		State:         pb.ResponseState(pb.ResponseState_value[j.State]),
		ProcessKilled: j.ProcessKilled, KilledPID: j.KilledPID, Kills: j.Kills,
		KillSkipReason: pb.KillSkipReason(pb.KillSkipReason_value[j.KillSkip]),
		AppliedAt:      j.AppliedAt, ExpiresAt: j.ExpiresAt, ReleasedAt: j.ReleasedAt,
		ReleasedBy: j.ReleasedBy, Error: j.Error, Container: j.Container,
	}
	return nil
}

// ToProto converts the response to its wire form; nil for a nil receiver.
func (r *FindingResponse) ToProto() *pb.FindingResponse {
	if r == nil {
		return nil
	}
	return &pb.FindingResponse{
		Action:         r.Action,
		State:          r.State,
		ProcessKilled:  r.ProcessKilled,
		KilledPid:      r.KilledPID,
		Kills:          r.Kills,
		KillSkipReason: r.KillSkipReason,
		AppliedAt:      timestampProto(r.AppliedAt),
		ExpiresAt:      timestampProto(r.ExpiresAt),
		ReleasedAt:     timestampProto(r.ReleasedAt),
		ReleasedBy:     r.ReleasedBy,
		Error:          r.Error,
		Container:      r.Container,
	}
}

// ResponseWriter is what the process responder needs from a finding store
// beyond FindingSink/FindingReader: recording what it did. Both stores
// satisfy it.
type ResponseWriter interface {
	// SetResponse replaces the finding's response, emits the updated
	// finding on the event bus, hands it to the notifier (a response
	// transition is a webhook delivery, #2718), and returns it.
	// ErrFindingNotFound if id does not exist. The kill facts are sticky
	// (#2766, #2816): when the finding has a kill on record and r carries no
	// kill, or one with a lower count, the stored kill (process_killed, the
	// latest pid, the count and the skip reason) is kept whole in the same
	// write, as FindingResponse.KeepKillOf describes.
	SetResponse(ctx context.Context, id int64, r FindingResponse) (*Finding, error)
	// SetResponseHeld records box's response while another box of a shared
	// finding still holds an applied action (#2820): standing (that box's
	// APPLIED record) is what the finding stores and shows, so it never
	// reads RELEASED, EXPIRED or FAILED while a box is still throttled or
	// frozen, and box is what the webhook delivers, naming box.Container.
	// The kill on record stays sticky on both, as in SetResponse.
	SetResponseHeld(ctx context.Context, id int64, box, standing FindingResponse) (*Finding, error)
	// ResolveWithResponse records r and resolves the finding in one write:
	// the release of the last box holding it (#2820). It is one webhook
	// delivery, the resolve, carrying r (so the consumer learns both that
	// the box was released and that the finding resolved). When the finding
	// is no longer open, r is still recorded and delivered as SetResponse
	// would, and the error wraps ErrFindingNotOpen; ErrFindingNotFound when
	// id does not exist. Any other error does not say whether r was written:
	// the Postgres store reads the row back after its UPDATE, so a failed
	// read (or a failed SetResponse on the not-open path) can come after r
	// was recorded and the finding resolved, with nothing delivered. A
	// caller that must be sure re-reads the finding, or records r again (the
	// process responder does: SetResponse of the same record is harmless).
	ResolveWithResponse(ctx context.Context, id int64, r FindingResponse) (*Finding, error)
}

// ResponseDelivery is the finding a response write hands the webhook:
// stored as the store now has it, carrying box (the record of the box the
// write is about) as its response, with the kill on record kept as the store
// keeps it, and naming box.Container as the finding's container (#2820: the
// stored row keeps the box that first opened a shared finding, which says
// nothing about which box this delivery is for). A copy: later writes to
// the stored finding do not change it.
func ResponseDelivery(stored *Finding, box FindingResponse) *Finding {
	out := *stored
	box.KeepKillOf(stored.Response)
	out.Response = &box
	if box.Container != "" {
		out.Container = box.Container
	}
	return &out
}

// resolveDelivery is the finding a plain resolve (Resolve, not
// ResolveWithResponse) hands the webhook (#2835): the stored finding, naming
// the box of the response it carries, if any, so that every post carrying a
// response names that response's box at the top level. The stored row keeps
// the box that first opened a shared finding, which says nothing about the
// response. A copy.
func resolveDelivery(stored *Finding) *Finding {
	if stored.Response == nil {
		out := *stored
		return &out
	}
	return ResponseDelivery(stored, *stored.Response)
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
	// Rule narrows to one rule; unset (THREAT_RULE_ID_UNSPECIFIED) = any rule.
	Rule pb.ThreatRuleId
	// BackendID narrows to findings written by one backend; "" = any backend.
	BackendID string
	Limit     int // <= 0 or > 200 => default/cap 50/200
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
	// Response is what the process responder did about this finding, nil
	// when nothing acted on it (#2636).
	Response *FindingResponse
}

// clone copies Response separately so later changes cannot alter the snapshot's response.
func (f *Finding) clone() *Finding {
	snapshot := *f
	if f.Response != nil {
		response := *f.Response
		snapshot.Response = &response
	}
	return &snapshot
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
			SrcIp:     fl.SrcIP,
			DstIp:     fl.DstIP,
			SrcPort:   fl.SrcPort,
			DstPort:   fl.DstPort,
			Protocol:  fl.Protocol,
			Bytes:     fl.Bytes,
			Packets:   fl.Packets,
			FirstSeen: timestampProto(fl.FirstSeen),
			LastSeen:  timestampProto(fl.LastSeen),
			Matched:   fl.Matched,
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

	cpu := make([]*pb.CPUEvidence, 0, len(f.Evidence.CPU))
	for _, c := range f.Evidence.CPU {
		cpu = append(cpu, &pb.CPUEvidence{
			MeanCores:     c.MeanCores,
			PeakCores:     c.PeakCores,
			WindowSeconds: c.WindowSeconds,
			Samples:       c.Samples,
		})
	}

	execs := make([]*pb.ExecEvidence, 0, len(f.Evidence.Execs))
	for _, x := range f.Evidence.Execs {
		execs = append(execs, x.ToProto())
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
			Cpu:       cpu,
			Execs:     execs,
		},
		FirstSeen: timestampProto(f.FirstSeen),
		LastSeen:  timestampProto(f.LastSeen),
		Response:  f.Response.ToProto(),
	}
}
