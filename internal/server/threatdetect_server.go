package server

import (
	"context"
	"sync"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/footprintai/containarium/internal/threatdetect"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// ThreatDetectionServer implements ThreatDetectionService. GetSentryStatus
// ships with #1640 (background detection loop); ListFindings/
// ResolveFinding/rule-config RPCs are added by later stories in the same
// umbrella (#1641-#1643) — see
// docs/architecture/continuous-threat-detection.md.
type ThreatDetectionServer struct {
	pb.UnimplementedThreatDetectionServiceServer

	// engine is nil whenever sentryEnabled or ebpfAvailable is false — a
	// disabled or unavailable sentry never constructs one.
	engine *threatdetect.Engine

	sentryEnabled bool // CONTAINARIUM_THREAT_SENTRY=1

	mu                sync.Mutex // guards the two fields below — SetUnavailable can flip them after Start()
	ebpfAvailable     bool       // eBPF object loaded (networkPolicyEnforcer != nil) AND still running
	unavailableReason string
}

// NewThreatDetectionServer builds the server. engine must be non-nil iff
// sentryEnabled && ebpfAvailable — the constructor doesn't re-derive that
// invariant, the daemon wiring (dual_server.go) is the one place that
// decides whether to construct an Engine at all. unavailableReason is
// surfaced verbatim on GetSentryStatus when !ebpfAvailable; it's ignored
// otherwise.
func NewThreatDetectionServer(engine *threatdetect.Engine, sentryEnabled, ebpfAvailable bool, unavailableReason string) *ThreatDetectionServer {
	return &ThreatDetectionServer{
		engine:            engine,
		sentryEnabled:     sentryEnabled,
		ebpfAvailable:     ebpfAvailable,
		unavailableReason: unavailableReason,
	}
}

// SetUnavailable flips the server to UNAVAILABLE after construction — for
// when the enforcer that was present at construction time (ebpfAvailable
// was computed true) later fails to actually start. Without this, a daemon
// that logged "enforcer failed to start, continuing without it" would still
// report sentry status OK: exactly the "silently detecting nothing" gap the
// design doc says to never allow.
func (s *ThreatDetectionServer) SetUnavailable(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ebpfAvailable = false
	s.unavailableReason = reason
}

// GetSentryStatus reports the detection engine's on/off state and every
// registered rule's health. Never silently reports "no findings" for a
// backend that can't detect anything — DISABLED and UNAVAILABLE are
// distinct, explicit states from OK/DEGRADED (design doc).
func (s *ThreatDetectionServer) GetSentryStatus(ctx context.Context, _ *pb.GetSentryStatusRequest) (*pb.GetSentryStatusResponse, error) {
	s.mu.Lock()
	ebpfAvailable, unavailableReason := s.ebpfAvailable, s.unavailableReason
	s.mu.Unlock()

	switch {
	case !s.sentryEnabled:
		return &pb.GetSentryStatusResponse{
			State:  pb.SentryState_SENTRY_STATE_DISABLED,
			Reason: "CONTAINARIUM_THREAT_SENTRY is not set",
		}, nil
	case !ebpfAvailable:
		reason := unavailableReason
		if reason == "" {
			reason = "eBPF object not loaded"
		}
		return &pb.GetSentryStatusResponse{
			State:  pb.SentryState_SENTRY_STATE_UNAVAILABLE,
			Reason: reason,
		}, nil
	case s.engine == nil:
		// Enabled + available implies an engine was constructed; this is a
		// wiring bug in dual_server.go, not a runtime condition an operator
		// caused — surfaced as UNAVAILABLE rather than a 500, since it's the
		// same "nothing is watching" fact from the operator's point of view.
		return &pb.GetSentryStatusResponse{
			State:  pb.SentryState_SENTRY_STATE_UNAVAILABLE,
			Reason: "sentry engine not constructed",
		}, nil
	}

	degraded, ruleStatus := s.engine.Status()
	state := pb.SentryState_SENTRY_STATE_OK
	reason := ""
	if degraded {
		state = pb.SentryState_SENTRY_STATE_DEGRADED
		reason = "FindingStore has no Postgres connection; findings are not persisted across a restart"
	}
	rules := make([]*pb.RuleStatus, 0, len(ruleStatus))
	for _, r := range ruleStatus {
		rs := &pb.RuleStatus{Rule: r.Rule, Healthy: r.Healthy, LastError: r.LastError}
		if !r.LastErrorAt.IsZero() {
			rs.LastErrorAt = timestamppb.New(r.LastErrorAt)
		}
		rules = append(rules, rs)
	}
	return &pb.GetSentryStatusResponse{State: state, Reason: reason, Rules: rules}, nil
}
