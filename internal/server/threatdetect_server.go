package server

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/threatdetect"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// ThreatDetectionServer implements ThreatDetectionService. GetSentryStatus
// ships with #1640 (background detection loop); ListBadDestinations/
// AddBadDestination/RemoveBadDestination ship with #1641 (known-bad
// destination rule); ListFindings/ResolveFinding ship with #1643 (findings
// delivery + triage) — see docs/architecture/continuous-threat-detection.md.
type ThreatDetectionServer struct {
	pb.UnimplementedThreatDetectionServiceServer

	// engine is nil whenever sentryEnabled or ebpfAvailable is false — a
	// disabled or unavailable sentry never constructs one.
	engine *threatdetect.Engine

	sentryEnabled bool // CONTAINARIUM_THREAT_SENTRY=1

	// badDestRule is constructed independent of sentryEnabled/ebpfAvailable
	// — an operator can curate the known-bad-destination list before ever
	// flipping CONTAINARIUM_THREAT_SENTRY on. nil only if construction
	// itself failed (malformed embedded baseline list — a build-time bug,
	// not a runtime condition).
	badDestRule *threatdetect.BadDestinationRule

	// store backs ListFindings/ResolveFinding (#1643). Independent of
	// sentryEnabled/ebpfAvailable — an operator can triage findings a
	// now-disabled sentry already recorded. nil (both Postgres and the
	// in-memory fallback failed to construct) reports Unavailable rather
	// than panicking, same as badDestRule.
	store threatdetect.FindingReader

	// policies and responder back the process-policy RPCs (#2636); see
	// threatdetect_policy_server.go. Either may be nil.
	policies  *threatdetect.ProcessPolicyStore
	miningCfg *threatdetect.MiningThresholdsConfig
	responder *ProcessResponder

	// minerSigRule backs the miner-signature RPCs (#2638); like badDestRule
	// it exists whether or not the sentry is armed. See
	// threatdetect_minersig_server.go.
	minerSigRule *threatdetect.MinerSignatureRule

	mu                sync.Mutex // guards the fields below — SetUnavailable / SetCPUSamplerStatus run after Start()
	ebpfAvailable     bool       // eBPF object loaded (networkPolicyEnforcer != nil) AND still running
	unavailableReason string
	cpuSamplerStatus  string              // GetSentryStatus.cpu_sampler (#2645); "" until wired
	execTelemetry     execTelemetrySource // exec telemetry (#2637); nil until wired
}

// execTelemetrySource is what the server needs from the ExecWatcher (#2637):
// its status line, the kernel's lost count, and a subscription for
// StreamExecEvents. An interface so the handler is testable with a fake.
type execTelemetrySource interface {
	Status() string
	Lost() int64
	Subscribe(container string, since time.Duration, buffer int) (replay []ExecEventRecord, ch <-chan ExecEventRecord, cancel func())
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

// SetCPUSamplerStatus records which source feeds the mining-behavior
// rule's CPU samples (#2645) — "metrics-collector", "standalone (30s)" or
// "unavailable (<reason>)" — surfaced as GetSentryStatus.cpu_sampler.
func (s *ThreatDetectionServer) SetCPUSamplerStatus(status string) {
	s.mu.Lock()
	s.cpuSamplerStatus = status
	s.mu.Unlock()
}

// SetExecTelemetry wires the exec watcher (#2637): GetSentryStatus reports
// its Status as exec_telemetry and its Lost as exec_events_lost, and
// StreamExecEvents subscribes to it. nil (never constructed) reads as
// "unavailable (not started)".
func (s *ThreatDetectionServer) SetExecTelemetry(src execTelemetrySource) {
	s.mu.Lock()
	s.execTelemetry = src
	s.mu.Unlock()
}

// SetBadDestinationRule wires the known-bad-destination rule (#1641) into
// the server's List/Add/RemoveBadDestination handlers. Separate from
// NewThreatDetectionServer's constructor args because the rule is
// constructed independent of whether the sentry itself is enabled — an
// operator can curate the list before ever setting
// CONTAINARIUM_THREAT_SENTRY. nil is valid (construction failure); the
// three handlers report that explicitly rather than panicking.
func (s *ThreatDetectionServer) SetBadDestinationRule(r *threatdetect.BadDestinationRule) {
	s.badDestRule = r
}

// SetFindingStore wires the finding store (#1643) into ListFindings and
// ResolveFinding — *threatdetect.FindingStore (Postgres) or
// *threatdetect.MemFindingStore (degraded) both satisfy FindingReader. nil
// is valid (neither store could be constructed); the two handlers report
// that explicitly rather than panicking.
func (s *ThreatDetectionServer) SetFindingStore(store threatdetect.FindingReader) {
	s.store = store
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

// degradedNoPersistenceReason is the GetSentryStatus reason when findings
// (and therefore process-policy responses) have no Postgres persistence.
const degradedNoPersistenceReason = "DEGRADED (no persistence): responses disabled"

// GetSentryStatus reports the detection engine's on/off state and every
// registered rule's health. Never silently reports "no findings" for a
// backend that can't detect anything — DISABLED and UNAVAILABLE are
// distinct, explicit states from OK/DEGRADED (design doc).
func (s *ThreatDetectionServer) GetSentryStatus(ctx context.Context, _ *pb.GetSentryStatusRequest) (*pb.GetSentryStatusResponse, error) {
	// Reveals whether the eBPF threat sentry is enabled and, if not, why —
	// telling an attacker which detection is off (#1718).
	if err := auth.RequireScope(ctx, auth.ScopeSecurityRead); err != nil {
		return nil, err
	}
	return s.sentryStatus(), nil
}

// ListBadDestinations returns the merged baseline + operator-added
// known-bad-destination list the bad-destination rule (#1641) matches
// against.
func (s *ThreatDetectionServer) ListBadDestinations(ctx context.Context, _ *pb.ListBadDestinationsRequest) (*pb.ListBadDestinationsResponse, error) {
	// The blocklist's current entries. Reading is far less damaging than the
	// mutations gated in #1717, but it still shows what is being watched for.
	if err := auth.RequireScope(ctx, auth.ScopeSecurityRead); err != nil {
		return nil, err
	}
	if s.badDestRule == nil {
		return nil, status.Errorf(codes.Unavailable, "bad-destination rule not available")
	}
	entries := s.badDestRule.ListDestinations()
	out := make([]*pb.BadDestinationEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, &pb.BadDestinationEntry{Cidr: e.CIDR, Label: e.Label, Source: e.Source})
	}
	return &pb.ListBadDestinationsResponse{Entries: out}, nil
}

// AddBadDestination adds an operator-supplied entry, effective immediately
// and (when a DaemonConfigStore is configured) persisted across restarts —
// no daemon rebuild required.
func (s *ThreatDetectionServer) AddBadDestination(ctx context.Context, req *pb.AddBadDestinationRequest) (*pb.AddBadDestinationResponse, error) {
	// Platform-wide security control, so BOTH gates (#1717). security:write
	// matches this file's own neighbours (ListFindings/ResolveFinding); the
	// admin role is the additional one, because unlike a finding this is not
	// tenant data — the blocklist protects the whole fleet, and a scoped
	// non-admin token has no business editing it.
	//
	// Removing an entry is the dangerous direction: adding a bad CIDR is a
	// nuisance a tenant would notice immediately, while deleting one silently
	// disables a detection rule and nothing looks wrong afterwards.
	if err := auth.RequireScope(ctx, auth.ScopeSecurityWrite); err != nil {
		return nil, err
	}
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	if s.badDestRule == nil {
		return nil, status.Errorf(codes.Unavailable, "bad-destination rule not available")
	}
	if req.GetCidr() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "cidr is required")
	}
	entry, err := s.badDestRule.AddDestination(ctx, req.GetCidr(), req.GetLabel())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	return &pb.AddBadDestinationResponse{
		Entry: &pb.BadDestinationEntry{Cidr: entry.CIDR, Label: entry.Label, Source: entry.Source},
	}, nil
}

// RemoveBadDestination removes a previously operator-added entry. Baseline
// entries cannot be removed — see BadDestinationRule.RemoveDestination.
func (s *ThreatDetectionServer) RemoveBadDestination(ctx context.Context, req *pb.RemoveBadDestinationRequest) (*pb.RemoveBadDestinationResponse, error) {
	// Platform-wide security control, so BOTH gates (#1717). security:write
	// matches this file's own neighbours (ListFindings/ResolveFinding); the
	// admin role is the additional one, because unlike a finding this is not
	// tenant data — the blocklist protects the whole fleet, and a scoped
	// non-admin token has no business editing it.
	//
	// Removing an entry is the dangerous direction: adding a bad CIDR is a
	// nuisance a tenant would notice immediately, while deleting one silently
	// disables a detection rule and nothing looks wrong afterwards.
	if err := auth.RequireScope(ctx, auth.ScopeSecurityWrite); err != nil {
		return nil, err
	}
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	if s.badDestRule == nil {
		return nil, status.Errorf(codes.Unavailable, "bad-destination rule not available")
	}
	if req.GetCidr() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "cidr is required")
	}
	if err := s.badDestRule.RemoveDestination(ctx, req.GetCidr()); err != nil {
		if isBadDestNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "%v", err)
		}
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	return &pb.RemoveBadDestinationResponse{}, nil
}

// ListFindings lists security findings, most recently seen first.
// Tenant-scoped the same way ContainerServer.ListContainers scopes by
// username: a non-admin caller's tenant_id filter is forced to their own
// subject, and an explicit different tenant_id is denied — findings are the
// same "who can see whose stuff" boundary as containers.
func (s *ThreatDetectionServer) ListFindings(ctx context.Context, req *pb.ListFindingsRequest) (*pb.ListFindingsResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeSecurityRead); err != nil {
		return nil, err
	}
	if s.store == nil {
		return nil, status.Errorf(codes.Unavailable, "finding store not available")
	}
	subject, roles, ok := auth.SubjectFromGRPCContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no authenticated subject")
	}
	tenantID := req.GetTenantId()
	if !auth.HasRole(roles, auth.RoleAdmin) {
		if tenantID != "" && tenantID != subject {
			return nil, status.Error(codes.PermissionDenied, "not authorized for this tenant")
		}
		tenantID = subject
	}

	filter := threatdetect.ListFilter{
		Severity: req.GetSeverity(),
		TenantID: tenantID,
		Limit:    int(req.GetLimit()),
	}
	if req.GetState() != pb.FindingState_FINDING_STATE_UNSPECIFIED {
		filter.State = findingStateFromProto(req.GetState())
	}
	if req.GetSince() != nil {
		filter.Since = req.GetSince().AsTime()
	}

	findings, err := s.store.List(ctx, filter)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list findings: %v", err)
	}
	out := make([]*pb.Finding, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.ToProto())
	}
	return &pb.ListFindingsResponse{Findings: out}, nil
}

// ResolveFinding transitions an open finding to resolved. Any authenticated
// caller with security:write may resolve any finding — findings aren't
// filtered per-tenant here the way ListFindings is, since resolving one is
// an operator/on-call action, not a tenant self-service one (matches
// RemediateSecurityFinding's scoping, the closest existing precedent).
func (s *ThreatDetectionServer) ResolveFinding(ctx context.Context, req *pb.ResolveFindingRequest) (*pb.ResolveFindingResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeSecurityWrite); err != nil {
		return nil, err
	}
	if s.store == nil {
		return nil, status.Errorf(codes.Unavailable, "finding store not available")
	}
	if req.GetId() <= 0 {
		return nil, status.Errorf(codes.InvalidArgument, "id is required")
	}
	f, err := s.store.Resolve(ctx, req.GetId())
	if err != nil {
		switch {
		case errors.Is(err, threatdetect.ErrFindingNotFound):
			return nil, status.Errorf(codes.NotFound, "%v", err)
		case errors.Is(err, threatdetect.ErrFindingNotOpen):
			return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
		default:
			return nil, status.Errorf(codes.Internal, "resolve finding: %v", err)
		}
	}
	return &pb.ResolveFindingResponse{Finding: f.ToProto()}, nil
}

// findingStateFromProto converts the wire enum to the store's string-typed
// state — the store's FindingState is a Go string type (matches the
// security_findings.state column), not the proto enum.
func findingStateFromProto(s pb.FindingState) threatdetect.FindingState {
	switch s {
	case pb.FindingState_FINDING_STATE_OPEN:
		return threatdetect.FindingStateOpen
	case pb.FindingState_FINDING_STATE_RESOLVED:
		return threatdetect.FindingStateResolved
	default:
		return ""
	}
}

// isBadDestNotFound reports whether err is BadDestinationRule.RemoveDestination's
// "not found among operator-added entries" case, so RemoveBadDestination can
// map it to codes.NotFound instead of InvalidArgument. Matched by message
// content rather than a sentinel error: threatdetect intentionally returns
// plain fmt.Errorf here (see rule_baddest.go) since this is the only caller
// that needs to distinguish it.
func isBadDestNotFound(err error) bool {
	return err != nil && strings.Contains(err.Error(), "not found among operator-added entries")
}

// sentryStatus computes GetSentryStatus's response without the auth gate,
// for in-process callers: the sentry-health loop (#2634) reads it every tick
// and uses Reason verbatim as its finding's subject, so the finding and
// `containarium security sentry status` always name the same fault.
func (s *ThreatDetectionServer) sentryStatus() *pb.GetSentryStatusResponse {
	s.mu.Lock()
	ebpfAvailable, unavailableReason := s.ebpfAvailable, s.unavailableReason
	s.mu.Unlock()

	switch {
	case !s.sentryEnabled:
		return &pb.GetSentryStatusResponse{
			State:  pb.SentryState_SENTRY_STATE_DISABLED,
			Reason: "CONTAINARIUM_THREAT_SENTRY is not set",
		}
	case !ebpfAvailable:
		reason := unavailableReason
		if reason == "" {
			reason = "eBPF object not loaded"
		}
		return &pb.GetSentryStatusResponse{
			State:  pb.SentryState_SENTRY_STATE_UNAVAILABLE,
			Reason: reason,
		}
	case s.engine == nil:
		// Enabled + available implies an engine was constructed; this is a
		// wiring bug in dual_server.go, not a runtime condition an operator
		// caused — surfaced as UNAVAILABLE rather than a 500, since it's the
		// same "nothing is watching" fact from the operator's point of view.
		return &pb.GetSentryStatusResponse{
			State:  pb.SentryState_SENTRY_STATE_UNAVAILABLE,
			Reason: "sentry engine not constructed",
		}
	}

	s.mu.Lock()
	cpuSampler := s.cpuSamplerStatus
	execSrc := s.execTelemetry
	s.mu.Unlock()
	if cpuSampler == "" {
		cpuSampler = cpuSamplerNotStartedStatus
	}
	execStatus, execLost := execTelemetryNotStartedStatus, int64(0)
	if execSrc != nil {
		execStatus, execLost = execSrc.Status(), execSrc.Lost()
	}

	degraded, ruleStatus := s.engine.Status()
	state := pb.SentryState_SENTRY_STATE_OK
	reason := ""
	if degraded {
		state = pb.SentryState_SENTRY_STATE_DEGRADED
		// The process responder (#2636) shares this condition: with no
		// persistence it cannot record what it changed, so it is ALERT-only.
		reason = degradedNoPersistenceReason
	}
	rules := make([]*pb.RuleStatus, 0, len(ruleStatus))
	reasons := []string{}
	if reason != "" {
		reasons = append(reasons, reason)
	}
	for _, r := range ruleStatus {
		rs := &pb.RuleStatus{Rule: r.Rule, Healthy: r.Healthy, LastError: r.LastError}
		if !r.LastErrorAt.IsZero() {
			rs.LastErrorAt = timestamppb.New(r.LastErrorAt)
		}
		rules = append(rules, rs)
		if !r.Healthy {
			// A panicking rule leaves the state OK (the others keep running)
			// but must still show up in the reason, or the status reads clean
			// while the sentry-health loop holds a finding open (#2634). The
			// loop's finding subject drops the ": <last_error>" tail.
			reasons = append(reasons, ruleUnhealthyPrefix(r.Rule)+": "+r.LastError)
		}
	}
	return &pb.GetSentryStatusResponse{
		State:          state,
		Reason:         strings.Join(reasons, "; "),
		Rules:          rules,
		CpuSampler:     cpuSampler,
		ExecTelemetry:  execStatus,
		ExecEventsLost: execLost,
	}
}

// StreamExecEvents streams attributed exec events from the host-side exec
// telemetry (#2637): a replay of the watcher's in-memory ring for `since`,
// then — with `follow` — live events until the client goes away. Admin +
// security:read, like the other fleet-wide security verbs: an exec stream
// shows every tenant's process names and arguments. UNAVAILABLE when exec
// telemetry is not running here (the reason is the status line); a
// subscriber that falls behind is disconnected with RESOURCE_EXHAUSTED
// rather than ever stalling the kernel ring consumer. When exec telemetry
// stops (daemon shutdown) or its consumer fails, an open --follow stream
// ends with UNAVAILABLE instead of holding up GracefulStop.
func (s *ThreatDetectionServer) StreamExecEvents(req *pb.StreamExecEventsRequest, stream pb.ThreatDetectionService_StreamExecEventsServer) error {
	ctx := stream.Context()
	if err := auth.RequireScope(ctx, auth.ScopeSecurityRead); err != nil {
		return err
	}
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return err
	}
	s.mu.Lock()
	src := s.execTelemetry
	s.mu.Unlock()
	if src == nil {
		return status.Errorf(codes.Unavailable, "exec telemetry %s", execTelemetryNotStartedStatus)
	}
	if st := src.Status(); st != execTelemetryOK {
		return status.Errorf(codes.Unavailable, "exec telemetry %s", st)
	}
	var since time.Duration
	if req.GetSince() != nil {
		since = req.GetSince().AsDuration()
	}
	replay, ch, cancel := src.Subscribe(req.GetContainer(), since, execSubscriberBuffer)
	defer cancel()
	for _, rec := range replay {
		if err := stream.Send(&pb.StreamExecEventsResponse{Event: execEventProto(rec)}); err != nil {
			return err
		}
	}
	if !req.GetFollow() {
		return nil
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case rec, ok := <-ch:
			if !ok {
				// The watcher closes a subscription for two reasons: exec
				// telemetry stopped (daemon shutdown, consumer failure — the
				// status has left "ok" first) or this subscriber fell behind.
				if st := src.Status(); st != execTelemetryOK {
					return status.Errorf(codes.Unavailable, "exec telemetry %s", st)
				}
				return status.Error(codes.ResourceExhausted, "exec-events subscriber fell behind and was dropped (the ring consumer never waits); reconnect")
			}
			if err := stream.Send(&pb.StreamExecEventsResponse{Event: execEventProto(rec)}); err != nil {
				return err
			}
		}
	}
}

// execEventProto renders one attributed exec record as the wire message.
func execEventProto(rec ExecEventRecord) *pb.ExecEvent {
	return &pb.ExecEvent{
		Container: rec.Container,
		TenantId:  rec.TenantID,
		At:        timestamppb.New(rec.At),
		Exec: &pb.ExecEvidence{
			Pid:           rec.Event.HostPID,
			Ppid:          rec.Event.PPID,
			Uid:           rec.Event.UID,
			Comm:          rec.Event.Comm,
			Filename:      rec.Event.Filename,
			Argv:          rec.Event.ArgvString(),
			ArgvTruncated: rec.Event.ArgvTruncated,
		},
	}
}
