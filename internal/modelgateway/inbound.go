package modelgateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/footprintai/containarium/internal/guardrail"
	"github.com/footprintai/containarium/internal/guardrailpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Inbound guardrail enforcement (#2367 slice B2;
// docs/architecture/guardrail-inbound-and-server-policy.md, "Enforcement in
// the gateway"). A model response is scanned when the server policy has at
// least one BLOCK rule for an inbound kind; otherwise the gateway behaves
// exactly as it did before this file existed. In scanned mode the whole
// response is held inside ModifyResponse, scanned once, and then either
// replayed unchanged or replaced by a typed error. Every failure to scan
// (engine down, unsupported kind, coverage gap, compressed or unrecognised
// body, held message over the byte limit) blocks: there is no fail-open
// switch, and the break-glass is an admin clearing the inbound rules.

const (
	// DefaultInboundHoldLimit bounds the held response. Past it the buffer
	// is discarded and the response blocked, so one long or hostile
	// response cannot pin memory per request.
	DefaultInboundHoldLimit = 8 << 20
	// DefaultInboundScanTimeout bounds one engine round trip.
	DefaultInboundScanTimeout = 15 * time.Second
	// InboundBlockType is the "type" of the error body a blocked response
	// receives, so a client can tell a guardrail block from an upstream error.
	InboundBlockType = "guardrail_inbound_block"
)

// InboundAuditSink receives one entry per blocked response. Kept an
// interface so the gateway has no dependency on internal/audit; the daemon
// adapts it onto audit.Store.Log. A failing sink never un-blocks a response.
type InboundAuditSink interface {
	RecordInboundBlock(ctx context.Context, b InboundBlock) error
}

// InboundBlock is the audit record of one block: attribution, the typed
// reason, kinds and counts. Never the flagged text, never the response body.
type InboundBlock struct {
	Tenant, SkillID, Provider, Model string
	Reason                           guardrail.InboundReason
	Kinds                            []pb.GuardrailKind
	Findings                         int
	EngineID                         string
	PolicyRevision                   int64
}

// InboundBlockBody is the error body a blocked response carries.
type InboundBlockBody struct {
	Error InboundBlockError `json:"error"`
}

// InboundBlockError names the block; kinds are the enum names without the
// GUARDRAIL_KIND_ prefix. No field carries response text.
type InboundBlockError struct {
	Type    string   `json:"type"`
	Reason  string   `json:"reason"`
	Kinds   []string `json:"kinds,omitempty"`
	Message string   `json:"message"`
}

// InboundStatus is the readout on /__gateway/status and the input a
// `code run` derives its scan status from.
type InboundStatus struct {
	// PolicySource is whether a policy provider is wired at all. False is
	// the standalone gateway: scanning is unavailable, visibly.
	PolicySource bool `json:"policy_source"`
	// Ready is false only while a wired provider has never answered (cold
	// start); the gateway refuses model calls until it has.
	Ready bool `json:"ready"`
	// Scanning is whether the last known policy has an inbound BLOCK rule.
	Scanning       bool              `json:"scanning"`
	PolicyRevision int64             `json:"policy_revision"`
	Blocked        map[string]uint64 `json:"blocked"`         // by reason
	BlockedByKind  map[string]uint64 `json:"blocked_by_kind"` // by finding kind
}

// inboundMode is what one request runs under, resolved from the policy.
type inboundMode struct {
	scan     bool
	kinds    []pb.GuardrailKind // inbound kinds with a BLOCK rule
	policy   *pb.GuardrailPolicy
	revision int64
}

func modeOf(p *pb.ServerGuardrailPolicy) inboundMode {
	m := inboundMode{policy: p.GetPolicy(), revision: p.GetRevision()}
	seen := map[pb.GuardrailKind]bool{}
	for _, r := range p.GetPolicy().GetRules() {
		k := r.GetKind()
		if !isInboundKind(k) || r.GetAction() != pb.GuardrailAction_GUARDRAIL_ACTION_BLOCK || seen[k] {
			continue
		}
		seen[k] = true
		m.kinds = append(m.kinds, k)
	}
	m.scan = len(m.kinds) > 0
	return m
}

func isInboundKind(k pb.GuardrailKind) bool {
	return k == pb.GuardrailKind_GUARDRAIL_KIND_UNSAFE_CODE || k == pb.GuardrailKind_GUARDRAIL_KIND_PROMPT_INJECTION
}

// inbound is the gateway's inbound-scan state: the policy source, the last
// known policy, and the block counters.
type inbound struct {
	provider guardrailpolicy.PolicyProvider
	engine   guardrail.Engine
	audit    InboundAuditSink
	limit    int
	timeout  time.Duration
	logger   *log.Logger

	mu            sync.Mutex
	loaded        bool                      // a read has succeeded (policy or ErrNotConfigured)
	policy        *pb.ServerGuardrailPolicy // last known; nil = not configured
	blocked       map[guardrail.InboundReason]uint64
	blockedByKind map[pb.GuardrailKind]uint64
}

func newInbound(cfg Config) *inbound {
	in := &inbound{
		provider: cfg.InboundPolicy, engine: cfg.InboundEngine, audit: cfg.InboundAudit,
		limit: cfg.InboundHoldLimit, timeout: cfg.InboundScanTimeout, logger: cfg.Logger,
		blocked: map[guardrail.InboundReason]uint64{}, blockedByKind: map[pb.GuardrailKind]uint64{},
	}
	if in.limit <= 0 {
		in.limit = DefaultInboundHoldLimit
	}
	if in.timeout <= 0 {
		in.timeout = DefaultInboundScanTimeout
	}
	switch {
	case in.provider == nil:
		in.logger.Printf("model-gateway: inbound guardrail scan unavailable: no policy provider wired; model traffic through this gateway is unscanned (UNSCANNED_NO_POLICY)")
	case in.engine == nil:
		in.logger.Printf("model-gateway: inbound guardrail scan: policy provider wired but no engine; an inbound BLOCK rule will block every response (engine_error)")
	default:
		in.logger.Printf("model-gateway: inbound guardrail scan: enforced once the server policy carries an inbound BLOCK rule; hold limit %d bytes", in.limit)
	}
	return in
}

// ready is false only on cold start: a provider is wired and has never
// answered, so the gateway cannot know whether any tenant has an active
// rule. The health check attempts the read itself, so readiness turns on
// as soon as the store answers, not on the next model call.
func (in *inbound) ready(ctx context.Context) bool {
	if in.provider == nil {
		return true
	}
	in.mu.Lock()
	loaded := in.loaded
	in.mu.Unlock()
	if loaded {
		return true
	}
	_, ok := in.resolve(ctx)
	return ok
}

// resolve reads the policy for one request. ok=false means the policy is
// unavailable and the call must be refused: cold start, or a read error
// while the last known policy had an active rule. A read error never turns
// an active policy off, and ErrNotConfigured is the only "no policy".
func (in *inbound) resolve(ctx context.Context) (mode inboundMode, ok bool) {
	if in.provider == nil {
		return inboundMode{}, true
	}
	p, err := in.provider.Get(ctx)
	in.mu.Lock()
	defer in.mu.Unlock()
	switch {
	case err == nil:
		in.loaded, in.policy = true, p
	case errors.Is(err, guardrailpolicy.ErrNotConfigured):
		in.loaded, in.policy = true, nil
	default:
		in.logger.Printf("model-gateway: inbound guardrail policy read failed (last known revision kept): %v", err)
		if !in.loaded {
			return inboundMode{}, false
		}
		m := modeOf(in.policy)
		return m, !m.scan
	}
	return modeOf(in.policy), true
}

func (in *inbound) status() InboundStatus {
	st := InboundStatus{PolicySource: in.provider != nil, Blocked: map[string]uint64{}, BlockedByKind: map[string]uint64{}}
	in.mu.Lock()
	defer in.mu.Unlock()
	st.Ready = in.provider == nil || in.loaded
	m := modeOf(in.policy)
	st.Scanning, st.PolicyRevision = m.scan, m.revision
	for r, n := range in.blocked {
		st.Blocked[r.String()] = n
	}
	for k, n := range in.blockedByKind {
		st.BlockedByKind[kindName(k)] = n
	}
	return st
}

// inboundSubject is who a block is attributed to.
type inboundSubject struct {
	tenant, skill, provider, model string
}

// block records one block: log line, counters, audit entry. It returns the
// typed error the response is replaced with. The audit write failing is
// logged and counted, never a reason to let the response through.
func (in *inbound) block(sub inboundSubject, dec guardrail.InboundDecision, revision int64) *inboundBlockError {
	in.logger.Printf("model-gateway: INBOUND-BLOCK tenant=%s skill=%s provider=%s model=%s reason=%s kinds=%v findings=%d gaps=%d engine=%q revision=%d",
		sub.tenant, sub.skill, sub.provider, sub.model, dec.Reason, kindNames(dec.Kinds), dec.Findings, dec.Gaps, dec.EngineID, revision)
	in.mu.Lock()
	in.blocked[dec.Reason]++
	for _, k := range dec.Kinds {
		in.blockedByKind[k]++
	}
	in.mu.Unlock()
	if in.audit != nil {
		ctx, cancel := context.WithTimeout(context.Background(), in.timeout)
		defer cancel()
		err := in.audit.RecordInboundBlock(ctx, InboundBlock{
			Tenant: sub.tenant, SkillID: sub.skill, Provider: sub.provider, Model: sub.model,
			Reason: dec.Reason, Kinds: dec.Kinds, Findings: dec.Findings, EngineID: dec.EngineID, PolicyRevision: revision,
		})
		if err != nil {
			in.logger.Printf("model-gateway: inbound block audit write failed (response stays blocked): %v", err)
		}
	}
	return &inboundBlockError{dec: dec}
}

// inboundBlockError is returned from ModifyResponse so the proxy's
// ErrorHandler writes the typed body instead of the model output.
type inboundBlockError struct{ dec guardrail.InboundDecision }

func (e *inboundBlockError) Error() string {
	return "guardrail inbound block: " + e.dec.Reason.String()
}

func writeInboundBlock(w http.ResponseWriter, status int, dec guardrail.InboundDecision) {
	body := InboundBlockBody{Error: InboundBlockError{
		Type: InboundBlockType, Reason: dec.Reason.String(), Kinds: kindNames(dec.Kinds),
		Message: fmt.Sprintf("model response blocked by the inbound guardrail (%s); no model output was delivered", dec.Reason),
	}}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func kindName(k pb.GuardrailKind) string { return strings.TrimPrefix(k.String(), "GUARDRAIL_KIND_") }

func kindNames(ks []pb.GuardrailKind) []string {
	if len(ks) == 0 {
		return nil
	}
	out := make([]string, 0, len(ks))
	for _, k := range ks {
		out = append(out, kindName(k))
	}
	return out
}

// inboundRequest is one scanned request: the mode it resolved and who to
// attribute a block to.
type inboundRequest struct {
	in   *inbound
	mode inboundMode
	sub  inboundSubject
}

// enforce is the ModifyResponse pre-stage in scanned mode. It holds the
// whole response (JSON or event stream) to its end, scans it once, and on a
// clean result restores the held bytes unchanged for the existing path to
// meter and normalise as today. Any other outcome returns the block error.
// Because the hold completes before ModifyResponse returns, the proxy has
// committed nothing to the client, so a block is a real error status and a
// stream is never half-opened.
func (ir *inboundRequest) enforce(resp *http.Response) error {
	fail := func(dec guardrail.InboundDecision) error {
		_ = resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(nil))
		return ir.in.block(ir.sub, dec, ir.mode.revision)
	}
	// An unscannable body cannot pass a gate that claims to scan. The
	// transport already decodes gzip the upstream chose on its own; a
	// Content-Encoding still present means the bytes are opaque to us.
	if resp.Header.Get("Content-Encoding") != "" {
		return fail(guardrail.InboundBlocked(guardrail.InboundReasonCoverageGap))
	}
	ct := resp.Header.Get("Content-Type")
	streaming := strings.Contains(ct, "text/event-stream")
	if !streaming && !strings.Contains(ct, "application/json") {
		return fail(guardrail.InboundBlocked(guardrail.InboundReasonCoverageGap))
	}
	held, err := io.ReadAll(io.LimitReader(resp.Body, int64(ir.in.limit)+1))
	if err != nil {
		return fail(guardrail.InboundBlocked(guardrail.InboundReasonEngineError))
	}
	if len(held) > ir.in.limit {
		// The buffer is dropped with this frame; none of it is released.
		return fail(guardrail.InboundBlocked(guardrail.InboundReasonOverLimit))
	}
	var units []*pb.GuardrailTextUnit
	if streaming {
		units = inboundUnitsSSE(held)
	} else {
		units = inboundUnitsJSON(held)
	}
	if dec := ir.scan(resp.Request.Context(), units); dec.Blocked {
		return fail(dec)
	}
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(held))
	return nil
}

// scan runs the engine over the units under the resolved policy. A unit
// that is not valid UTF-8 is a coverage gap, as in guardrail.LoadUnits: a
// lenient decode would hand the engine quietly corrupted text.
func (ir *inboundRequest) scan(ctx context.Context, units []*pb.GuardrailTextUnit) guardrail.InboundDecision {
	if ir.in.engine == nil {
		return guardrail.InboundBlocked(guardrail.InboundReasonEngineError)
	}
	for _, u := range units {
		if !utf8.ValidString(u.GetText()) {
			return guardrail.InboundBlocked(guardrail.InboundReasonCoverageGap)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, ir.in.timeout)
	defer cancel()
	resp, err := ir.in.engine.Scan(ctx, &pb.GuardrailScanRequest{Units: units, Kinds: ir.mode.kinds})
	return guardrail.DecideInbound(resp, err, ir.mode.policy)
}
