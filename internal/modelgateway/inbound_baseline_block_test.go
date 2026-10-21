package modelgateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/guardrail"
	"github.com/footprintai/containarium/internal/guardrailpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Baseline BLOCK mode (#2738, slice C of #2575): with no admin policy and the
// baseline switched to BLOCK, a response is held, scanned with the baseline
// rules and blocked on a match, through the admin policy's hold-and-block
// path. Key material is synthetic filler.

type fakeBaselineMode struct {
	mu    sync.Mutex
	mode  pb.GuardrailBaselineMode
	err   error
	calls int
}

func (f *fakeBaselineMode) GetBaselineMode(context.Context) (*pb.GuardrailBaselineSetting, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return &pb.GuardrailBaselineSetting{Mode: f.mode, Revision: 1}, nil
}

func (f *fakeBaselineMode) set(mode pb.GuardrailBaselineMode, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mode, f.err = mode, err
}

const (
	modeLog   = pb.GuardrailBaselineMode_GUARDRAIL_BASELINE_MODE_LOG
	modeBlock = pb.GuardrailBaselineMode_GUARDRAIL_BASELINE_MODE_BLOCK
)

// newBaselineModeHarness is a fresh install (no admin policy) whose stored
// baseline mode is mode.
func newBaselineModeHarness(t *testing.T, prov string, up upstreamFn, mode pb.GuardrailBaselineMode, mut func(*Config)) (*inboundHarness, *fakeBaselineMode) {
	t.Helper()
	bm := &fakeBaselineMode{mode: mode}
	h := newInboundHarness(t, prov, up, func(c *Config) {
		c.InboundBaselineMode = bm
		if mut != nil {
			mut(c)
		}
	})
	h.provider.set(nil, guardrailpolicy.ErrNotConfigured)
	return h, bm
}

func decodeBlockBody(t *testing.T, body []byte) InboundBlockBody {
	t.Helper()
	var b InboundBlockBody
	if err := json.Unmarshal(body, &b); err != nil || b.Error.Type != InboundBlockType {
		t.Fatalf("body %q is not a typed inbound block (%v)", body, err)
	}
	return b
}

func TestBaselineBlock_SeededKeyIsBlockedAndAudited(t *testing.T) {
	cases := []struct {
		name, prov, body string
		upstream         func(string) upstreamFn
		rule             guardrail.BaselineRuleID
	}{
		{"anthropic json pem", "anthropic", anthropicText("your key:\n" + fakeKeyBody), jsonUpstream, guardrail.BaselineRulePEMPrivateKey},
		// The id is split across stream chunks: the held stream is reassembled.
		{"openai stream aws id split", "openai", oaiToolChunks(`{"k":"AKIA`, `FAKEFAKEFAKEFAKE"}`), sseUpstream, guardrail.BaselineRuleAWSAccessKeyID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := newBaselineModeHarness(t, tc.prov, tc.upstream(tc.body), modeBlock, nil)
			resp, got := h.call(`{"model":"m"}`)
			if resp.StatusCode != http.StatusBadGateway {
				t.Fatalf("status = %d body %q, want 502", resp.StatusCode, got)
			}
			b := decodeBlockBody(t, got)
			if b.Error.Reason != guardrail.InboundReasonFinding.String() || len(b.Error.Kinds) != 1 || b.Error.Kinds[0] != "SECRET" {
				t.Fatalf("block body = %+v, want reason finding, kinds [SECRET]", b.Error)
			}
			if strings.Contains(string(got), "FAKE") || strings.Contains(string(got), "BEGIN") {
				t.Fatalf("blocked response carried model output: %q", got)
			}
			dets := h.detectionsAll()
			if len(dets) != 1 || dets[0].RuleID != tc.rule || dets[0].Action != guardrail.BaselineActionBlock ||
				dets[0].Tenant != "tenant-a" || dets[0].Provider != tc.prov {
				t.Fatalf("detections = %+v, want one %s detection, action block, attributed", dets, tc.rule)
			}
			blocks := h.auditAll()
			if len(blocks) != 1 || blocks[0].Reason != guardrail.InboundReasonFinding || blocks[0].EngineID != BaselineEngineID ||
				len(blocks[0].Kinds) != 1 || blocks[0].Kinds[0] != pb.GuardrailKind_GUARDRAIL_KIND_SECRET {
				t.Fatalf("block entries = %+v, want one baseline finding on SECRET", blocks)
			}
			if h.engine.Calls() != 0 {
				t.Errorf("baseline block must use its own rule table, not the policy engine")
			}
			st := h.gw.InboundStatus()
			if st.BaselineMode != "block" || !st.Scanning || st.BaselineDetections[string(tc.rule)] != 1 || st.Blocked[guardrail.InboundReasonFinding.String()] != 1 {
				t.Errorf("status = mode %q scanning %v detections %v blocked %v", st.BaselineMode, st.Scanning, st.BaselineDetections, st.Blocked)
			}
			if strings.Contains(h.logs.String(), "FAKE") {
				t.Errorf("matched text leaked into the gateway log")
			}
		})
	}
}

func TestBaselineBlock_CleanResponsePassesUnchanged(t *testing.T) {
	body := anthropicText("all clear")
	h, _ := newBaselineModeHarness(t, "anthropic", jsonUpstream(body), modeBlock, nil)
	resp, got := h.call(`{"model":"m"}`)
	if resp.StatusCode != 200 || string(got) != body {
		t.Fatalf("status = %d body %q, want the upstream body unchanged", resp.StatusCode, got)
	}
	if dets, blocks := h.detectionsAll(), h.auditAll(); len(dets) != 0 || len(blocks) != 0 {
		t.Fatalf("clean response wrote detections %+v blocks %+v", dets, blocks)
	}
}

// Switching back to LOG restores log-only: the same response passes and is
// flagged with action log.
func TestBaselineBlock_SwitchToLogRestoresLogOnly(t *testing.T) {
	body := anthropicText(fakeKeyBody)
	h, bm := newBaselineModeHarness(t, "anthropic", jsonUpstream(body), modeBlock, nil)
	if resp, _ := h.call(`{"model":"m"}`); resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("BLOCK mode status = %d, want 502", resp.StatusCode)
	}
	bm.set(modeLog, nil)
	h.gw.InvalidateInboundPolicy()
	resp, got := h.call(`{"model":"m"}`)
	if resp.StatusCode != 200 || string(got) != body {
		t.Fatalf("LOG mode status = %d body %q, want the response delivered unchanged", resp.StatusCode, got)
	}
	dets := h.detectionsAll()
	if len(dets) != 2 || dets[0].Action != guardrail.BaselineActionBlock || dets[1].Action != guardrail.BaselineActionLog {
		t.Fatalf("detections = %+v, want one block then one log", dets)
	}
	if n := len(h.auditAll()); n != 1 {
		t.Fatalf("block entries = %d, want only the one from BLOCK mode", n)
	}
	if st := h.gw.InboundStatus(); st.BaselineMode != "log" || st.Scanning {
		t.Fatalf("status after LOG = mode %q scanning %v, want log and not scanning", st.BaselineMode, st.Scanning)
	}
}

// BLOCK mode inherits the hold path's fail-closed rows: a body over the hold
// limit, or one with a content encoding, is blocked, not passed unscanned.
func TestBaselineBlock_UnscannableIsBlocked(t *testing.T) {
	t.Run("over the hold limit", func(t *testing.T) {
		h, _ := newBaselineModeHarness(t, "anthropic", jsonUpstream(anthropicText(strings.Repeat("x", 4096))), modeBlock,
			func(c *Config) { c.InboundHoldLimit = 1024 })
		resp, got := h.call(`{"model":"m"}`)
		if resp.StatusCode != http.StatusBadGateway || decodeBlockBody(t, got).Error.Reason != guardrail.InboundReasonOverLimit.String() {
			t.Fatalf("status = %d body %q, want a 502 over_limit block", resp.StatusCode, got)
		}
		if st := h.gw.InboundStatus(); st.BaselineUnscanned != 0 {
			t.Fatalf("BLOCK mode counted baseline_unscanned = %d; it blocks instead", st.BaselineUnscanned)
		}
	})
	t.Run("unrecognised 2xx", func(t *testing.T) {
		h, _ := newBaselineModeHarness(t, "anthropic", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("here: " + fakeKeyBody))
		}, modeBlock, nil)
		resp, got := h.call(`{"model":"m"}`)
		if resp.StatusCode != http.StatusBadGateway || decodeBlockBody(t, got).Error.Reason != guardrail.InboundReasonCoverageGap.String() {
			t.Fatalf("status = %d body %q, want a 502 coverage_gap block", resp.StatusCode, got)
		}
		if strings.Contains(string(got), "FAKE") {
			t.Fatalf("blocked response carried model output: %q", got)
		}
	})
	t.Run("content encoded", func(t *testing.T) {
		h, _ := newBaselineModeHarness(t, "anthropic", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Encoding", "br")
			_, _ = w.Write([]byte("opaque"))
		}, modeBlock, nil)
		resp, got := h.call(`{"model":"m"}`)
		if resp.StatusCode != http.StatusBadGateway || decodeBlockBody(t, got).Error.Reason != guardrail.InboundReasonCoverageGap.String() {
			t.Fatalf("status = %d body %q, want a 502 coverage_gap block", resp.StatusCode, got)
		}
	})
}

// An upstream error the hold path passes through unscanned (non-2xx, not
// JSON or an event stream) is still teed and scanned in BLOCK mode, so BLOCK
// never records less than LOG: one detection with action log, no block.
func TestBaselineBlock_UpstreamErrorIsRecordedLikeLog(t *testing.T) {
	upstream := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("debug dump: " + fakeKeyBody))
	}
	for _, mode := range []pb.GuardrailBaselineMode{modeLog, modeBlock} {
		t.Run(mode.String(), func(t *testing.T) {
			h, _ := newBaselineModeHarness(t, "anthropic", upstream, mode, nil)
			resp, got := h.call(`{"model":"m"}`)
			if resp.StatusCode != http.StatusInternalServerError || !strings.Contains(string(got), "debug dump") {
				t.Fatalf("status = %d body %q, want the upstream error passed through", resp.StatusCode, got)
			}
			dets := h.detectionsAll()
			if len(dets) != 1 || dets[0].RuleID != guardrail.BaselineRulePEMPrivateKey || dets[0].Action != guardrail.BaselineActionLog {
				t.Fatalf("detections = %+v, want one pem detection with action log", dets)
			}
			if n := len(h.auditAll()); n != 0 {
				t.Fatalf("block entries = %d, want 0 (the response was delivered)", n)
			}
		})
	}
}

// gatedBaselineMode answers its first read with the mode it held when the
// read began, but only after the test releases it: a read in flight while
// an admin switches the mode.
type gatedBaselineMode struct {
	fakeBaselineMode
	entered, release chan struct{}
	once             sync.Once
}

func (g *gatedBaselineMode) GetBaselineMode(ctx context.Context) (*pb.GuardrailBaselineSetting, error) {
	s, err := g.fakeBaselineMode.GetBaselineMode(ctx)
	first := false
	g.once.Do(func() { first = true })
	if first {
		close(g.entered)
		<-g.release
	}
	return s, err
}

// With the policy cache ON, a read that began before a switch must not keep
// the stale mode cached: after the switch and the server's invalidation,
// the next call sees BLOCK.
func TestBaselineBlock_SwitchAppliesOnNextCallWithCache(t *testing.T) {
	g := &gatedBaselineMode{fakeBaselineMode: fakeBaselineMode{mode: modeLog}, entered: make(chan struct{}), release: make(chan struct{})}
	h := newInboundHarness(t, "anthropic", jsonUpstream(anthropicText(fakeKeyBody)), func(c *Config) {
		c.InboundBaselineMode = g
		c.InboundPolicyTTL = time.Minute
	})
	h.provider.set(nil, guardrailpolicy.ErrNotConfigured)

	first := make(chan int, 1)
	go func() {
		resp, _ := h.call(`{"model":"m"}`)
		first <- resp.StatusCode
	}()
	<-g.entered
	g.set(modeBlock, nil) // the admin's switch commits while the read is in flight
	h.gw.InvalidateInboundPolicy()
	close(g.release)
	if code := <-first; code != 200 {
		t.Fatalf("in-flight call status = %d, want 200 (it read LOG)", code)
	}
	if resp, _ := h.call(`{"model":"m"}`); resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("next call after the switch = %d, want 502: the stale LOG read was cached", resp.StatusCode)
	}
}

// A stored BLOCK under a configured policy with no inbound BLOCK rule (NONE)
// does nothing: no hold, no baseline scan.
func TestBaselineBlock_NonePolicyIgnoresMode(t *testing.T) {
	body := anthropicText(fakeKeyBody)
	h, _ := newBaselineModeHarness(t, "anthropic", jsonUpstream(body), modeBlock, nil)
	h.provider.set(blockPolicy(pb.GuardrailKind_GUARDRAIL_KIND_SECRET), nil)
	resp, got := h.call(`{"model":"m"}`)
	if resp.StatusCode != 200 || string(got) != body {
		t.Fatalf("status = %d body %q, want an unscanned pass-through", resp.StatusCode, got)
	}
	if dets, blocks := h.detectionsAll(), h.auditAll(); len(dets) != 0 || len(blocks) != 0 || h.engine.Calls() != 0 {
		t.Fatalf("NONE policy scanned: detections %+v blocks %+v engine calls %d", dets, blocks, h.engine.Calls())
	}
}

// A mode read error never loosens an active block: last known BLOCK refuses,
// last known LOG stays log-only, and a cold start with no successful read
// refuses rather than guessing.
func TestBaselineBlock_ModeReadError(t *testing.T) {
	body := anthropicText(fakeKeyBody)
	readErr := errors.New("connection refused")

	t.Run("last known block refuses", func(t *testing.T) {
		h, bm := newBaselineModeHarness(t, "anthropic", jsonUpstream(body), modeBlock, nil)
		if resp, _ := h.call(`{"model":"m"}`); resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("first call status = %d, want 502", resp.StatusCode)
		}
		bm.set(modeBlock, readErr)
		resp, got := h.call(`{"model":"m"}`)
		if resp.StatusCode != http.StatusServiceUnavailable || decodeBlockBody(t, got).Error.Reason != guardrail.InboundReasonPolicyUnavailable.String() {
			t.Fatalf("status = %d body %q, want a 503 policy_unavailable refusal", resp.StatusCode, got)
		}
	})
	t.Run("last known log passes log-only", func(t *testing.T) {
		h, bm := newBaselineModeHarness(t, "anthropic", jsonUpstream(body), modeLog, nil)
		if resp, _ := h.call(`{"model":"m"}`); resp.StatusCode != 200 {
			t.Fatalf("first call status = %d, want 200", resp.StatusCode)
		}
		bm.set(modeLog, readErr)
		if resp, got := h.call(`{"model":"m"}`); resp.StatusCode != 200 || string(got) != body {
			t.Fatalf("status = %d body %q, want log-only pass-through", resp.StatusCode, got)
		}
	})
	t.Run("cold start refuses", func(t *testing.T) {
		h, bm := newBaselineModeHarness(t, "anthropic", jsonUpstream(body), modeLog, nil)
		bm.set(modeLog, readErr)
		if resp, _ := h.call(`{"model":"m"}`); resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("cold start status = %d, want 503", resp.StatusCode)
		}
		if h.hits.Load() != 0 {
			t.Fatalf("a refused call reached the upstream")
		}
	})
}

// With an admin policy configured the stored BLOCK mode is unused: the admin
// path is unchanged and the baseline does not run.
func TestBaselineBlock_AdminPolicyIgnoresMode(t *testing.T) {
	body := anthropicText(fakeKeyBody)
	h, bm := newBaselineModeHarness(t, "anthropic", jsonUpstream(body), modeBlock, nil)
	h.provider.set(inboundBlockPolicy(), nil)
	resp, got := h.call(`{"model":"m"}`)
	if resp.StatusCode != 200 || string(got) != body {
		t.Fatalf("status = %d body %q, want the admin path's clean pass-through", resp.StatusCode, got)
	}
	if dets := h.detectionsAll(); len(dets) != 0 {
		t.Fatalf("baseline ran under an admin policy: %+v", dets)
	}
	if h.engine.Calls() != 1 {
		t.Fatalf("engine calls = %d, want 1 (the admin path scans)", h.engine.Calls())
	}
	bm.mu.Lock()
	reads := bm.calls
	bm.mu.Unlock()
	if reads != 0 {
		t.Fatalf("baseline mode read %d times under an admin policy, want 0", reads)
	}
}
