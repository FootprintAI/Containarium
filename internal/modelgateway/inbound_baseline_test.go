package modelgateway

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/guardrail"
	"github.com/footprintai/containarium/internal/guardrailpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Baseline response scan (#2736, slice A of #2575): with no admin policy the
// gateway scans responses against the baseline rule table, log-only. The key
// material below is synthetic filler, never a real key.

var (
	fakeKeyHeader = "-----BEGIN " + "RSA PRIVATE KEY-----"
	fakeKeyBody   = fakeKeyHeader + "\nMIIEFAKEFAKEFAKEFAKE\n-----END " + "RSA PRIVATE KEY-----"
	fakeAWSID     = "AKIA" + "FAKEFAKEFAKEFAKE"
)

// newBaselineHarness is a gateway whose policy store answers "not
// configured": a fresh install.
func newBaselineHarness(t *testing.T, prov string, up upstreamFn) *inboundHarness {
	t.Helper()
	h := newInboundHarness(t, prov, up, nil)
	h.provider.set(nil, guardrailpolicy.ErrNotConfigured)
	return h
}

// detectionsAll waits for every request the harness served to finish on the
// gateway side, then flushes the audit queue. The baseline scan runs when the
// proxy closes the body, which can be after a client holding a full
// Content-Length body has already returned; the END lifecycle line is logged
// only once ServeHTTP is done.
func (h *inboundHarness) detectionsAll() []InboundDetection {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for strings.Count(h.logs.String(), " END ") < int(h.hits.Load()) {
		if time.Now().After(deadline) {
			h.t.Fatalf("gateway did not finish %d request(s)", h.hits.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.gw.FlushInboundAudit(ctx); err != nil {
		h.t.Fatalf("flush audit: %v", err)
	}
	return h.audit.allDetections()
}

func TestBaseline_NoPolicy_SeededKeyIsFlaggedAndAudited(t *testing.T) {
	cases := []struct {
		name, prov, body string
		upstream         func(string) upstreamFn
		rule             guardrail.BaselineRuleID
	}{
		{"anthropic json pem", "anthropic", anthropicText("your key:\n" + fakeKeyBody), jsonUpstream, guardrail.BaselineRulePEMPrivateKey},
		{"openai json aws id in tool call", "openai", openAIToolCall(`{"env":"AWS_ACCESS_KEY_ID=` + fakeAWSID + `"}`), jsonUpstream, guardrail.BaselineRuleAWSAccessKeyID},
		{"gemini json pem", "gemini", geminiText(fakeKeyBody), jsonUpstream, guardrail.BaselineRulePEMPrivateKey},
		// The header is split across stream chunks; the scan reassembles it.
		{"anthropic stream pem split", "anthropic", anthropicTextStream("ok -----BEGIN RSA ", "PRIVATE KEY-----\nMIIEFAKE"), sseUpstream, guardrail.BaselineRulePEMPrivateKey},
		{"openai stream aws id split", "openai", oaiToolChunks(`{"k":"AKIA`, `FAKEFAKEFAKEFAKE"}`), sseUpstream, guardrail.BaselineRuleAWSAccessKeyID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newBaselineHarness(t, tc.prov, tc.upstream(tc.body))
			resp, got := h.call(`{"model":"m"}`)
			// Log-only: the response reaches the client.
			if resp.StatusCode != 200 {
				t.Fatalf("status = %d body %q, want 200 pass-through", resp.StatusCode, got)
			}
			if !strings.Contains(string(got), "PRIVATE KEY") && !strings.Contains(string(got), "FAKEFAKE") {
				t.Fatalf("model output did not reach the client: %q", got)
			}
			dets := h.detectionsAll()
			if len(dets) != 1 {
				t.Fatalf("detections = %+v, want exactly one", dets)
			}
			d := dets[0]
			if d.RuleID != tc.rule || d.Kind != pb.GuardrailKind_GUARDRAIL_KIND_SECRET || d.Action != guardrail.BaselineActionLog || d.Matches < 1 {
				t.Errorf("detection = %+v, want rule %s kind SECRET action log", d, tc.rule)
			}
			if d.Tenant != "tenant-a" || d.SkillID != "skill-1" || d.Provider != tc.prov {
				t.Errorf("detection attribution = %+v", d)
			}
			// Never the matched text: not in the audit record, not in the log.
			if b, _ := json.Marshal(d); strings.Contains(string(b), "FAKE") || strings.Contains(string(b), "BEGIN") {
				t.Errorf("matched text leaked into the audit record: %s", b)
			}
			if strings.Contains(h.logs.String(), "FAKE") || strings.Contains(h.logs.String(), "BEGIN RSA") {
				t.Errorf("matched text leaked into the gateway log")
			}
			if !strings.Contains(h.logs.String(), "INBOUND-BASELINE") {
				t.Errorf("no baseline detection log line: %q", h.logs.String())
			}
			if n := len(h.audit.all()); n != 0 {
				t.Errorf("log-only baseline wrote %d block entries", n)
			}
			if h.engine.Calls() != 0 {
				t.Errorf("baseline must use its own rule table, not the policy engine")
			}
			if st := h.gw.InboundStatus(); st.BaselineDetections[string(tc.rule)] != 1 {
				t.Errorf("status baseline detections = %v", st.BaselineDetections)
			}
		})
	}
}

func TestBaseline_NoPolicy_CleanResponseWritesNothing(t *testing.T) {
	body := anthropicText("all clear")
	h := newBaselineHarness(t, "anthropic", jsonUpstream(body))
	resp, got := h.call(`{"model":"m"}`)
	if resp.StatusCode != 200 || string(got) != body {
		t.Fatalf("status = %d body %q, want the upstream body unchanged", resp.StatusCode, got)
	}
	if dets := h.detectionsAll(); len(dets) != 0 {
		t.Errorf("clean response produced detections: %+v", dets)
	}
}

// The baseline never holds a response: the first streamed event reaches the
// client while the upstream is still mid-stream, and the scan runs at the end.
func TestBaseline_StreamIsNotHeldBack(t *testing.T) {
	release := make(chan struct{})
	firstEvent := anthropicTextStream("hello ")
	rest := anthropicTextStream(fakeKeyHeader)
	h := newBaselineHarness(t, "anthropic", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, firstEvent)
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-time.After(10 * time.Second):
		}
		_, _ = io.WriteString(w, rest)
	})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()

	// The request and the first event share one deadline, so a hold at any
	// point (headers or body) fails the test while the upstream is parked.
	type first struct {
		resp *http.Response
		br   *bufio.Reader
		line string
		err  error
	}
	gotFirst := make(chan first, 1)
	go func() {
		req, _ := http.NewRequest("POST", h.srv.URL+h.path, strings.NewReader(`{"model":"m"}`))
		req.Header.Set("Authorization", "Bearer "+h.tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			gotFirst <- first{err: err}
			return
		}
		br := bufio.NewReader(resp.Body)
		line, err := br.ReadString('\n')
		gotFirst <- first{resp: resp, br: br, line: line, err: err}
	}()
	var f first
	select {
	case f = <-gotFirst:
	case <-time.After(3 * time.Second):
		t.Fatal("first streamed event was held back by the baseline scan")
	}
	if f.err != nil {
		t.Fatal(f.err)
	}
	defer f.resp.Body.Close()
	if f.resp.StatusCode != 200 || !strings.Contains(f.line, "message_start") {
		t.Fatalf("status = %d first line = %q, want 200 and the first upstream event", f.resp.StatusCode, f.line)
	}
	br := f.br
	if dets := h.audit.allDetections(); len(dets) != 0 {
		t.Fatalf("detection recorded before the stream ended: %+v", dets)
	}

	close(release)
	restBody, _ := io.ReadAll(br)
	if !strings.Contains(string(restBody), "PRIVATE KEY") {
		t.Fatalf("rest of the stream did not reach the client unchanged: %q", restBody)
	}
	dets := h.detectionsAll()
	if len(dets) != 1 || dets[0].RuleID != guardrail.BaselineRulePEMPrivateKey {
		t.Fatalf("detections after the stream ended = %+v, want one PEM detection", dets)
	}
}

// Log-only never blocks: a response past the scan buffer limit passes
// through whole and is counted as unscanned, with no detection invented.
func TestBaseline_OverLimitPassesThroughAndIsCounted(t *testing.T) {
	body := anthropicText(strings.Repeat("x", 4096) + fakeKeyHeader)
	h := newInboundHarness(t, "anthropic", jsonUpstream(body), func(c *Config) { c.InboundHoldLimit = 1024 })
	h.provider.set(nil, guardrailpolicy.ErrNotConfigured)
	resp, got := h.call(`{"model":"m"}`)
	if resp.StatusCode != 200 || string(got) != body {
		t.Fatalf("status = %d len %d, want 200 and the whole body", resp.StatusCode, len(got))
	}
	if dets := h.detectionsAll(); len(dets) != 0 {
		t.Errorf("over-limit response produced detections: %+v", dets)
	}
	if st := h.gw.InboundStatus(); st.BaselineUnscanned != 1 {
		t.Errorf("baseline unscanned = %d, want 1", st.BaselineUnscanned)
	}
}

// With an admin policy present the baseline is off and the admin path is
// unchanged: a secret in the response is not the inbound policy's business
// (no detection, no block), and an inbound hit is still held and blocked.
func TestBaseline_AdminPolicyPathUnchanged(t *testing.T) {
	policies := []struct {
		name   string
		policy *pb.ServerGuardrailPolicy
	}{
		{"inbound block policy", inboundBlockPolicy()},
		{"outbound rules only", blockPolicy(pb.GuardrailKind_GUARDRAIL_KIND_SECRET)},
		{"empty policy", &pb.ServerGuardrailPolicy{Policy: &pb.GuardrailPolicy{}, Revision: 3}},
	}
	for _, p := range policies {
		t.Run(p.name+"/secret passes, no detection", func(t *testing.T) {
			body := anthropicText(fakeKeyBody)
			h := newInboundHarness(t, "anthropic", jsonUpstream(body), nil)
			h.provider.set(p.policy, nil)
			resp, got := h.call(`{"model":"m"}`)
			if resp.StatusCode != 200 || string(got) != body {
				t.Fatalf("status = %d body %q, want 200 and the upstream body", resp.StatusCode, got)
			}
			if dets := h.detectionsAll(); len(dets) != 0 {
				t.Errorf("baseline ran under an admin policy: %+v", dets)
			}
			if n := len(h.audit.all()); n != 0 {
				t.Errorf("admin path wrote %d block entries for a clean inbound scan", n)
			}
		})
	}
	t.Run("inbound hit still blocked", func(t *testing.T) {
		h := newInboundHarness(t, "anthropic", jsonUpstream(anthropicText(injectionText+" "+fakeKeyHeader)), nil)
		resp, got := h.call(`{"model":"m"}`)
		h.assertBlocked(resp, got, guardrail.InboundReasonFinding, "ignore all previous instructions")
		if dets := h.detectionsAll(); len(dets) != 0 {
			t.Errorf("baseline ran under an admin policy: %+v", dets)
		}
		if h.engine.Calls() != 1 {
			t.Errorf("engine calls = %d, want 1", h.engine.Calls())
		}
	})
}

// The standalone gateway has no policy source at all; the baseline belongs
// to the "no admin policy in the store" case, so nothing changes there.
func TestBaseline_NoProviderIsUnchanged(t *testing.T) {
	h := newInboundHarness(t, "anthropic", jsonUpstream(anthropicText(fakeKeyBody)), func(c *Config) { c.InboundPolicy = nil })
	if resp, _ := h.call(`{"model":"m"}`); resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if dets := h.detectionsAll(); len(dets) != 0 {
		t.Errorf("detections without a policy source: %+v", dets)
	}
}
