package modelgateway

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/footprintai/containarium/internal/guardrail"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Baseline response scan (#2736, slice A of #2575). When the policy store
// answers "not configured" the response is scanned against
// guardrail.BaselineRules, log-only. Unlike the admin-policy hold in
// inboundRequest.enforce, nothing is held: the body is teed to the client as
// it arrives, and the copy is scanned once the proxy has finished writing it
// (on Close), so a streamed response on a default install is not delayed.
// A detection is logged, counted and audited; it never blocks.

// baselineRequest is one response under the baseline.
type baselineRequest struct {
	in  *inbound
	sub inboundSubject
}

// watch wraps the final response body. It runs as the last step of
// ModifyResponse, so it sees exactly the bytes the client is sent.
func (br *baselineRequest) watch(resp *http.Response) {
	if resp.Body == nil || resp.Body == http.NoBody {
		return
	}
	// Encoded bytes are opaque to the rules; count, never block.
	if resp.Header.Get("Content-Encoding") != "" {
		br.in.baselineUnscanned.Add(1)
		return
	}
	resp.Body = &baselineTee{
		src: resp.Body, br: br, limit: br.in.limit,
		streaming: strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream"),
	}
}

// baselineTee passes reads through unchanged and keeps a bounded copy. Past
// the limit the copy is dropped (the response still flows) and the response
// is counted as unscanned.
type baselineTee struct {
	src       io.ReadCloser
	br        *baselineRequest
	limit     int
	streaming bool
	buf       bytes.Buffer
	over      bool
	once      sync.Once
}

func (t *baselineTee) Read(p []byte) (int, error) {
	n, err := t.src.Read(p)
	if n > 0 && !t.over {
		if t.buf.Len()+n > t.limit {
			t.over = true
			t.buf = bytes.Buffer{}
		} else {
			t.buf.Write(p[:n])
		}
	}
	return n, err
}

// Close is called by the proxy after the last byte was written to the
// client; the scan runs here, once.
func (t *baselineTee) Close() error {
	err := t.src.Close()
	t.once.Do(t.finish)
	return err
}

func (t *baselineTee) finish() {
	if t.over {
		t.br.in.baselineUnscanned.Add(1)
		return
	}
	if t.buf.Len() == 0 {
		return
	}
	var units []*pb.GuardrailTextUnit
	if t.streaming {
		units = inboundUnitsSSE(t.buf.Bytes())
	} else {
		units = inboundUnitsJSON(t.buf.Bytes())
	}
	for _, d := range guardrail.ScanBaseline(units) {
		t.br.in.detect(t.br.sub, d)
	}
	t.buf = bytes.Buffer{}
}

// detect records one baseline detection: a log line (ids and counts only),
// the counter, and a queued audit entry.
func (in *inbound) detect(sub inboundSubject, d guardrail.BaselineDetection) {
	in.logger.Printf("model-gateway: INBOUND-BASELINE tenant=%s skill=%s provider=%s model=%s rule=%s kind=%s action=%s matches=%d",
		sub.tenant, sub.skill, sub.provider, sub.model, d.RuleID, kindName(d.Kind), in.baselineAction, d.Matches)
	in.mu.Lock()
	in.baselineHits[d.RuleID]++
	in.mu.Unlock()
	in.enqueueAudit(auditJob{d: &InboundDetection{
		Tenant: sub.tenant, SkillID: sub.skill, Provider: sub.provider, Model: sub.model,
		RuleID: d.RuleID, Kind: d.Kind, Action: in.baselineAction, Matches: d.Matches,
	}})
}
