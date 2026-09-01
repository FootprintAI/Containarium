package threatdetect

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeConfigSource is an in-memory WebhookConfigSource for tests.
type fakeConfigSource struct {
	mu     sync.Mutex
	values map[string]string
}

func newFakeConfigSource(url, secret string) *fakeConfigSource {
	return &fakeConfigSource{values: map[string]string{
		webhookURLConfigKey:    url,
		webhookSecretConfigKey: secret,
	}}
}

func (f *fakeConfigSource) Get(_ context.Context, key string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.values[key]
	if !ok || v == "" {
		return "", fmt.Errorf("no value for %s", key)
	}
	return v, nil
}

func testFinding(severity pb.ThreatSeverity) *Finding {
	return &Finding{
		ID:       1,
		Rule:     pb.ThreatRuleId_THREAT_RULE_ID_BAD_DESTINATION,
		Severity: severity,
		TenantID: "tenant-a",
		Subject:  "203.0.113.7",
		State:    FindingStateOpen,
		Count:    1,
	}
}

// waitFor polls cond until it's true or the timeout elapses, failing the
// test on timeout. Delivery is asynchronous (queue + worker goroutine), so
// tests can't assert on it synchronously after Notify returns.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", timeout)
}

func TestWebhookNotifier_SeverityThreshold(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tests := []struct {
		name     string
		severity pb.ThreatSeverity
		wantHit  bool
	}{
		{"unspecified skipped", pb.ThreatSeverity_THREAT_SEVERITY_UNSPECIFIED, false},
		{"low skipped", pb.ThreatSeverity_THREAT_SEVERITY_LOW, false},
		{"medium delivered", pb.ThreatSeverity_THREAT_SEVERITY_MEDIUM, true},
		{"high delivered", pb.ThreatSeverity_THREAT_SEVERITY_HIGH, true},
		{"critical delivered", pb.ThreatSeverity_THREAT_SEVERITY_CRITICAL, true},
	}

	cfg := newFakeConfigSource(srv.URL, "")
	n := NewWebhookNotifier(cfg, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n.Start(ctx)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := atomic.LoadInt32(&hits)
			n.Notify(testFinding(tt.severity))
			if tt.wantHit {
				waitFor(t, time.Second, func() bool { return atomic.LoadInt32(&hits) > before })
			} else {
				time.Sleep(50 * time.Millisecond)
				if atomic.LoadInt32(&hits) != before {
					t.Fatalf("expected no delivery for severity %v, but webhook was hit", tt.severity)
				}
			}
		})
	}
}

func TestWebhookNotifier_HMACSignature(t *testing.T) {
	const secret = "shh-its-a-secret"
	var gotSig string
	var gotBody []byte
	done := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-Containarium-Signature")
		gotBody = make([]byte, r.ContentLength)
		_, _ = r.Body.Read(gotBody)
		w.WriteHeader(http.StatusOK)
		select {
		case done <- struct{}{}:
		default:
		}
	}))
	defer srv.Close()

	cfg := newFakeConfigSource(srv.URL, secret)
	n := NewWebhookNotifier(cfg, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n.Start(ctx)

	n.Notify(testFinding(pb.ThreatSeverity_THREAT_SEVERITY_HIGH))

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("webhook was never hit")
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(gotBody)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if gotSig != want {
		t.Fatalf("signature mismatch: got %q want %q", gotSig, want)
	}
}

func TestWebhookNotifier_NoWebhookConfigured_NoOp(t *testing.T) {
	cfg := newFakeConfigSource("", "")
	n := NewWebhookNotifier(cfg, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n.Start(ctx)

	// Should not panic or block; there's simply nothing to assert on the
	// network side since no URL is configured.
	n.Notify(testFinding(pb.ThreatSeverity_THREAT_SEVERITY_CRITICAL))
	time.Sleep(50 * time.Millisecond)
}

func TestWebhookNotifier_RetriesOnFailureThenSucceeds(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n < 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := newFakeConfigSource(srv.URL, "")
	n := NewWebhookNotifier(cfg, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n.Start(ctx)

	n.Notify(testFinding(pb.ThreatSeverity_THREAT_SEVERITY_HIGH))
	waitFor(t, 2*time.Second, func() bool { return atomic.LoadInt32(&attempts) >= 2 })
}

func TestWebhookNotifier_DeadWebhookNeverBlocksNotify(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block // hang until the test closes it
	}))
	// LIFO order matters here: srv.Close() blocks until every in-flight
	// handler returns, and the handler above blocks on <-block. Registering
	// close(block) AFTER srv.Close() means it runs FIRST during unwind —
	// unblocking any handler still stuck mid-request before Close() waits on
	// it. The reverse order deadlocks whenever the delivery worker actually
	// reaches the handler before the test's own goroutine finishes (racy,
	// but real: it reproduced under -tags=integration's extra scheduler
	// contention from concurrent Postgres tests).
	defer srv.Close()
	defer close(block)

	cfg := newFakeConfigSource(srv.URL, "")
	n := NewWebhookNotifier(cfg, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n.Start(ctx)

	// Fill the queue well past capacity; every call must return immediately
	// even though the one in-flight delivery is stuck against the hanging
	// server. A dead/slow webhook must never make the detection hot path
	// (the caller of Notify) wait.
	done := make(chan struct{})
	go func() {
		for i := 0; i < notifierQueueCap*2; i++ {
			n.Notify(testFinding(pb.ThreatSeverity_THREAT_SEVERITY_CRITICAL))
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Notify blocked — a dead webhook must never block the caller")
	}
}

func TestWebhookNotifier_NilFinding_NoPanic(t *testing.T) {
	cfg := newFakeConfigSource("http://example.invalid", "")
	n := NewWebhookNotifier(cfg, nil)
	n.Notify(nil)
}
