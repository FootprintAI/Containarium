package audit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// Trenyx audit finding #4 (2026-09-16): the async writer paths (HTTP
// middleware, gRPC interceptor, event subscriber) logged a persistence
// failure and moved on, with nothing counting it — a row that was never
// written was otherwise undetectable. These tests prove both failure
// modes (a Log() error, and a full buffered channel dropping an entry
// before Log() was even attempted) now increment the shared counter.

func TestPersistFailureReport_StartsAtZero(t *testing.T) {
	ResetPersistFailuresForTest()
	r := GetPersistFailureReport()
	if r.Count != 0 {
		t.Fatalf("Count = %d, want 0", r.Count)
	}
	if !r.Since.IsZero() {
		t.Fatalf("Since = %v, want zero", r.Since)
	}
}

func TestPersistFailureReport_CountsAndLatchesFirstTimestamp(t *testing.T) {
	ResetPersistFailuresForTest()
	t.Cleanup(ResetPersistFailuresForTest)

	recordPersistFailure()
	first := GetPersistFailureReport()
	if first.Count != 1 {
		t.Fatalf("Count = %d, want 1", first.Count)
	}
	if first.Since.IsZero() {
		t.Fatal("Since is zero after the first failure, want a timestamp")
	}

	recordPersistFailure()
	recordPersistFailure()
	second := GetPersistFailureReport()
	if second.Count != 3 {
		t.Fatalf("Count = %d, want 3", second.Count)
	}
	if !second.Since.Equal(first.Since) {
		t.Fatalf("Since changed from %v to %v — it must latch to the FIRST failure, not the latest", first.Since, second.Since)
	}
}

// errAuditLogger always fails Log(), simulating a store outage — the
// failure mode explicitly named in the report ("failed audit writes are
// logged and not counted").
type errAuditLogger struct{}

func (errAuditLogger) Log(_ context.Context, _ *AuditEntry) error {
	return errors.New("simulated store failure")
}

func TestGRPCInterceptor_LogErrorRecordsPersistFailure(t *testing.T) {
	ResetPersistFailuresForTest()
	t.Cleanup(ResetPersistFailuresForTest)

	g := NewGRPCInterceptor()
	g.setLogger(errAuditLogger{})

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(auth.MDKeyUsername, "alice"))
	handler := func(ctx context.Context, req interface{}) (interface{}, error) { return "ok", nil }
	if _, err := g.Unary()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/x/Y"}, handler); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if GetPersistFailureReport().Count >= 1 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("persist-failure count never reached 1 after a Log() error; got %d", GetPersistFailureReport().Count)
}

// blockingAuditLogger blocks inside Log() until the test releases it —
// used to deterministically fill GRPCInterceptor's buffered channel so
// the channel-full drop path (the SECOND failure mode named in the
// report) is exercised rather than raced.
type blockingAuditLogger struct {
	proceed chan struct{}
}

func (b *blockingAuditLogger) Log(_ context.Context, _ *AuditEntry) error {
	<-b.proceed
	return nil
}

func TestGRPCInterceptor_ChannelFullRecordsPersistFailure(t *testing.T) {
	ResetPersistFailuresForTest()
	t.Cleanup(ResetPersistFailuresForTest)

	g := NewGRPCInterceptor()
	blocker := &blockingAuditLogger{proceed: make(chan struct{})}
	g.setLogger(blocker)
	defer close(blocker.proceed) // release the parked writer goroutine

	handler := func(ctx context.Context, req interface{}) (interface{}, error) { return "ok", nil }
	call := func() {
		_, _ = g.Unary()(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/x/Y"}, handler)
	}

	// First call is dequeued immediately by the writer goroutine and
	// blocks inside Log(), holding the "in flight" slot — the 256-entry
	// buffer starts fully free after this.
	call()
	time.Sleep(20 * time.Millisecond) // let the writer goroutine reach the blocking Log() call

	for i := 0; i < 256; i++ {
		call() // fills the buffer exactly
	}

	before := GetPersistFailureReport().Count
	call() // the 258th entry: buffer full, must be dropped and counted

	if got := GetPersistFailureReport().Count; got != before+1 {
		t.Fatalf("persist-failure count = %d, want %d — a channel-full drop must be counted", got, before+1)
	}
}
