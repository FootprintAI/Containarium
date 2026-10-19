package sshban

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/sentinel/sshsession"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

type captureRecorder struct {
	mu   sync.Mutex
	recs []sshsession.Record
	err  error
}

func (c *captureRecorder) Record(r sshsession.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	c.recs = append(c.recs, r)
	return nil
}

func (c *captureRecorder) snapshot() []sshsession.Record {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]sshsession.Record(nil), c.recs...)
}

// runOnce queues events, then runs one tick and shuts down, returning what was
// written. Run is single-goroutine, so this is deterministic.
func runOnce(t *testing.T, cfg AuditConfig, feed func(a *AuditRecorder), sweep func()) []sshsession.Record {
	t.Helper()
	rec := &captureRecorder{}
	cfg.Out = rec
	if cfg.Listener == 0 {
		cfg.Listener = pb.SSHBanListener_SSH_BAN_LISTENER_MAIN
	}
	n := 0
	cfg.NewID = func() string { n++; return "id-" + strconv.Itoa(n) }
	cfg.Now = func() time.Time { return time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC) }
	a := NewAuditRecorder(cfg)
	feed(a)
	ctx, cancel := context.WithCancel(context.Background())
	ticks := make(chan time.Time, 1)
	ticks <- time.Time{}
	done := make(chan struct{})
	go func() { a.Run(ctx, ticks, sweep); close(done) }()
	// The tick is consumed or the queue drained by the time cancel's final
	// drain runs; cancel after giving Run the chance to take the tick.
	for len(ticks) > 0 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	return rec.snapshot()
}

func TestAuditRecorder_WritesBanAndSummaryRecordsThatValidate(t *testing.T) {
	until := time.Date(2026, 10, 19, 0, 5, 0, 0, time.UTC)
	recs := runOnce(t, AuditConfig{}, func(a *AuditRecorder) {
		a.Emit(Event{Kind: "auth_failure", IP: "203.0.113.1", Failures: 1}) // per-failure events are ignored
		a.Emit(Event{Kind: EventWindowFailures, IP: "203.0.113.1", Failures: 3})
		a.Emit(Event{Kind: "ban", IP: "203.0.113.2", Failures: 100, ExpiresAt: until})
		a.Emit(Event{Kind: "expire", IP: "203.0.113.2", Failures: 100})
	}, nil)
	if len(recs) != 2 {
		t.Fatalf("records = %+v, want one auth_failed and one banned", recs)
	}
	f, b := recs[0], recs[1]
	if f.Phase != sshsession.SessionPhaseAuthFailed || f.ClientIP != "203.0.113.1" || f.FailureCount != 3 {
		t.Errorf("auth_failed record = %+v", f)
	}
	if b.Phase != sshsession.SessionPhaseBanned || b.ClientIP != "203.0.113.2" || b.FailureCount != 100 || b.BannedUntil == nil || !b.BannedUntil.Equal(until) {
		t.Errorf("banned record = %+v", b)
	}
	for _, r := range recs {
		if r.BanListener != pb.SSHBanListener_SSH_BAN_LISTENER_MAIN || r.Login != "" || r.Target != "" || r.Credential != (sshsession.Credential{}) {
			t.Errorf("record carries session identity or lacks the listener: %+v", r)
		}
		if _, err := sshsession.FromProto(sshsession.ToProto(r)); err != nil {
			t.Errorf("record would be rejected at ingest: %v (%+v)", err, r)
		}
	}
}

func TestAuditRecorder_RateCapFoldsSummariesIntoOneOverflowRecordAndNeverCapsBans(t *testing.T) {
	until := time.Date(2026, 10, 19, 0, 5, 0, 0, time.UTC)
	recs := runOnce(t, AuditConfig{MaxPerMinute: 2}, func(a *AuditRecorder) {
		for i := 0; i < 5; i++ { // 5 sources, 4 failures each; only 2 fit
			a.Emit(Event{Kind: EventWindowFailures, IP: "198.51.100." + strconv.Itoa(i+1), Failures: 4})
		}
		a.Emit(Event{Kind: "ban", IP: "198.51.100.9", Failures: 100, ExpiresAt: until})
	}, nil)
	var failed, banned, overflow []sshsession.Record
	for _, r := range recs {
		switch {
		case r.Phase == sshsession.SessionPhaseBanned:
			banned = append(banned, r)
		case r.ClientIP == "":
			overflow = append(overflow, r)
		default:
			failed = append(failed, r)
		}
	}
	if len(failed) != 2 || len(banned) != 1 || len(overflow) != 1 {
		t.Fatalf("failed/banned/overflow = %d/%d/%d, want 2/1/1: %+v", len(failed), len(banned), len(overflow), recs)
	}
	if overflow[0].SuppressedCount != 12 || overflow[0].FailureCount != 0 {
		t.Errorf("overflow = %+v, want suppressed_count 12 (3 sources x 4 failures)", overflow[0])
	}
	if _, err := sshsession.FromProto(sshsession.ToProto(overflow[0])); err != nil {
		t.Errorf("overflow record would be rejected at ingest: %v", err)
	}
}

// Emit runs under the guard's mutex during SSH authentication: a full queue
// must drop into the overflow count, never block.
func TestAuditRecorder_FullQueueDropsIntoOverflowAndEmitNeverBlocks(t *testing.T) {
	recs := runOnce(t, AuditConfig{QueueSize: 1}, func(a *AuditRecorder) {
		done := make(chan struct{})
		go func() {
			defer close(done)
			a.Emit(Event{Kind: EventWindowFailures, IP: "203.0.113.1", Failures: 2}) // queued
			a.Emit(Event{Kind: EventWindowFailures, IP: "203.0.113.2", Failures: 5}) // dropped
			a.Emit(Event{Kind: EventWindowFailures, IP: "203.0.113.3", Failures: 7}) // dropped
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("Emit blocked on a full queue")
		}
	}, nil)
	var overflow uint64
	for _, r := range recs {
		if r.ClientIP == "" {
			overflow += r.SuppressedCount
		}
	}
	if overflow != 12 {
		t.Fatalf("overflow suppressed = %d, want 12 (5+7 dropped): %+v", overflow, recs)
	}
}

func TestAuditRecorder_TickSweepsTheGuardAndAWriteErrorDoesNotStopIt(t *testing.T) {
	swept := 0
	runOnce(t, AuditConfig{}, func(*AuditRecorder) {}, func() { swept++ })
	if swept != 1 {
		t.Fatalf("sweep called %d times, want 1", swept)
	}

	rec := &captureRecorder{err: errors.New("disk full")}
	var logged []string
	a := NewAuditRecorder(AuditConfig{Out: rec, Listener: pb.SSHBanListener_SSH_BAN_LISTENER_MAIN,
		Logf: func(f string, args ...any) { logged = append(logged, f) }})
	a.Emit(Event{Kind: EventWindowFailures, IP: "203.0.113.1", Failures: 1})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a.Run(ctx, nil, nil) // returns after the final drain; must not panic or hang
	if len(logged) == 0 {
		t.Error("a failed write was not logged")
	}
}

// End to end with the real guard: failures below the budget surface as one
// summary when the window ends, a ban as one banned record.
func TestAuditRecorder_WithGuard(t *testing.T) {
	rec := &captureRecorder{}
	a := NewAuditRecorder(AuditConfig{Out: rec, Listener: pb.SSHBanListener_SSH_BAN_LISTENER_MAIN})
	g, now := fixture(t, func(c *Config) { c.Emit = a.Emit }) // MaxFailures 2

	_ = g.Check("203.0.113.1:1")
	g.Fail("203.0.113.1:1", "auth_failure")
	_ = g.Check("203.0.113.2:1")
	g.Fail("203.0.113.2:1", "auth_failure")
	g.Fail("203.0.113.2:1", "auth_failure")
	*now = now.Add(10 * time.Minute)

	ctx, cancel := context.WithCancel(context.Background())
	ticks := make(chan time.Time, 1)
	ticks <- time.Time{}
	done := make(chan struct{})
	go func() { a.Run(ctx, ticks, g.Sweep); close(done) }()
	for len(ticks) > 0 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done

	var f, b int
	for _, r := range rec.snapshot() {
		switch {
		case r.Phase == sshsession.SessionPhaseAuthFailed && r.ClientIP == "203.0.113.1" && r.FailureCount == 1:
			f++
		case r.Phase == sshsession.SessionPhaseBanned && r.ClientIP == "203.0.113.2" && r.FailureCount == 2:
			b++
		default:
			t.Errorf("unexpected record %+v", r)
		}
	}
	if f != 1 || b != 1 {
		t.Fatalf("auth_failed=%d banned=%d, want 1 each: %+v", f, b, rec.snapshot())
	}
}

// The records go through the real JSONL sink, and what the shipper later reads
// back from the file must still validate (its parseLine does json.Unmarshal and
// then FromProto(ToProto(rec))).
func TestAuditRecorder_FileSinkLinesSurviveTheShippersParse(t *testing.T) {
	path := t.TempDir() + "/records.jsonl"
	sink, err := sshsession.NewJSONLFileRecorder(path)
	if err != nil {
		t.Fatal(err)
	}
	until := time.Date(2026, 10, 19, 0, 5, 0, 0, time.UTC)
	a := NewAuditRecorder(AuditConfig{Out: sink, Listener: pb.SSHBanListener_SSH_BAN_LISTENER_ANONYMOUS, QueueSize: 1})
	a.Emit(Event{Kind: "ban", IP: "2001:db8::1", Failures: 100, ExpiresAt: until})
	a.Emit(Event{Kind: EventWindowFailures, IP: "203.0.113.1", Failures: 9}) // queue full: lands in the overflow record
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a.Run(ctx, nil, nil)
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("file has %d lines, want 2:\n%s", len(lines), data)
	}
	for _, line := range lines {
		var rec sshsession.Record
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatalf("line is not a Record: %v: %s", err, line)
		}
		if _, err := sshsession.FromProto(sshsession.ToProto(rec)); err != nil {
			t.Fatalf("the shipper would reject this line as malformed: %v: %s", err, line)
		}
		if rec.BanListener != pb.SSHBanListener_SSH_BAN_LISTENER_ANONYMOUS {
			t.Errorf("listener lost in the file: %s", line)
		}
	}
}
