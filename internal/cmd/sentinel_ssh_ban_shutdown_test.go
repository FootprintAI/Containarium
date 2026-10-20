//go:build !windows && !containarium_client

package cmd

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/sentinel/sshban"
	"github.com/footprintai/containarium/internal/sentinel/sshsession"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

type shutdownSink struct {
	mu      sync.Mutex
	records []sshsession.Record
	closed  bool
	entered chan struct{}
	release chan struct{}
}

func (s *shutdownSink) Record(r sshsession.Record) error {
	if s.entered != nil {
		close(s.entered)
		<-s.release
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("write after close")
	}
	s.records = append(s.records, r)
	return nil
}

func (s *shutdownSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func (s *shutdownSink) snapshot() (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records), s.closed
}

func shutdownGuard(t *testing.T, now *time.Time, emit func(sshban.Event)) *sshban.Guard {
	t.Helper()
	g, err := sshban.New(sshban.Config{
		Listener: pb.SSHBanListener_SSH_BAN_LISTENER_MAIN, MaxFailures: 3,
		Duration: time.Minute, MaxEntries: 10, Now: func() time.Time { return *now }, Emit: emit,
	})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func startShutdownRecorder(a *sshban.AuditRecorder, sink *shutdownSink, ticks <-chan time.Time, g *sshban.Guard) (context.CancelFunc, <-chan struct{}) {
	ctx, cancel := context.WithCancel(context.Background())
	reopenDone := make(chan struct{})
	close(reopenDone)
	return cancel, startSSHBanAudit(ctx, a, ticks, g, func() {}, reopenDone, sink)
}

func shutdownDeadline(t *testing.T, stop func(), g *sshban.Guard, a *sshban.AuditRecorder, cancel context.CancelFunc, done <-chan struct{}) {
	t.Helper()
	ctx, end := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer end()
	returned := make(chan error, 1)
	go func() { returned <- shutdownSSHBanAudit(ctx, stop, g, a, cancel, done) }()
	select {
	case err := <-returned:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("shutdown = %v, want deadline exceeded", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown exceeded its deadline")
	}
}

func waitShutdown(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("blocked operation did not finish after release")
	}
}

func TestSSHBanShutdownFlushesOpenWindowAndClosesSink(t *testing.T) {
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	sink := &shutdownSink{}
	a := sshban.NewAuditRecorder(sshban.AuditConfig{Out: sink, Listener: pb.SSHBanListener_SSH_BAN_LISTENER_MAIN})
	g := shutdownGuard(t, &now, a.Emit)
	if err := g.Check("203.0.113.1:22"); err != nil {
		t.Fatal(err)
	}
	g.Fail("203.0.113.1:22", "auth_failure")
	cancel, done := startShutdownRecorder(a, sink, nil, g)
	ctx, end := context.WithTimeout(context.Background(), 2*time.Second)
	defer end()
	if err := shutdownSSHBanAudit(ctx, func() {}, g, a, cancel, done); err != nil {
		t.Fatal(err)
	}
	if count, closed := sink.snapshot(); count != 1 || !closed {
		t.Fatalf("normal shutdown wrote %d records; sink closed=%t", count, closed)
	}
}

func TestSSHBanShutdownDeadlineWithAlreadyBlockedSweepEmission(t *testing.T) {
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	sink := &shutdownSink{}
	a := sshban.NewAuditRecorder(sshban.AuditConfig{Out: sink, Listener: pb.SSHBanListener_SSH_BAN_LISTENER_MAIN})
	entered, release := make(chan struct{}), make(chan struct{})
	g := shutdownGuard(t, &now, func(e sshban.Event) {
		if e.Kind == sshban.EventWindowFailures {
			close(entered)
			<-release
		}
		a.Emit(e)
	})
	if err := g.Check("203.0.113.1:22"); err != nil {
		t.Fatal(err)
	}
	g.Fail("203.0.113.1:22", "auth_failure")
	now = now.Add(2 * time.Minute)
	ticks := make(chan time.Time, 1)
	cancel, done := startShutdownRecorder(a, sink, ticks, g)
	ticks <- now
	waitShutdown(t, entered) // sweep has acquired the guard and entered Emit
	shutdownDeadline(t, func() {}, g, a, cancel, done)
	if _, closed := sink.snapshot(); closed {
		t.Fatal("sink closed while the recorder was still in a sweep")
	}
	close(release)
	waitShutdown(t, done)
}

func TestSSHBanShutdownAbortAfterBlockedFinalSweep(t *testing.T) {
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	sink := &shutdownSink{}
	a := sshban.NewAuditRecorder(sshban.AuditConfig{Out: sink, Listener: pb.SSHBanListener_SSH_BAN_LISTENER_MAIN})
	entered, release := make(chan struct{}), make(chan struct{})
	g := shutdownGuard(t, &now, func(e sshban.Event) {
		if e.Kind == sshban.EventWindowFailures {
			close(entered)
			<-release
		}
		a.Emit(e)
	})
	if err := g.Check("203.0.113.1:22"); err != nil {
		t.Fatal(err)
	}
	g.Fail("203.0.113.1:22", "auth_failure")
	now = now.Add(2 * time.Minute)
	cancel, done := startShutdownRecorder(a, sink, nil, g)
	ctx, timeout := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- shutdownSSHBanAudit(ctx, func() {}, g, a, cancel, done) }()
	waitShutdown(t, entered) // final sweep is already inside Emit
	timeout()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("shutdown = %v, want context cancellation", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not stop waiting for the final sweep")
	}
	close(release)
	waitShutdown(t, done)
	if count, closed := sink.snapshot(); count != 0 || !closed {
		t.Fatalf("aborted final sweep wrote %d records; sink closed=%t", count, closed)
	}
}

func TestSSHBanShutdownDeadlineWithBlockedSinkWrite(t *testing.T) {
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	sink := &shutdownSink{entered: make(chan struct{}), release: make(chan struct{})}
	a := sshban.NewAuditRecorder(sshban.AuditConfig{Out: sink, Listener: pb.SSHBanListener_SSH_BAN_LISTENER_MAIN})
	g := shutdownGuard(t, &now, a.Emit)
	cancel, done := startShutdownRecorder(a, sink, nil, g)
	a.Emit(sshban.Event{Kind: "ban", IP: "203.0.113.1", Failures: 3, ExpiresAt: now.Add(time.Minute)})
	waitShutdown(t, sink.entered)
	shutdownDeadline(t, func() {}, g, a, cancel, done)
	if _, closed := sink.snapshot(); closed {
		t.Fatal("sink closed during an in-flight Record")
	}
	close(sink.release)
	waitShutdown(t, done)
	if count, closed := sink.snapshot(); count != 1 || !closed {
		t.Fatalf("released write produced %d records; sink closed=%t", count, closed)
	}
}

func TestSSHBanShutdownDeadlineWithBlockedControlStop(t *testing.T) {
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	sink := &shutdownSink{}
	a := sshban.NewAuditRecorder(sshban.AuditConfig{Out: sink, Listener: pb.SSHBanListener_SSH_BAN_LISTENER_MAIN})
	g := shutdownGuard(t, &now, a.Emit)
	cancel, done := startShutdownRecorder(a, sink, nil, g)
	entered, release, stopped := make(chan struct{}), make(chan struct{}), make(chan struct{})
	stop := func() { close(entered); <-release; close(stopped) }
	shutdownDeadline(t, stop, g, a, cancel, done)
	waitShutdown(t, entered)
	if err := g.PluginConfig().NewConnectionCallback(nil); err == nil {
		t.Fatal("callback accepted after shutdown closed the gate")
	}
	waitShutdown(t, done)
	close(release)
	waitShutdown(t, stopped)
}

func TestSSHBanShutdownKeepsSinkOpenUntilReopenerStops(t *testing.T) {
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	sink := &shutdownSink{}
	a := sshban.NewAuditRecorder(sshban.AuditConfig{Out: sink, Listener: pb.SSHBanListener_SSH_BAN_LISTENER_MAIN})
	g := shutdownGuard(t, &now, a.Emit)
	ctx, cancel := context.WithCancel(context.Background())
	reopenDone := make(chan struct{})
	done := startSSHBanAudit(ctx, a, nil, g, func() {}, reopenDone, sink)
	shutdownDeadline(t, func() {}, g, a, cancel, done)
	if _, closed := sink.snapshot(); closed {
		t.Fatal("sink closed while its reopener was still active")
	}
	close(reopenDone)
	waitShutdown(t, done)
	if _, closed := sink.snapshot(); !closed {
		t.Fatal("sink remained open after the reopener stopped")
	}
}
