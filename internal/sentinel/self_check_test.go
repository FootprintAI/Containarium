package sentinel

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// wedgedListener accepts TCP connections and never reads/writes anything —
// simulating the exact production wedge: the listener is alive (TCP accepts
// succeed) but nothing downstream ever services the connection.
type wedgedListener struct {
	ln   net.Listener
	port int
}

func newWedgedListener(t *testing.T) *wedgedListener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	w := &wedgedListener{ln: ln, port: ln.Addr().(*net.TCPAddr).Port}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Deliberately never read or write — hold the connection open
			// forever, same as a wedged dispatch pipeline.
			_ = conn
		}
	}()
	return w
}

func (w *wedgedListener) Close() error { return w.ln.Close() }

// echoCloseListener accepts a connection, reads one byte (the probe), and
// closes — simulating a pipeline that reacted (even if only to fail fast),
// which must NOT be treated as a wedge.
type echoCloseListener struct {
	ln   net.Listener
	port int
}

func newEchoCloseListener(t *testing.T) *echoCloseListener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	e := &echoCloseListener{ln: ln, port: ln.Addr().(*net.TCPAddr).Port}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 1)
			_, _ = conn.Read(buf)
			_ = conn.Close()
		}
	}()
	return e
}

func (e *echoCloseListener) Close() error { return e.ln.Close() }

// newSelfCheckManager builds a Manager in StateProxy with ConnMux/hybrid
// mode armed (httpsDispatch != nil is what gates the self-check on), so
// selfCheckOnce actually runs instead of short-circuiting.
func newSelfCheckManager(t *testing.T, threshold int) *Manager {
	t.Helper()
	m := NewManager(Config{SelfCheckFailureThreshold: threshold}, &fakeRecoveryProvider{})
	m.state.Store(StateProxy)
	m.httpsDispatch = newDispatchListener(newChanListener(nil))
	return m
}

func TestSelfCheck_SuccessKeepsCounterAtZero(t *testing.T) {
	m := newSelfCheckManager(t, 3)
	m.selfCheckFn = func() error { return nil }

	failures, triggered := m.selfCheckOnce(0)
	if triggered {
		t.Fatal("a successful self-check must not trigger exit")
	}
	if failures != 0 {
		t.Fatalf("failures = %d, want 0 after a success", failures)
	}
}

func TestSelfCheck_FailuresBelowThresholdDoNotTrigger(t *testing.T) {
	m := newSelfCheckManager(t, 3)
	exited := false
	m.exitFn = func() { exited = true }
	m.selfCheckFn = func() error { return errors.New("proxy path unresponsive") }

	failures := 0
	var triggered bool
	for i := 0; i < 2; i++ {
		failures, triggered = m.selfCheckOnce(failures)
		if triggered {
			t.Fatalf("triggered after only %d failures, want threshold 3", i+1)
		}
	}
	if failures != 2 {
		t.Fatalf("failures = %d, want 2", failures)
	}
	if exited {
		t.Fatal("exitFn must not be called before the threshold is reached")
	}
}

func TestSelfCheck_ThresholdReachedTriggersExit(t *testing.T) {
	m := newSelfCheckManager(t, 3)
	exitCalls := 0
	m.exitFn = func() { exitCalls++ }
	m.selfCheckFn = func() error { return errors.New("proxy path unresponsive") }

	failures := 0
	var triggered bool
	for i := 0; i < 3; i++ {
		failures, triggered = m.selfCheckOnce(failures)
	}
	if !triggered {
		t.Fatal("expected trigger on the 3rd consecutive failure")
	}
	if failures != 3 {
		t.Fatalf("failures = %d, want 3", failures)
	}
	if exitCalls != 1 {
		t.Fatalf("exitFn called %d times, want exactly 1", exitCalls)
	}
}

func TestSelfCheck_SuccessAfterFailuresResetsCounter(t *testing.T) {
	m := newSelfCheckManager(t, 3)
	m.exitFn = func() { t.Fatal("exitFn must not be called: threshold never reached") }

	failing := true
	m.selfCheckFn = func() error {
		if failing {
			return errors.New("proxy path unresponsive")
		}
		return nil
	}

	failures, _ := m.selfCheckOnce(0)
	failures, _ = m.selfCheckOnce(failures)
	if failures != 2 {
		t.Fatalf("failures = %d, want 2 before recovery", failures)
	}

	failing = false
	failures, triggered := m.selfCheckOnce(failures)
	if triggered {
		t.Fatal("a recovered self-check must not trigger exit")
	}
	if failures != 0 {
		t.Fatalf("failures = %d, want reset to 0 after a success", failures)
	}
}

func TestSelfCheck_SkippedOutsideProxyState(t *testing.T) {
	m := newSelfCheckManager(t, 1)
	m.state.Store(StateMaintenance)
	m.exitFn = func() { t.Fatal("exitFn must not be called while in maintenance") }
	calls := 0
	m.selfCheckFn = func() error { calls++; return errors.New("should not run") }

	failures, triggered := m.selfCheckOnce(5) // pre-existing count from before the transition
	if triggered {
		t.Fatal("must not trigger while not in StateProxy")
	}
	if failures != 0 {
		t.Fatalf("failures = %d, want reset to 0 outside StateProxy", failures)
	}
	if calls != 0 {
		t.Fatalf("selfCheckFn called %d times, want 0 (state gate should short-circuit)", calls)
	}
}

func TestSelfCheck_DisabledByZeroThresholdNeverStarts(t *testing.T) {
	m := newSelfCheckManager(t, 0)
	m.exitFn = func() { t.Fatal("exitFn must not be called: self-check disabled") }
	m.selfCheckFn = func() error { t.Fatal("selfCheckFn must not run: self-check disabled"); return nil }

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	// runSelfCheckLoop must return immediately (threshold<=0 no-op) rather
	// than block until ctx expires — this proves the gate is checked
	// before any ticker/goroutine work starts.
	done := make(chan struct{})
	go func() {
		m.runSelfCheckLoop(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("runSelfCheckLoop did not return promptly when disabled")
	}
}

func TestSelfCheck_DisabledWithoutConnMux(t *testing.T) {
	m := NewManager(Config{SelfCheckFailureThreshold: 3}, &fakeRecoveryProvider{})
	m.state.Store(StateProxy)
	// httpsDispatch left nil (not ConnMux/hybrid mode).
	m.exitFn = func() { t.Fatal("exitFn must not be called: no ConnMux to check") }
	m.selfCheckFn = func() error { t.Fatal("selfCheckFn must not run: no ConnMux to check"); return nil }

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		m.runSelfCheckLoop(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("runSelfCheckLoop did not return promptly without httpsDispatch")
	}
}

// TestSelfCheckProxyPath_TimeoutIsAFailure exercises the real dial/probe
// implementation against a listener that accepts but never responds — the
// exact production signature (TCP accepts, nothing downstream ever reacts).
// It must report a timeout error, not hang or silently succeed.
func TestSelfCheckProxyPath_TimeoutIsAFailure(t *testing.T) {
	ln := newWedgedListener(t)
	defer ln.Close()

	m := &Manager{config: Config{HTTPSPort: ln.port}}
	err := m.selfCheckProxyPath(500 * time.Millisecond)
	if err == nil {
		t.Fatal("expected an error probing a listener that never responds")
	}
}

// TestSelfCheckProxyPath_EOFCountsAsAlive exercises the real implementation
// against a listener that accepts, reads the probe byte, then closes —
// proving a reacting-but-closing pipeline is NOT treated as a wedge.
func TestSelfCheckProxyPath_EOFCountsAsAlive(t *testing.T) {
	ln := newEchoCloseListener(t)
	defer ln.Close()

	m := &Manager{config: Config{HTTPSPort: ln.port}}
	if err := m.selfCheckProxyPath(2 * time.Second); err != nil {
		t.Fatalf("expected no error from a listener that reacts and closes, got: %v", err)
	}
}
