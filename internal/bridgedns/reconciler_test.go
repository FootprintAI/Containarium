package bridgedns

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// The real Incus client is what the daemon hands the reconciler; keep the two
// in step at compile time.
var _ Backend = (*incus.Client)(nil)

const testCaddy = "core-caddy-test"

// fakeBackend is an in-memory Incus: one core-caddy container and one
// network config key, with every write recorded — "writes nothing when in
// sync" is the property most of these tests pin.
type fakeBackend struct {
	mu sync.Mutex

	caddy    *incus.ContainerInfo
	caddyErr error

	raw    string
	getErr error
	setErr error
	sets   []string
}

func (f *fakeBackend) GetContainer(name string) (*incus.ContainerInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if name != testCaddy {
		return nil, errors.New("not found: " + name)
	}
	if f.caddyErr != nil {
		return nil, f.caddyErr
	}
	c := *f.caddy
	return &c, nil
}

func (f *fakeBackend) GetNetworkConfigValue(network, key string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if network != "incusbr0" || key != "raw.dnsmasq" {
		return "", errors.New("unexpected key " + network + "/" + key)
	}
	return f.raw, f.getErr
}

func (f *fakeBackend) SetNetworkConfigValue(network, key, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if network != "incusbr0" || key != "raw.dnsmasq" {
		return errors.New("unexpected key " + network + "/" + key)
	}
	if f.setErr != nil {
		return f.setErr
	}
	f.raw = value
	f.sets = append(f.sets, value)
	return nil
}

func (f *fakeBackend) setCaddyIP(ip string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.caddy.IPAddress = ip
}

func (f *fakeBackend) snapshot() (raw string, sets []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.raw, append([]string(nil), f.sets...)
}

func newFake(ip, raw string) *fakeBackend {
	return &fakeBackend{caddy: &incus.ContainerInfo{Name: testCaddy, State: "Running", IPAddress: ip}, raw: raw}
}

// render stands in for the daemon's bridgeDNSRaw closure.
func render(ip string) string { return "address=/example.com/" + ip + "\nserver=/ssh.example.com/#" }

func newRec(be Backend, interval time.Duration) *Reconciler {
	return NewReconciler(be, Config{Bridge: "incusbr0", CaddyContainer: testCaddy, Render: render, Interval: interval})
}

func TestReconcileOnce_InSyncWritesNothing(t *testing.T) {
	be := newFake("10.0.3.5", render("10.0.3.5"))
	r := newRec(be, time.Hour)
	if err := r.ReconcileOnce(context.Background()); err != nil {
		t.Fatalf("ReconcileOnce: %v", err)
	}
	if _, sets := be.snapshot(); len(sets) != 0 {
		t.Fatalf("wrote %d times while in sync: %q", len(sets), sets)
	}
	st := r.Status()
	if !st.InSync || st.DriftCount != 0 || st.CaddyIP != "10.0.3.5" || st.LastError != "" || st.LastPass.IsZero() {
		t.Fatalf("status = %+v; want in sync, no drift, caddy 10.0.3.5, no error, LastPass set", st)
	}
}

// A trailing newline or padding is not drift: Incus may store the value
// slightly differently from what was sent, and rewriting on every pass would
// churn dnsmasq for nothing.
func TestReconcileOnce_WhitespaceIsNotDrift(t *testing.T) {
	be := newFake("10.0.3.5", "  "+render("10.0.3.5")+"\n")
	r := newRec(be, time.Hour)
	if err := r.ReconcileOnce(context.Background()); err != nil {
		t.Fatalf("ReconcileOnce: %v", err)
	}
	if _, sets := be.snapshot(); len(sets) != 0 {
		t.Fatalf("rewrote a value that differed only in whitespace: %q", sets)
	}
}

func TestReconcileOnce_StaleAddressIsRepaired(t *testing.T) {
	be := newFake("10.0.3.5", render("10.0.3.9")) // the #2188 shape: record points at a dead address
	r := newRec(be, time.Hour)
	if err := r.ReconcileOnce(context.Background()); err != nil {
		t.Fatalf("ReconcileOnce: %v", err)
	}
	raw, sets := be.snapshot()
	if len(sets) != 1 || raw != render("10.0.3.5") {
		t.Fatalf("raw=%q sets=%q; want exactly one write of the live-address value", raw, sets)
	}
	st := r.Status()
	if !st.InSync || st.DriftCount != 1 || st.LastApplied.IsZero() || st.Desired != render("10.0.3.5") {
		t.Fatalf("status = %+v; want in sync after one repaired drift", st)
	}
}

func TestReconcileOnce_HandEditIsRestored(t *testing.T) {
	be := newFake("10.0.3.5", "address=/example.com/9.9.9.9")
	if err := newRec(be, time.Hour).ReconcileOnce(context.Background()); err != nil {
		t.Fatalf("ReconcileOnce: %v", err)
	}
	if raw, _ := be.snapshot(); raw != render("10.0.3.5") {
		t.Fatalf("raw = %q; want the daemon-owned value restored", raw)
	}
}

func TestReconcileOnce_UnsetRecordIsWritten(t *testing.T) {
	be := newFake("10.0.3.5", "")
	if err := newRec(be, time.Hour).ReconcileOnce(context.Background()); err != nil {
		t.Fatalf("ReconcileOnce: %v", err)
	}
	if raw, _ := be.snapshot(); raw != render("10.0.3.5") {
		t.Fatalf("raw = %q; want the record written when unset", raw)
	}
}

// Acceptance: core-caddy gets a new address while the daemon keeps running;
// the next pass moves the record to it.
func TestReconcileOnce_FollowsCaddyAddressChange(t *testing.T) {
	be := newFake("10.0.3.5", "")
	r := newRec(be, time.Hour)
	ctx := context.Background()
	if err := r.ReconcileOnce(ctx); err != nil {
		t.Fatalf("pass 1: %v", err)
	}
	be.setCaddyIP("10.0.3.77")
	if err := r.ReconcileOnce(ctx); err != nil {
		t.Fatalf("pass 2: %v", err)
	}
	if raw, sets := be.snapshot(); raw != render("10.0.3.77") || len(sets) != 2 {
		t.Fatalf("raw=%q sets=%d; want the record on the new address after 2 writes", raw, len(sets))
	}
	if err := r.ReconcileOnce(ctx); err != nil {
		t.Fatalf("pass 3: %v", err)
	}
	if _, sets := be.snapshot(); len(sets) != 2 {
		t.Fatalf("a third pass on a converged record wrote again (%d writes)", len(sets))
	}
}

// Fail-safe: never write a record built from an address we do not know.
func TestReconcileOnce_UnknownCaddyWritesNothing(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*fakeBackend)
	}{
		{"lookup error", func(f *fakeBackend) { f.caddyErr = errors.New("incus down") }},
		{"not running", func(f *fakeBackend) { f.caddy.State = "Stopped" }},
		{"no address yet", func(f *fakeBackend) { f.caddy.IPAddress = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			be := newFake("10.0.3.5", render("10.0.3.9"))
			tc.setup(be)
			r := newRec(be, time.Hour)
			if err := r.ReconcileOnce(context.Background()); err == nil {
				t.Fatal("want an error when core-caddy's address is unknown")
			}
			if _, sets := be.snapshot(); len(sets) != 0 {
				t.Fatalf("wrote %q without a known address", sets)
			}
			if st := r.Status(); st.LastError == "" || st.InSync {
				t.Fatalf("status = %+v; want LastError set and not in sync", st)
			}
		})
	}
}

func TestReconcileOnce_ReadErrorWritesNothing(t *testing.T) {
	be := newFake("10.0.3.5", "")
	be.getErr = errors.New("api error")
	r := newRec(be, time.Hour)
	if err := r.ReconcileOnce(context.Background()); err == nil {
		t.Fatal("want an error when the current value cannot be read")
	}
	if _, sets := be.snapshot(); len(sets) != 0 {
		t.Fatalf("wrote %q after a failed read", sets)
	}
}

// A failed write is an error and a status field, and the next pass retries —
// not the single warning log line the start-up write leaves behind.
func TestReconcileOnce_WriteFailureIsSurfacedAndRetried(t *testing.T) {
	be := newFake("10.0.3.5", render("10.0.3.9"))
	be.setErr = errors.New("permission denied")
	r := newRec(be, time.Hour)
	ctx := context.Background()
	if err := r.ReconcileOnce(ctx); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("err = %v; want the write error", err)
	}
	if st := r.Status(); st.InSync || !strings.Contains(st.LastError, "permission denied") || st.DriftCount != 1 {
		t.Fatalf("status = %+v; want not in sync, LastError set, drift counted", st)
	}
	be.mu.Lock()
	be.setErr = nil
	be.mu.Unlock()
	if err := r.ReconcileOnce(ctx); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if st := r.Status(); !st.InSync || st.LastError != "" {
		t.Fatalf("status after retry = %+v; want in sync, error cleared", st)
	}
}

func TestReconcileOnce_CancelledContextDoesNothing(t *testing.T) {
	be := newFake("10.0.3.5", "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := newRec(be, time.Hour).ReconcileOnce(ctx); err == nil {
		t.Fatal("want ctx error")
	}
	if _, sets := be.snapshot(); len(sets) != 0 {
		t.Fatalf("wrote after cancellation: %q", sets)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// Run repairs at start-up, follows a later address change on the ticker, wakes
// early on an event, and returns when the context is cancelled.
func TestRun_StartupTickerEventAndStop(t *testing.T) {
	be := newFake("10.0.3.5", "stale")
	r := newRec(be, 30*time.Millisecond)
	events := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx, events); close(done) }()

	waitFor(t, "start-up repair", func() bool { raw, _ := be.snapshot(); return raw == render("10.0.3.5") })
	be.setCaddyIP("10.0.3.9")
	waitFor(t, "ticker to follow the new address", func() bool { raw, _ := be.snapshot(); return raw == render("10.0.3.9") })

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func TestRun_EventWakesBeforeTheTick(t *testing.T) {
	be := newFake("10.0.3.5", render("10.0.3.5"))
	r := newRec(be, time.Hour) // the tick will not fire during the test
	events := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx, events)

	waitFor(t, "start-up pass", func() bool { return r.Status().InSync })
	be.setCaddyIP("10.0.3.9")
	events <- struct{}{}
	waitFor(t, "event-driven repair", func() bool { raw, _ := be.snapshot(); return raw == render("10.0.3.9") })
}

func TestNewReconcilerDefaults(t *testing.T) {
	r := NewReconciler(newFake("10.0.3.5", ""), Config{Bridge: "incusbr0", CaddyContainer: testCaddy, Render: render})
	if r.cfg.Interval != DefaultInterval {
		t.Fatalf("interval = %v; want DefaultInterval %v", r.cfg.Interval, DefaultInterval)
	}
}
