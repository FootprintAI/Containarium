package alert

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeProber returns a scripted credential source per skill id.
type fakeProber struct {
	mu      sync.Mutex
	targets []CredentialWatchTarget
	sources map[string]pb.CodeCredentialSource
	errs    map[string]error
}

func (p *fakeProber) CredentialWatchTargets(context.Context) ([]CredentialWatchTarget, error) {
	return p.targets, nil
}

func (p *fakeProber) ProbeCredential(_ context.Context, t CredentialWatchTarget) (pb.CodeCredentialSource, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.errs[t.SkillID]; err != nil {
		return pb.CodeCredentialSource_CODE_CREDENTIAL_SOURCE_UNSPECIFIED, err
	}
	return p.sources[t.SkillID], nil
}

func (p *fakeProber) set(skillID string, src pb.CodeCredentialSource) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sources[skillID] = src
}

// memStateStore is an in-memory CredentialStateStore. Sharing one instance
// across two watchers models a daemon restart against the same Postgres.
type memStateStore struct {
	mu        sync.Mutex
	last      map[string]pb.CodeCredentialSource
	recordErr error
}

func newMemStateStore() *memStateStore {
	return &memStateStore{last: map[string]pb.CodeCredentialSource{}}
}

func (s *memStateStore) LastSeen(_ context.Context, skillID string) (pb.CodeCredentialSource, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	src, ok := s.last[skillID]
	return src, ok, nil
}

func (s *memStateStore) Record(_ context.Context, skillID string, src pb.CodeCredentialSource, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.recordErr != nil {
		return s.recordErr
	}
	s.last[skillID] = src
	return nil
}

type recordingNotifier struct {
	mu     sync.Mutex
	alerts []CredentialExpiredAlert
}

func (n *recordingNotifier) NotifyCredentialExpired(_ context.Context, a CredentialExpiredAlert) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.alerts = append(n.alerts, a)
}

func (n *recordingNotifier) count() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.alerts)
}

const (
	srcInteractive = pb.CodeCredentialSource_CODE_CREDENTIAL_SOURCE_INTERACTIVE
	srcExpired     = pb.CodeCredentialSource_CODE_CREDENTIAL_SOURCE_EXPIRED
	srcNone        = pb.CodeCredentialSource_CODE_CREDENTIAL_SOURCE_NONE
)

func oneTargetProber(src pb.CodeCredentialSource) *fakeProber {
	return &fakeProber{
		targets: []CredentialWatchTarget{{SkillID: "s1", Box: "agent-s1-container", Engine: pb.AgentEngine_AGENT_ENGINE_CLAUDE}},
		sources: map[string]pb.CodeCredentialSource{"s1": src},
		errs:    map[string]error{},
	}
}

// TestCredentialWatcher_FiresOncePerFlip is AC2's core: a sequence of
// sweeps over one box fires exactly one alert per transition INTO expired,
// and none while it stays expired or while it is anything else.
func TestCredentialWatcher_FiresOncePerFlip(t *testing.T) {
	tests := []struct {
		name      string
		sequence  []pb.CodeCredentialSource
		wantFired int
	}{
		{name: "stays interactive", sequence: []pb.CodeCredentialSource{srcInteractive, srcInteractive, srcInteractive}, wantFired: 0},
		{name: "flip to expired then stays", sequence: []pb.CodeCredentialSource{srcInteractive, srcExpired, srcExpired, srcExpired}, wantFired: 1},
		{name: "expired, re-signed in, expired again", sequence: []pb.CodeCredentialSource{srcInteractive, srcExpired, srcInteractive, srcExpired}, wantFired: 2},
		{name: "first observation already expired fires once", sequence: []pb.CodeCredentialSource{srcExpired, srcExpired}, wantFired: 1},
		{name: "signed out (none) is not expiry", sequence: []pb.CodeCredentialSource{srcInteractive, srcNone, srcNone}, wantFired: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prober := oneTargetProber(tc.sequence[0])
			notifier := &recordingNotifier{}
			w := NewCredentialWatcher(prober, newMemStateStore(), notifier)
			for _, src := range tc.sequence {
				prober.set("s1", src)
				w.Sweep(context.Background())
			}
			if got := notifier.count(); got != tc.wantFired {
				t.Errorf("alerts fired = %d, want %d", got, tc.wantFired)
			}
		})
	}
}

// TestCredentialWatcher_RestartDoesNotRefire: the last-seen state lives in
// the store, not the watcher, so a fresh watcher (a restarted daemon) over
// the same store does not alert again for a box that was already expired.
func TestCredentialWatcher_RestartDoesNotRefire(t *testing.T) {
	prober := oneTargetProber(srcInteractive)
	store := newMemStateStore()
	notifier := &recordingNotifier{}

	first := NewCredentialWatcher(prober, store, notifier)
	first.Sweep(context.Background())
	prober.set("s1", srcExpired)
	first.Sweep(context.Background())

	restarted := NewCredentialWatcher(prober, store, notifier)
	restarted.Sweep(context.Background())
	restarted.Sweep(context.Background())

	if got := notifier.count(); got != 1 {
		t.Fatalf("alerts fired across a restart = %d, want exactly 1", got)
	}
}

// TestCredentialWatcher_AlertCarriesNamesOnly pins the payload: which box,
// which engine, the transition — and no field a credential value could ride.
func TestCredentialWatcher_AlertCarriesNamesOnly(t *testing.T) {
	prober := oneTargetProber(srcInteractive)
	notifier := &recordingNotifier{}
	w := NewCredentialWatcher(prober, newMemStateStore(), notifier)
	fixed := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	w.now = func() time.Time { return fixed }

	w.Sweep(context.Background())
	prober.set("s1", srcExpired)
	w.Sweep(context.Background())

	if notifier.count() != 1 {
		t.Fatalf("alerts fired = %d, want 1", notifier.count())
	}
	got := notifier.alerts[0]
	want := CredentialExpiredAlert{
		SkillID:          "s1",
		Box:              "agent-s1-container",
		Engine:           pb.AgentEngine_AGENT_ENGINE_CLAUDE,
		CredentialSource: srcExpired,
		PreviousSource:   srcInteractive,
		ObservedAt:       fixed,
	}
	if got != want {
		t.Errorf("alert = %+v, want %+v", got, want)
	}

	body, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var wire credentialExpiredWire
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields() // a field added later must be added here on purpose
	if err := dec.Decode(&wire); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	wantWire := credentialExpiredWire{
		Alert:            CredentialExpiredAlertName,
		SkillID:          "s1",
		Box:              "agent-s1-container",
		Engine:           "AGENT_ENGINE_CLAUDE",
		CredentialSource: "CODE_CREDENTIAL_SOURCE_EXPIRED",
		PreviousSource:   "CODE_CREDENTIAL_SOURCE_INTERACTIVE",
		ObservedAt:       fixed,
	}
	if wire != wantWire {
		t.Errorf("wire payload = %+v, want %+v", wire, wantWire)
	}
}

// TestCredentialWatcher_ProbeErrorKeepsState: a box that cannot be probed
// this sweep (stopped mid-sweep, exec failure) neither alerts nor
// overwrites its last-seen state — so the flip is still caught next time.
func TestCredentialWatcher_ProbeErrorKeepsState(t *testing.T) {
	prober := oneTargetProber(srcInteractive)
	store := newMemStateStore()
	notifier := &recordingNotifier{}
	w := NewCredentialWatcher(prober, store, notifier)

	w.Sweep(context.Background())
	prober.errs["s1"] = errors.New("exec failed")
	w.Sweep(context.Background())
	if src, _, _ := store.LastSeen(context.Background(), "s1"); src != srcInteractive {
		t.Fatalf("last-seen after a probe error = %v, want unchanged INTERACTIVE", src)
	}
	delete(prober.errs, "s1")
	prober.set("s1", srcExpired)
	w.Sweep(context.Background())
	if notifier.count() != 1 {
		t.Fatalf("alerts fired = %d, want 1", notifier.count())
	}
}

// TestCredentialWatcher_UnpersistedFlipDoesNotNotify: state is written
// BEFORE the alert goes out, so a store failure means no alert this sweep
// (it retries next sweep) rather than an alert that repeats every sweep.
func TestCredentialWatcher_UnpersistedFlipDoesNotNotify(t *testing.T) {
	prober := oneTargetProber(srcExpired)
	store := newMemStateStore()
	store.recordErr = errors.New("db down")
	notifier := &recordingNotifier{}
	w := NewCredentialWatcher(prober, store, notifier)

	w.Sweep(context.Background())
	w.Sweep(context.Background())
	if notifier.count() != 0 {
		t.Fatalf("alerts fired while the flip could not be persisted = %d, want 0", notifier.count())
	}
	store.recordErr = nil
	w.Sweep(context.Background())
	w.Sweep(context.Background())
	if notifier.count() != 1 {
		t.Fatalf("alerts fired once the store recovered = %d, want 1", notifier.count())
	}
}

// TestCredentialWatcher_StartSweepsAndStopEnds: Start runs a sweep right
// away (no 15-minute wait for the first one) and Stop returns only once the
// loop has exited, so daemon shutdown leaves no goroutine behind.
func TestCredentialWatcher_StartSweepsAndStopEnds(t *testing.T) {
	prober := oneTargetProber(srcExpired)
	notifier := &recordingNotifier{}
	w := NewCredentialWatcher(prober, newMemStateStore(), notifier)
	w.Start(context.Background())
	deadline := time.Now().Add(5 * time.Second)
	for notifier.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if notifier.count() != 1 {
		t.Fatalf("alerts after Start = %d, want 1 from the immediate first sweep", notifier.count())
	}
	stopped := make(chan struct{})
	go func() { w.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return")
	}
	select {
	case <-w.done:
	default:
		t.Fatal("Stop returned before the loop exited")
	}
}

type mapConfig map[string]string

func (m mapConfig) Get(_ context.Context, key string) (string, error) { return m[key], nil }

// TestCredentialWebhookNotifier_SignsWithOperatorSecret: delivery reuses the
// operator webhook URL/secret config keys and the same "sha256=<hex>" HMAC
// header the threat-detection notifier and the alert relay send.
func TestCredentialWebhookNotifier_SignsWithOperatorSecret(t *testing.T) {
	var gotBody []byte
	var gotSig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotSig = r.Header.Get("X-Containarium-Signature")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := NewCredentialWebhookNotifier(mapConfig{
		WebhookURLConfigKey:    srv.URL + "/hook",
		WebhookSecretConfigKey: "s3cret",
	}, nil)
	n.NotifyCredentialExpired(context.Background(), CredentialExpiredAlert{SkillID: "s1", CredentialSource: srcExpired})

	if len(gotBody) == 0 {
		t.Fatal("webhook received no body")
	}
	mac := hmac.New(sha256.New, []byte("s3cret"))
	mac.Write(gotBody)
	if want := "sha256=" + hex.EncodeToString(mac.Sum(nil)); gotSig != want {
		t.Errorf("signature = %q, want %q", gotSig, want)
	}
}

// TestCredentialWebhookNotifier_RetriesThenStops: a failing webhook is
// retried a bounded number of times within one delivery, never forever.
func TestCredentialWebhookNotifier_RetriesThenStops(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	n := NewCredentialWebhookNotifier(mapConfig{WebhookURLConfigKey: srv.URL}, nil)
	n.backoff = func(int) time.Duration { return 0 }
	n.NotifyCredentialExpired(context.Background(), CredentialExpiredAlert{SkillID: "s1"})
	if calls != credentialWebhookMaxAttempts {
		t.Errorf("POST attempts = %d, want %d", calls, credentialWebhookMaxAttempts)
	}
}

// TestCredentialWebhookNotifier_NoURLIsANoop: no webhook configured means
// nothing to deliver — not an error, and no request anywhere.
func TestCredentialWebhookNotifier_NoURLIsANoop(t *testing.T) {
	n := NewCredentialWebhookNotifier(mapConfig{}, nil)
	n.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("no webhook URL configured, but a request was sent")
		return nil, nil
	})}
	n.NotifyCredentialExpired(context.Background(), CredentialExpiredAlert{SkillID: "s1"})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
