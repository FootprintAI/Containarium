package runlease

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// callRecorder records the order in which fake steps ran, shared between a
// test's fakeRevoker and fakeWiper so tests can assert call order across
// both.
type callRecorder struct {
	mu    sync.Mutex
	order []string
}

func (c *callRecorder) record(s string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.order = append(c.order, s)
}

func (c *callRecorder) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.order))
	copy(out, c.order)
	return out
}

// fakeRevoker is a Revoker that records every call, can be told to return a
// per-jti error, and can be told to delay a per-jti response past the
// caller's timeout (while still honoring ctx.Done() so it doesn't leak).
type fakeRevoker struct {
	rec      *callRecorder
	mu       sync.Mutex
	calls    []string
	errFor   map[string]error
	delayFor map[string]time.Duration
}

func newFakeRevoker() *fakeRevoker {
	return &fakeRevoker{rec: &callRecorder{}}
}

func newFakeRevokerWithRecorder(rec *callRecorder) *fakeRevoker {
	return &fakeRevoker{rec: rec}
}

func (f *fakeRevoker) Revoke(ctx context.Context, jti string, expiresAt time.Time, reason string) error {
	f.mu.Lock()
	f.calls = append(f.calls, jti)
	delay := f.delayFor[jti]
	err := f.errFor[jti]
	f.mu.Unlock()

	if f.rec != nil {
		f.rec.record("revoke:" + jti)
	}

	// A real store makes its call with ctx, so an already-expired or
	// already-cancelled context fails the call exactly like a real one
	// would.
	if ctx.Err() != nil {
		return ctx.Err()
	}

	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return err
}

func (f *fakeRevoker) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// fakeWiper is a Wiper that records every call and can be told to return an
// injected error.
type fakeWiper struct {
	rec *callRecorder
	mu  sync.Mutex
	got []wipeCall
	err error
}

type wipeCall struct {
	container string
	cmd       []string
}

func newFakeWiper() *fakeWiper {
	return &fakeWiper{rec: &callRecorder{}}
}

func newFakeWiperWithRecorder(rec *callRecorder) *fakeWiper {
	return &fakeWiper{rec: rec}
}

func (f *fakeWiper) Exec(container string, cmd []string) error {
	f.mu.Lock()
	cp := make([]string, len(cmd))
	copy(cp, cmd)
	f.got = append(f.got, wipeCall{container: container, cmd: cp})
	err := f.err
	f.mu.Unlock()

	if f.rec != nil {
		f.rec.record("wipe")
	}
	return err
}

func (f *fakeWiper) calls() []wipeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]wipeCall, len(f.got))
	copy(out, f.got)
	return out
}

func testLease(box, seedDir string, creds ...Credential) Lease {
	return Lease{
		RunID:       "run-1",
		Box:         box,
		SeedDir:     seedDir,
		Credentials: creds,
	}
}

func cred(kind Kind, jti string) Credential {
	return Credential{Kind: kind, JTI: jti, ExpiresAt: time.Now().Add(time.Hour)}
}

func TestEnd_RevokesEveryCredentialThenWipes(t *testing.T) {
	rec := &callRecorder{}
	rev := newFakeRevokerWithRecorder(rec)
	w := newFakeWiperWithRecorder(rec)

	lease := testLease("box-1", "/etc/containarium/agent",
		cred(KindPlatformJWT, "jti-1"),
		cred(KindGatewayToken, "jti-2"),
	)

	out := End(context.Background(), lease, rev, w, "run_exit")

	want := []string{"revoke:jti-1", "revoke:jti-2", "wipe"}
	if got := rec.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("call order = %v, want %v", got, want)
	}
	if len(out.Revoked) != 2 || len(out.Unrevoked) != 0 || !out.Wiped || len(out.Errs) != 0 {
		t.Fatalf("unexpected outcome: %+v", out)
	}
}

func TestEnd_Table(t *testing.T) {
	tests := []struct {
		name            string
		creds           []Credential
		nilRevoker      bool
		errFor          map[string]error
		delayFor        map[string]time.Duration
		wipeErr         error
		wantRevoked     []string
		wantUnrevoked   []string
		wantWiped       bool
		wantErrs        int
		wantRevokeCalls int
		wantWipeCalls   int
	}{
		{
			name:            "all ok",
			creds:           []Credential{cred(KindPlatformJWT, "jti-1"), cred(KindGatewayToken, "jti-2")},
			wantRevoked:     []string{"jti-1", "jti-2"},
			wantUnrevoked:   nil,
			wantWiped:       true,
			wantErrs:        0,
			wantRevokeCalls: 2,
			wantWipeCalls:   1,
		},
		{
			name:            "first revoke errors",
			creds:           []Credential{cred(KindPlatformJWT, "jti-1"), cred(KindGatewayToken, "jti-2")},
			errFor:          map[string]error{"jti-1": errors.New("store rejected")},
			wantRevoked:     []string{"jti-2"},
			wantUnrevoked:   []string{"jti-1"},
			wantWiped:       true,
			wantErrs:        1,
			wantRevokeCalls: 2,
			wantWipeCalls:   1,
		},
		{
			name:            "second times out",
			creds:           []Credential{cred(KindPlatformJWT, "jti-1"), cred(KindGatewayToken, "jti-2")},
			delayFor:        map[string]time.Duration{"jti-2": 5 * time.Second},
			wantRevoked:     []string{"jti-1"},
			wantUnrevoked:   []string{"jti-2"},
			wantWiped:       true,
			wantErrs:        1,
			wantRevokeCalls: 2,
			wantWipeCalls:   1,
		},
		{
			name:            "nil revoker",
			creds:           []Credential{cred(KindPlatformJWT, "jti-1"), cred(KindGatewayToken, "jti-2")},
			nilRevoker:      true,
			wantRevoked:     nil,
			wantUnrevoked:   []string{"jti-1", "jti-2"},
			wantWiped:       true,
			wantErrs:        0,
			wantRevokeCalls: 0,
			wantWipeCalls:   1,
		},
		{
			name:            "wipe errors",
			creds:           []Credential{cred(KindPlatformJWT, "jti-1"), cred(KindGatewayToken, "jti-2")},
			wipeErr:         errors.New("box gone"),
			wantRevoked:     []string{"jti-1", "jti-2"},
			wantUnrevoked:   nil,
			wantWiped:       false,
			wantErrs:        1,
			wantRevokeCalls: 2,
			wantWipeCalls:   1,
		},
		{
			name:            "zero credentials",
			creds:           nil,
			wantRevoked:     nil,
			wantUnrevoked:   nil,
			wantWiped:       true,
			wantErrs:        0,
			wantRevokeCalls: 0,
			wantWipeCalls:   1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rev := newFakeRevoker()
			rev.errFor = tc.errFor
			rev.delayFor = tc.delayFor
			w := newFakeWiper()
			w.err = tc.wipeErr

			lease := testLease("box-1", "/etc/containarium/agent", tc.creds...)

			var revoker Revoker = rev
			if tc.nilRevoker {
				revoker = nil
			}

			out := End(context.Background(), lease, revoker, w, "run_exit")

			if !reflect.DeepEqual(out.Revoked, tc.wantRevoked) {
				t.Errorf("Revoked = %v, want %v", out.Revoked, tc.wantRevoked)
			}
			if !reflect.DeepEqual(out.Unrevoked, tc.wantUnrevoked) {
				t.Errorf("Unrevoked = %v, want %v", out.Unrevoked, tc.wantUnrevoked)
			}
			if out.Wiped != tc.wantWiped {
				t.Errorf("Wiped = %v, want %v", out.Wiped, tc.wantWiped)
			}
			if len(out.Errs) != tc.wantErrs {
				t.Errorf("len(Errs) = %d, want %d (errs: %v)", len(out.Errs), tc.wantErrs, out.Errs)
			}
			if !tc.nilRevoker && rev.callCount() != tc.wantRevokeCalls {
				t.Errorf("revoke calls = %d, want %d (every credential must be attempted)", rev.callCount(), tc.wantRevokeCalls)
			}
			if len(w.calls()) != tc.wantWipeCalls {
				t.Errorf("wipe calls = %d, want %d (wipe must always be attempted)", len(w.calls()), tc.wantWipeCalls)
			}
		})
	}
}

func TestEnd_HonorsDetachedContext(t *testing.T) {
	lease := testLease("box-1", "/etc/containarium/agent", cred(KindPlatformJWT, "jti-1"))

	t.Run("cancelled parent without detaching fails the revoke", func(t *testing.T) {
		parent, cancel := context.WithCancel(context.Background())
		cancel()

		rev := newFakeRevoker()
		w := newFakeWiper()
		out := End(parent, lease, rev, w, "run_exit")

		if len(out.Revoked) != 0 {
			t.Fatalf("expected no successful revokes against an already-cancelled context, got %v", out.Revoked)
		}
		if !reflect.DeepEqual(out.Unrevoked, []string{"jti-1"}) {
			t.Fatalf("expected jti-1 unrevoked, got %v", out.Unrevoked)
		}
		if len(out.Errs) == 0 {
			t.Fatalf("expected an error surfaced from the cancelled context")
		}
	})

	t.Run("detached context still runs both steps", func(t *testing.T) {
		parent, cancel := context.WithCancel(context.Background())
		cancel()
		detached := context.WithoutCancel(parent)

		rev := newFakeRevoker()
		w := newFakeWiper()
		out := End(detached, lease, rev, w, "run_exit")

		if !reflect.DeepEqual(out.Revoked, []string{"jti-1"}) {
			t.Fatalf("expected jti-1 revoked via detached context, got %v", out.Revoked)
		}
		if !out.Wiped {
			t.Fatalf("expected wipe to succeed via detached context")
		}
		if len(out.Errs) != 0 {
			t.Fatalf("expected no errors, got %v", out.Errs)
		}
	})
}

func TestEnd_WipeCommandIsFixed(t *testing.T) {
	w := newFakeWiper()
	lease := testLease("agent-box-1", "/etc/containarium/agent", cred(KindPlatformJWT, "jti-1"))
	lease.RunID = "super-secret-run-id"

	_ = End(context.Background(), lease, newFakeRevoker(), w, "run_exit")

	calls := w.calls()
	if len(calls) != 1 {
		t.Fatalf("expected exactly one wipe exec call, got %d", len(calls))
	}
	got := calls[0]
	if got.container != lease.Box {
		t.Fatalf("wipe ran against container %q, want %q", got.container, lease.Box)
	}
	want := []string{"rm", "-f", lease.SeedDir + "/token", lease.SeedDir + "/gateway.env"}
	if !reflect.DeepEqual(got.cmd, want) {
		t.Fatalf("wipe argv = %v, want %v", got.cmd, want)
	}
	for _, arg := range got.cmd {
		if strings.Contains(arg, lease.RunID) {
			t.Fatalf("run id leaked into wipe argv: %v", got.cmd)
		}
	}
}
