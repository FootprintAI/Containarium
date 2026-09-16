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

// fakeWiper is a Wiper that records every call, can be told to return an
// injected error, and can be told to block for a fixed delay before
// returning (simulating a slow rm) — Exec has no context to honor, so the
// delay is a plain time.Sleep.
type fakeWiper struct {
	rec   *callRecorder
	mu    sync.Mutex
	got   []wipeCall
	err   error
	delay time.Duration
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
	delay := f.delay
	f.mu.Unlock()

	// Record the attempt before blocking, so a caller racing this Exec
	// against a timeout still observes that the wipe was attempted even
	// if it never observes this call return.
	if delay > 0 {
		time.Sleep(delay)
	}

	if f.rec != nil {
		// Distinguish the two Wiper.Exec callers by the shape of their argv
		// (cmd[1] is "-f" for wipeSeed's file wipe, "-rf" for removeDirs'
		// directory removal) so an order-assertion can tell them apart.
		label := "wipe"
		if len(cmd) > 1 {
			switch cmd[1] {
			case "-f":
				label = "wipe-files"
			case "-rf":
				label = "wipe-dirs"
			}
		}
		f.rec.record(label)
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

	// #1860: a third step, removing the seed dir + workspace, runs after the
	// existing revoke-then-wipe-files order.
	want := []string{"revoke:jti-1", "revoke:jti-2", "wipe-files", "wipe-dirs"}
	if got := rec.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("call order = %v, want %v", got, want)
	}
	if len(out.Revoked) != 2 || len(out.Unrevoked) != 0 || !out.Wiped || !out.DirsRemoved || len(out.Errs) != 0 {
		t.Fatalf("unexpected outcome: %+v", out)
	}
}

func TestEnd_Table(t *testing.T) {
	// wantExecCalls counts BOTH Wiper.Exec callers (wipeSeed's file wipe AND
	// removeDirs' directory removal, #1860) — every case below leaves
	// Workspace empty (the zero value from testLease), so removeDirs' argv
	// never carries a second path; TestEnd_RemovesDirsWithWorkspace covers
	// that separately. wipeErr/wipeDelay are injected on the shared fake and
	// so apply to BOTH Exec calls identically — that is why "wipe errors" and
	// "wipe times out" below now expect TWO errors, not one: each step fails
	// independently, and both are always attempted.
	tests := []struct {
		name            string
		seedDir         string
		creds           []Credential
		nilRevoker      bool
		errFor          map[string]error
		delayFor        map[string]time.Duration
		wipeErr         error
		wipeDelay       time.Duration
		wantRevoked     []string
		wantUnrevoked   []string
		wantWiped       bool
		wantDirsRemoved bool
		wantErrs        int
		wantErrSubstr   string // when non-empty, at least one Errs entry must contain it
		wantRevokeCalls int
		wantExecCalls   int
		wantElapsedMin  time.Duration // zero skips the check
		wantElapsedMax  time.Duration // zero skips the check
	}{
		{
			name:            "all ok",
			creds:           []Credential{cred(KindPlatformJWT, "jti-1"), cred(KindGatewayToken, "jti-2")},
			wantRevoked:     []string{"jti-1", "jti-2"},
			wantUnrevoked:   nil,
			wantWiped:       true,
			wantDirsRemoved: true,
			wantErrs:        0,
			wantRevokeCalls: 2,
			wantExecCalls:   2,
		},
		{
			name:            "first revoke errors",
			creds:           []Credential{cred(KindPlatformJWT, "jti-1"), cred(KindGatewayToken, "jti-2")},
			errFor:          map[string]error{"jti-1": errors.New("store rejected")},
			wantRevoked:     []string{"jti-2"},
			wantUnrevoked:   []string{"jti-1"},
			wantWiped:       true,
			wantDirsRemoved: true,
			wantErrs:        1,
			wantRevokeCalls: 2,
			wantExecCalls:   2,
		},
		{
			// Pins the timeout value itself, not just "some deadline
			// shorter than the injected 5s delay exists": revokeTimeout
			// is 2s, so this must land in [2s, 3s).
			name:            "second times out",
			creds:           []Credential{cred(KindPlatformJWT, "jti-1"), cred(KindGatewayToken, "jti-2")},
			delayFor:        map[string]time.Duration{"jti-2": 5 * time.Second},
			wantRevoked:     []string{"jti-1"},
			wantUnrevoked:   []string{"jti-2"},
			wantWiped:       true,
			wantDirsRemoved: true,
			wantErrs:        1,
			wantRevokeCalls: 2,
			wantExecCalls:   2,
			wantElapsedMin:  2 * time.Second,
			wantElapsedMax:  3 * time.Second,
		},
		{
			name:            "nil revoker",
			creds:           []Credential{cred(KindPlatformJWT, "jti-1"), cred(KindGatewayToken, "jti-2")},
			nilRevoker:      true,
			wantRevoked:     nil,
			wantUnrevoked:   []string{"jti-1", "jti-2"},
			wantWiped:       true,
			wantDirsRemoved: true,
			wantErrs:        0,
			wantRevokeCalls: 0,
			wantExecCalls:   2,
		},
		{
			// wipeErr is shared by both Exec callers (the fake has no notion
			// of which step is calling), so BOTH the file wipe and the dirs
			// removal fail — two independent errors, not one.
			name:            "wipe errors",
			creds:           []Credential{cred(KindPlatformJWT, "jti-1"), cred(KindGatewayToken, "jti-2")},
			wipeErr:         errors.New("box gone"),
			wantRevoked:     []string{"jti-1", "jti-2"},
			wantUnrevoked:   nil,
			wantWiped:       false,
			wantDirsRemoved: false,
			wantErrs:        2,
			wantRevokeCalls: 2,
			wantExecCalls:   2,
		},
		{
			// Proves wipeTimeout and removeDirsTimeout (3s each) are real,
			// not decorative: the fake blocks 6s on every Exec call, so
			// neither step waits for it. The revokes still land, and each
			// step's own timeout fires independently — sequentially, since
			// removeDirs runs after wipeSeed returns — for a combined worst
			// case just under 2*wipeTimeout.
			name:            "wipe times out",
			creds:           []Credential{cred(KindPlatformJWT, "jti-1"), cred(KindGatewayToken, "jti-2")},
			wipeDelay:       6 * time.Second,
			wantRevoked:     []string{"jti-1", "jti-2"},
			wantUnrevoked:   nil,
			wantWiped:       false,
			wantDirsRemoved: false,
			wantErrs:        2,
			wantErrSubstr:   "timed out",
			wantRevokeCalls: 2,
			wantExecCalls:   2,
			wantElapsedMax:  6500 * time.Millisecond,
		},
		{
			name:            "zero credentials",
			creds:           nil,
			wantRevoked:     nil,
			wantUnrevoked:   nil,
			wantWiped:       true,
			wantDirsRemoved: true,
			wantErrs:        0,
			wantRevokeCalls: 0,
			wantExecCalls:   2,
		},
		{
			// An empty SeedDir must never turn into "rm -f /token
			// /gateway.env" or "rm -rf" against the box root — both steps
			// refuse independently, so this is two errors, zero Exec calls.
			name:            "empty seed dir",
			seedDir:         "",
			creds:           []Credential{cred(KindPlatformJWT, "jti-1")},
			wantRevoked:     []string{"jti-1"},
			wantUnrevoked:   nil,
			wantWiped:       false,
			wantDirsRemoved: false,
			wantErrs:        2,
			wantErrSubstr:   "empty seed dir",
			wantRevokeCalls: 1,
			wantExecCalls:   0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rev := newFakeRevoker()
			rev.errFor = tc.errFor
			rev.delayFor = tc.delayFor
			w := newFakeWiper()
			w.err = tc.wipeErr
			w.delay = tc.wipeDelay

			seedDir := tc.seedDir
			if seedDir == "" && tc.name != "empty seed dir" {
				seedDir = "/etc/containarium/agent"
			}
			lease := testLease("box-1", seedDir, tc.creds...)

			var revoker Revoker = rev
			if tc.nilRevoker {
				revoker = nil
			}

			start := time.Now()
			out := End(context.Background(), lease, revoker, w, "run_exit")
			elapsed := time.Since(start)

			if !reflect.DeepEqual(out.Revoked, tc.wantRevoked) {
				t.Errorf("Revoked = %v, want %v", out.Revoked, tc.wantRevoked)
			}
			if !reflect.DeepEqual(out.Unrevoked, tc.wantUnrevoked) {
				t.Errorf("Unrevoked = %v, want %v", out.Unrevoked, tc.wantUnrevoked)
			}
			if out.Wiped != tc.wantWiped {
				t.Errorf("Wiped = %v, want %v", out.Wiped, tc.wantWiped)
			}
			if out.DirsRemoved != tc.wantDirsRemoved {
				t.Errorf("DirsRemoved = %v, want %v", out.DirsRemoved, tc.wantDirsRemoved)
			}
			if len(out.Errs) != tc.wantErrs {
				t.Errorf("len(Errs) = %d, want %d (errs: %v)", len(out.Errs), tc.wantErrs, out.Errs)
			}
			if tc.wantErrSubstr != "" {
				found := false
				for _, e := range out.Errs {
					if strings.Contains(e.Error(), tc.wantErrSubstr) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Errs = %v, want an entry containing %q", out.Errs, tc.wantErrSubstr)
				}
			}
			if !tc.nilRevoker && rev.callCount() != tc.wantRevokeCalls {
				t.Errorf("revoke calls = %d, want %d (every credential must be attempted)", rev.callCount(), tc.wantRevokeCalls)
			}
			// Exec calls are recorded before fakeWiper.Exec blocks on its
			// injected delay, so it's safe to read immediately even when End
			// timed a step out and returned before Exec did.
			if len(w.calls()) != tc.wantExecCalls {
				t.Errorf("wiper exec calls = %d, want %d (wipe + removeDirs must always both be attempted)", len(w.calls()), tc.wantExecCalls)
			}
			if tc.wantElapsedMin > 0 && elapsed < tc.wantElapsedMin {
				t.Errorf("End returned in %s, want >= %s", elapsed, tc.wantElapsedMin)
			}
			if tc.wantElapsedMax > 0 && elapsed >= tc.wantElapsedMax {
				t.Errorf("End returned in %s, want < %s", elapsed, tc.wantElapsedMax)
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
	lease := testLease("agent-box-1", "/etc/containarium/agent/runs/super-secret-run-id", cred(KindPlatformJWT, "jti-1"))
	lease.RunID = "super-secret-run-id"

	_ = End(context.Background(), lease, newFakeRevoker(), w, "run_exit")

	calls := w.calls()
	if len(calls) != 2 {
		t.Fatalf("expected exactly two exec calls (wipe files, then remove dirs), got %d", len(calls))
	}

	wipe := calls[0]
	if wipe.container != lease.Box {
		t.Fatalf("wipe ran against container %q, want %q", wipe.container, lease.Box)
	}
	wantWipe := []string{"rm", "-f", lease.SeedDir + "/token", lease.SeedDir + "/gateway.env"}
	if !reflect.DeepEqual(wipe.cmd, wantWipe) {
		t.Fatalf("wipe argv = %v, want %v", wipe.cmd, wantWipe)
	}

	// #1860: the removal argv is equally fixed — it is built from the
	// already-validated SeedDir/Workspace fields alone, never from RunID
	// directly, even though the run id happens to appear as SeedDir's last
	// path segment (that is the caller's job, not an interpolation here).
	remove := calls[1]
	if remove.container != lease.Box {
		t.Fatalf("remove dirs ran against container %q, want %q", remove.container, lease.Box)
	}
	wantRemove := []string{"rm", "-rf", lease.SeedDir}
	if !reflect.DeepEqual(remove.cmd, wantRemove) {
		t.Fatalf("remove dirs argv = %v, want %v", remove.cmd, wantRemove)
	}
	for _, arg := range append(append([]string{}, wipe.cmd...), remove.cmd...) {
		if arg == lease.RunID {
			t.Fatalf("run id appears as a bare argv token (interpolated directly rather than via SeedDir): %v / %v", wipe.cmd, remove.cmd)
		}
	}
}

// TestEnd_RemovesDirsWithWorkspace: when Workspace is set, the removal argv
// carries both paths; when it is empty ("" = no git_source on the run, #1859),
// only SeedDir is removed.
func TestEnd_RemovesDirsWithWorkspace(t *testing.T) {
	t.Run("workspace set", func(t *testing.T) {
		w := newFakeWiper()
		lease := testLease("agent-box-1", "/etc/containarium/agent/runs/run-1")
		lease.Workspace = "/workspace/runs/run-1"

		out := End(context.Background(), lease, newFakeRevoker(), w, "run_exit")

		if !out.DirsRemoved {
			t.Fatalf("expected DirsRemoved, got outcome %+v", out)
		}
		calls := w.calls()
		if len(calls) != 2 {
			t.Fatalf("expected 2 exec calls, got %d", len(calls))
		}
		want := []string{"rm", "-rf", lease.SeedDir, lease.Workspace}
		if !reflect.DeepEqual(calls[1].cmd, want) {
			t.Errorf("remove dirs argv = %v, want %v", calls[1].cmd, want)
		}
	})

	t.Run("workspace empty", func(t *testing.T) {
		w := newFakeWiper()
		lease := testLease("agent-box-1", "/etc/containarium/agent/runs/run-1")
		// Workspace left at its zero value.

		out := End(context.Background(), lease, newFakeRevoker(), w, "run_exit")

		if !out.DirsRemoved {
			t.Fatalf("expected DirsRemoved, got outcome %+v", out)
		}
		calls := w.calls()
		want := []string{"rm", "-rf", lease.SeedDir}
		if !reflect.DeepEqual(calls[1].cmd, want) {
			t.Errorf("remove dirs argv = %v, want %v (no workspace arg)", calls[1].cmd, want)
		}
	})
}

// TestEnd_RefusesUnsafeRemovalPaths: a SeedDir or Workspace that is empty,
// relative, unclean, or too shallow (e.g. "/", "/etc") must never reach
// `rm -rf` — the combined command is refused entirely rather than dropping
// the bad half silently.
func TestEnd_RefusesUnsafeRemovalPaths(t *testing.T) {
	tests := []struct {
		name      string
		seedDir   string
		workspace string
	}{
		{"seed dir is root", "/", ""},
		{"seed dir too shallow", "/etc", ""},
		{"seed dir relative", "etc/containarium/agent/runs/run-1", ""},
		{"seed dir has dot-dot", "/etc/containarium/agent/runs/../../../etc", ""},
		{"workspace unsafe, seed dir fine", "/etc/containarium/agent/runs/run-1", "/"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := newFakeWiper()
			lease := testLease("agent-box-1", tc.seedDir)
			lease.Workspace = tc.workspace

			out := End(context.Background(), lease, newFakeRevoker(), w, "run_exit")

			if out.DirsRemoved {
				t.Fatalf("expected DirsRemoved=false for unsafe path, got outcome %+v", out)
			}
			// wipeSeed (the pre-existing, unchanged step) still runs its own
			// `rm -f` for any non-empty seedDir — that safety floor is out
			// of scope here. What this test pins is that removeDirs' `-rf`
			// never fires for an unsafe path.
			for _, c := range w.calls() {
				if len(c.cmd) > 1 && c.cmd[1] == "-rf" {
					t.Fatalf("expected NO rm -rf call for an unsafe path, got %v", c.cmd)
				}
			}
			found := false
			for _, e := range out.Errs {
				if strings.Contains(e.Error(), "not safe to remove") {
					found = true
				}
			}
			if !found {
				t.Errorf("Errs = %v, want an entry about the unsafe path", out.Errs)
			}
		})
	}
}
