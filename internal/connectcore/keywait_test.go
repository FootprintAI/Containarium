package connectcore

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeClock is an injected clock: Sleep advances Now instantly, so the retry
// loop's timing is exercised without a single real sleep.
type fakeClock struct {
	now    time.Time
	sleeps []time.Duration
}

func (c *fakeClock) Now() time.Time { return c.now }

func (c *fakeClock) Sleep(_ context.Context, d time.Duration) error {
	c.sleeps = append(c.sleeps, d)
	c.now = c.now.Add(d)
	return nil
}

// fakeDialer returns the scripted results in order, then repeats the last one.
type fakeDialer struct {
	results  []error
	attempts int
}

func (f *fakeDialer) dial(_ context.Context, attempt int) error {
	f.attempts++
	if attempt != f.attempts {
		panic("attempt numbers must be 1-based and sequential")
	}
	i := attempt - 1
	if i >= len(f.results) {
		i = len(f.results) - 1
	}
	return f.results[i]
}

func denied() error {
	return &SSHError{ExitCode: 255, Stderr: "alice@ssh.example.com: Permission denied (publickey).\n"}
}

func TestKeyWaitDo(t *testing.T) {
	hostKey := &SSHError{ExitCode: 255, Stderr: "Host key verification failed.\n"}
	refused := &SSHError{ExitCode: 255, Stderr: "ssh: connect to host ssh.example.com port 22: Connection refused\n"}
	timeout := &SSHError{ExitCode: 255, Stderr: "ssh: connect to host ssh.example.com port 22: Operation timed out\n"}

	tests := []struct {
		name         string
		armed        bool
		window       time.Duration
		results      []error
		wantAttempts int
		wantErr      bool
		wantErrIs    error // nil = don't check
		wantErrText  []string
		wantStatus   bool // did the waiting line get printed?
	}{
		{
			name:         "first attempt succeeds: no output",
			armed:        true,
			window:       150 * time.Second,
			results:      []error{nil},
			wantAttempts: 1,
		},
		{
			name:         "succeeds on the third attempt",
			armed:        true,
			window:       150 * time.Second,
			results:      []error{denied(), denied(), nil},
			wantAttempts: 3,
			wantStatus:   true,
		},
		{
			name:         "never succeeds: error names the cause and the window",
			armed:        true,
			window:       150 * time.Second,
			results:      []error{denied()},
			wantAttempts: 31, // t=0,5,...,150s
			wantErr:      true,
			wantErrIs:    ErrKeyNotLearned,
			wantErrText:  []string{"sentinel", "2m30s", "keysync", "Permission denied (publickey)"},
			wantStatus:   true,
		},
		{
			name:         "host key failure fails at once with its own message",
			armed:        true,
			window:       150 * time.Second,
			results:      []error{hostKey, nil},
			wantAttempts: 1,
			wantErr:      true,
			wantErrText:  []string{"Host key verification failed"},
		},
		{
			name:         "connection refused fails at once",
			armed:        true,
			window:       150 * time.Second,
			results:      []error{refused, nil},
			wantAttempts: 1,
			wantErr:      true,
			wantErrText:  []string{"Connection refused"},
		},
		{
			name:         "timeout fails at once",
			armed:        true,
			window:       150 * time.Second,
			results:      []error{timeout, nil},
			wantAttempts: 1,
			wantErr:      true,
			wantErrText:  []string{"timed out"},
		},
		{
			name:         "non-ssh error fails at once",
			armed:        true,
			window:       150 * time.Second,
			results:      []error{errors.New("ssh not found in PATH"), nil},
			wantAttempts: 1,
			wantErr:      true,
			wantErrText:  []string{"ssh not found"},
		},
		{
			name:         "invocation that did not create or authorize fails at once",
			armed:        false,
			window:       150 * time.Second,
			results:      []error{denied(), nil},
			wantAttempts: 1,
			wantErr:      true,
			wantErrText:  []string{"Permission denied (publickey)"},
		},
		{
			name:         "window 0 disables the retry",
			armed:        true,
			window:       0,
			results:      []error{denied(), nil},
			wantAttempts: 1,
			wantErr:      true,
			wantErrText:  []string{"Permission denied (publickey)"},
		},
		{
			name:         "publickey then a different failure: stops at the different one",
			armed:        true,
			window:       150 * time.Second,
			results:      []error{denied(), refused, nil},
			wantAttempts: 2,
			wantErr:      true,
			wantErrText:  []string{"Connection refused"},
			wantStatus:   true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clk := &fakeClock{now: time.Unix(1_700_000_000, 0)}
			var status bytes.Buffer
			kw := KeyWait{
				Armed:    tc.armed,
				Window:   tc.window,
				Interval: 5 * time.Second,
				Status:   &status,
				Clock:    clk,
			}
			d := &fakeDialer{results: tc.results}
			err := kw.Do(context.Background(), d.dial)

			if d.attempts != tc.wantAttempts {
				t.Errorf("attempts = %d, want %d", d.attempts, tc.wantAttempts)
			}
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErrIs != nil && !errors.Is(err, tc.wantErrIs) {
				t.Errorf("err = %v, want errors.Is %v", err, tc.wantErrIs)
			}
			if tc.wantErrIs == nil && errors.Is(err, ErrKeyNotLearned) {
				t.Errorf("err = %v must not be ErrKeyNotLearned", err)
			}
			for _, s := range tc.wantErrText {
				if !strings.Contains(err.Error(), s) {
					t.Errorf("err %q does not contain %q", err.Error(), s)
				}
			}
			gotStatus := strings.Contains(status.String(), "waiting for the sentinel to learn your key (up to ~2 min)...")
			if gotStatus != tc.wantStatus {
				t.Errorf("status printed = %v, want %v (output %q)", gotStatus, tc.wantStatus, status.String())
			}
			if !tc.wantStatus && status.Len() != 0 {
				t.Errorf("expected no output, got %q", status.String())
			}
			if tc.wantStatus && strings.Count(status.String(), "\n") != 1 {
				t.Errorf("status must be ONE line updated in place (\\r), got %q", status.String())
			}
			var total time.Duration
			for _, s := range clk.sleeps {
				total += s
			}
			if total > tc.window {
				t.Errorf("slept %s in total, more than the %s window", total, tc.window)
			}
		})
	}
}

func TestKeyWaitDo_ContextCancelStopsWaiting(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	kw := KeyWait{Armed: true, Window: time.Minute, Interval: time.Second, Status: &bytes.Buffer{}, Clock: ctxClock{}}
	d := &fakeDialer{results: []error{denied()}}
	err := kw.Do(ctx, d.dial)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if d.attempts != 1 {
		t.Errorf("attempts = %d, want 1", d.attempts)
	}
}

// ctxClock honours cancellation the way the real clock does.
type ctxClock struct{}

func (ctxClock) Now() time.Time { return time.Unix(0, 0) }
func (ctxClock) Sleep(ctx context.Context, _ time.Duration) error {
	return ctx.Err()
}

func TestIsPublickeyDenied(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"ssh publickey", denied(), true},
		{"publickey among methods", &SSHError{ExitCode: 255, Stderr: "Permission denied (publickey,password).\n"}, true},
		{"wrapped", errors.Join(errors.New("ctx"), denied()), true},
		{"host key", &SSHError{ExitCode: 255, Stderr: "Host key verification failed.\n"}, false},
		{"remote command printed the text but exited 1", &SSHError{ExitCode: 1, Stderr: "Permission denied (publickey)."}, false},
		{"plain error text is not trusted", errors.New("Permission denied (publickey)"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsPublickeyDenied(tc.err); got != tc.want {
				t.Errorf("IsPublickeyDenied(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestResolveKeyWaitWindow(t *testing.T) {
	tests := []struct {
		name    string
		flag    string
		env     string
		want    time.Duration
		wantErr bool
	}{
		{"default", "", "", DefaultKeyWaitWindow, false},
		{"env overrides default", "", "60s", 60 * time.Second, false},
		{"flag overrides env", "30s", "60s", 30 * time.Second, false},
		{"zero disables", "0", "", 0, false},
		{"bare seconds", "90", "", 90 * time.Second, false},
		{"garbage flag", "soon", "", 0, true},
		{"negative", "-5s", "", 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveKeyWaitWindow(tc.flag, tc.env)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}
