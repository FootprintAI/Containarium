package cmd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/connectcore"
	"github.com/spf13/cobra"
)

// stepClock is an injected clock for the cmd-level key-wait tests: Sleep
// advances Now instantly, so no test really sleeps.
type stepClock struct{ now time.Time }

func (c *stepClock) Now() time.Time { return c.now }
func (c *stepClock) Sleep(_ context.Context, d time.Duration) error {
	c.now = c.now.Add(d)
	return nil
}

func pkDenied() error {
	return &connectcore.SSHError{ExitCode: 255, Stderr: "Permission denied (publickey).\n"}
}

// scripted returns results in order, repeating the last.
func scripted(results ...error) (func() error, *int) {
	n := 0
	return func() error {
		i := n
		if i >= len(results) {
			i = len(results) - 1
		}
		n++
		return results[i]
	}, &n
}

func withProbe(t *testing.T, probe func(context.Context, []string) error) {
	t.Helper()
	orig := sshProbeFn
	t.Cleanup(func() { sshProbeFn = orig })
	sshProbeFn = probe
}

func TestSSHWithKeyWait(t *testing.T) {
	tests := []struct {
		name        string
		armed       bool
		ops         []error // real ssh invocation results
		probes      []error // auth-probe results
		wantOps     int
		wantErr     bool
		wantErrIs   error
		wantRemote  bool // error is the pass-through remote exit
		wantWaiting bool
	}{
		{
			name:    "first attempt succeeds: no probe, no output",
			armed:   true,
			ops:     []error{nil},
			probes:  []error{errors.New("probe must not run")},
			wantOps: 1,
		},
		{
			name:  "lag: denied, probe denied twice, then connects",
			armed: true,
			ops:   []error{pkDenied(), nil},
			// confirm (denied), attempt-2 probe (denied), attempt-3 probe (ok)
			probes:      []error{pkDenied(), pkDenied(), nil},
			wantOps:     2,
			wantWaiting: true,
		},
		{
			name:        "never learned: names the window",
			armed:       true,
			ops:         []error{pkDenied()},
			probes:      []error{pkDenied()},
			wantOps:     1,
			wantErr:     true,
			wantErrIs:   connectcore.ErrKeyNotLearned,
			wantWaiting: true,
		},
		{
			name:       "remote command printed the words and exited 255: our auth works, not retried",
			armed:      true,
			ops:        []error{pkDenied(), nil},
			probes:     []error{nil},
			wantOps:    1,
			wantErr:    true,
			wantRemote: true,
		},
		{
			name:    "host key failure: not retried",
			armed:   true,
			ops:     []error{&connectcore.SSHError{ExitCode: 255, Stderr: "Host key verification failed.\n"}, nil},
			probes:  []error{errors.New("probe must not run")},
			wantOps: 1,
			wantErr: true,
		},
		{
			name:    "unarmed: publickey fails once",
			armed:   false,
			ops:     []error{pkDenied(), nil},
			probes:  []error{errors.New("probe must not run")},
			wantOps: 1,
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			probe, _ := scripted(tc.probes...)
			withProbe(t, func(context.Context, []string) error { return probe() })
			op, nOps := scripted(tc.ops...)
			var status bytes.Buffer
			kw := connectcore.KeyWait{
				Armed: tc.armed, Window: 150 * time.Second, Interval: 5 * time.Second,
				Status: &status, Clock: &stepClock{now: time.Unix(0, 0)},
			}
			err := sshWithKeyWait(context.Background(), kw, []string{"probe"}, op)
			if *nOps != tc.wantOps {
				t.Errorf("real ssh ran %d times, want %d", *nOps, tc.wantOps)
			}
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if err != nil && strings.Contains(err.Error(), "probe must not run") {
				t.Fatalf("probe ran when it should not have: %v", err)
			}
			if tc.wantErrIs != nil && !errors.Is(err, tc.wantErrIs) {
				t.Errorf("err = %v, want %v", err, tc.wantErrIs)
			}
			var re *remoteExitError
			if got := errors.As(err, &re); got != tc.wantRemote {
				t.Errorf("remote exit pass-through = %v, want %v (err %v)", got, tc.wantRemote, err)
			}
			if got := strings.Contains(status.String(), "waiting for the sentinel to learn your key"); got != tc.wantWaiting {
				t.Errorf("waiting line = %v, want %v (%q)", got, tc.wantWaiting, status.String())
			}
		})
	}
}

func TestCodeInstall_RetriesPublickeyAfterAuthorize(t *testing.T) {
	origSSH, origResolve, origClock := sshExec, resolveCodeTargetFn, keyWaitClock
	origBootstrap, origRelease, origVersion, origWait := codeBootstrapURL, codeRelease, codeClaudeCodeVersion, codeKeyWait
	t.Cleanup(func() {
		sshExec, resolveCodeTargetFn, keyWaitClock = origSSH, origResolve, origClock
		codeBootstrapURL, codeRelease, codeClaudeCodeVersion, codeKeyWait = origBootstrap, origRelease, origVersion, origWait
	})
	codeBootstrapURL, codeRelease, codeClaudeCodeVersion, codeKeyWait = "", "", "", ""
	t.Setenv(connectcore.KeyWaitEnv, "")
	keyWaitClock = &stepClock{now: time.Unix(0, 0)}

	resolveCodeTargetFn = func(context.Context, string, io.Writer) (connectcore.Target, string, error) {
		return connectcore.Target{User: "alice", Host: "box.example.test", Port: 22}, "/dev/null", nil
	}
	calls := 0
	sshExec = func(_ io.Writer, _ []string) (string, error) {
		calls++
		if calls == 1 {
			return "", pkDenied()
		}
		return "1.2.3 (Claude Code)\ncredential sources present:\n  (none)", nil
	}
	probe, _ := scripted(pkDenied(), pkDenied(), nil)
	withProbe(t, func(context.Context, []string) error { return probe() })

	cmd := &cobra.Command{}
	var out, stderr bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&stderr)
	cmd.SetContext(context.Background())
	if err := runCodeInstall(cmd, []string{"alice"}); err != nil {
		t.Fatalf("install failed despite the key landing: %v", err)
	}
	if !strings.Contains(stderr.String(), "waiting for the sentinel to learn your key") {
		t.Errorf("expected the waiting line on stderr, got %q", stderr.String())
	}
}

func TestResolveCodeKeyWait_FlagAndEnv(t *testing.T) {
	orig := codeKeyWait
	t.Cleanup(func() { codeKeyWait = orig })

	t.Setenv(connectcore.KeyWaitEnv, "40s")
	codeKeyWait = ""
	kw, err := newKeyWait(codeKeyWait, true, &bytes.Buffer{})
	if err != nil || kw.Window != 40*time.Second || !kw.Armed {
		t.Fatalf("env: kw=%+v err=%v", kw, err)
	}
	codeKeyWait = "0"
	kw, err = newKeyWait(codeKeyWait, true, &bytes.Buffer{})
	if err != nil || kw.Window != 0 {
		t.Fatalf("flag 0: kw=%+v err=%v", kw, err)
	}
}
