package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"

	"github.com/footprintai/containarium/internal/connectcore"
)

// Key-propagation wait for the CLI's ssh paths (#2013): `connect`, `code *`
// and `quickstart`. The retry policy itself lives in connectcore.KeyWait;
// this file adapts it to the local ssh binary.

const keyWaitFlagUsage = "how long to keep retrying `Permission denied (publickey)` right after this command authorized your key or created the box, while the sentinel learns the key (e.g. 150s, 3m; 0 disables; default 150s, or $" + connectcore.KeyWaitEnv + ")"

// keyWaitClock is a test seam; nil means the wall clock.
var keyWaitClock connectcore.Clock

// newKeyWait builds the retry policy for one invocation. armed must be true
// only when this invocation itself created the box or authorized the key.
func newKeyWait(flag string, armed bool, status io.Writer) (connectcore.KeyWait, error) {
	window, err := connectcore.ResolveKeyWaitWindow(flag, os.Getenv(connectcore.KeyWaitEnv))
	if err != nil {
		return connectcore.KeyWait{}, err
	}
	return connectcore.KeyWait{Armed: armed, Window: window, Status: status, Clock: keyWaitClock}, nil
}

// remoteExitError is a non-zero exit that is NOT the ssh client failing to
// get in: the remote command's own exit code, to be propagated verbatim.
type remoteExitError struct {
	code int
	err  error // the process error, kept for its message; may be nil
}

func (e *remoteExitError) Error() string {
	if e.err != nil {
		return e.err.Error()
	}
	return fmt.Sprintf("remote command exited %d", e.code)
}

func (e *remoteExitError) Unwrap() error { return e.err }

// probeSSHArgs turns an ssh argv (options + destination, no remote command)
// into a silent auth check: BatchMode so nothing prompts, a connect timeout
// so a dead host is a fast non-publickey failure, and `true` as the command.
func probeSSHArgs(base []string) []string {
	args := []string{"-o", "BatchMode=yes", "-o", "ConnectTimeout=15"}
	args = append(args, base...)
	return append(args, "true")
}

// sshProbeFn runs a probe argv (from probeSSHArgs) with stderr captured.
// Test seam.
var sshProbeFn = runSSHProbe

func runSSHProbe(ctx context.Context, args []string) error {
	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		return fmt.Errorf("ssh not found in PATH: %w", err)
	}
	// #nosec G204 -- sshBin is the resolved `ssh` binary; args are the
	// same daemon-resolved target the real invocation uses, plus fixed
	// options and the fixed remote command `true`.
	c := exec.CommandContext(ctx, sshBin, args...)
	var stderr bytes.Buffer
	c.Stderr = &stderr
	return classifySSHRun(c.Run(), stderr.String())
}

// classifySSHRun maps an ssh process result: exit 255 is ssh itself failing
// (*connectcore.SSHError, classifiable), any other non-zero exit is the
// remote command's (*remoteExitError), anything else is returned as is.
func classifySSHRun(runErr error, stderr string) error {
	if runErr == nil {
		return nil
	}
	var ee *exec.ExitError
	if !errors.As(runErr, &ee) {
		return runErr
	}
	if ee.ExitCode() == 255 {
		return &connectcore.SSHError{ExitCode: 255, Stderr: stderr, Err: runErr}
	}
	return &remoteExitError{code: ee.ExitCode(), err: runErr}
}

// sshWithKeyWait runs op — one real ssh invocation whose stderr the user
// sees — under kw. A publickey denial is first confirmed with a probe (so a
// remote command that printed the same words and exited 255 is passed
// through, never re-run); while the key is still unknown, later attempts
// probe silently and re-run op only once the probe gets in, so the user sees
// one updating status line instead of a denial per attempt.
func sshWithKeyWait(ctx context.Context, kw connectcore.KeyWait, probeArgs []string, op func() error) error {
	return kw.Do(ctx, func(ctx context.Context, attempt int) error {
		if attempt > 1 {
			if err := sshProbeFn(ctx, probeArgs); err != nil {
				return err
			}
		}
		err := op()
		if kw.Armed && kw.Window > 0 && connectcore.IsPublickeyDenied(err) {
			if perr := sshProbeFn(ctx, probeArgs); perr == nil {
				// Keep the process error for its message, but NOT the
				// SSHError itself: this must no longer classify as a denial.
				var se *connectcore.SSHError
				errors.As(err, &se)
				return &remoteExitError{code: 255, err: se.Err}
			}
		}
		return err
	})
}

// tailWriter passes writes through to dst and keeps the last few KiB, so
// ssh's diagnostics reach the user unchanged AND can be classified after.
type tailWriter struct {
	mu  sync.Mutex
	dst io.Writer
	buf []byte
}

const tailWriterMax = 4096

func (w *tailWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.buf = append(w.buf, p...)
	if len(w.buf) > tailWriterMax {
		w.buf = w.buf[len(w.buf)-tailWriterMax:]
	}
	w.mu.Unlock()
	return w.dst.Write(p)
}

func (w *tailWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return string(w.buf)
}

// exitForSSHError reproduces the pre-#2013 behaviour for a failure that is
// not retried: ssh already printed its own message, so exit with its code.
// A KeyNotLearned error (window ran out) and non-exit errors are returned
// for cobra to print.
func exitForSSHError(err error) error {
	if err == nil {
		return nil
	}
	var re *remoteExitError
	if errors.As(err, &re) {
		os.Exit(re.code)
	}
	var se *connectcore.SSHError
	if errors.As(err, &se) && !errors.Is(err, connectcore.ErrKeyNotLearned) {
		os.Exit(se.ExitCode)
	}
	return err
}

// waitForKeyByProbe blocks until a silent probe gets in (armed), the window
// runs out, or the probe fails for another reason. For callers that have no
// "real" ssh invocation of their own to retry (quickstart).
func waitForKeyByProbe(ctx context.Context, kw connectcore.KeyWait, probeArgs []string) error {
	return kw.Do(ctx, func(ctx context.Context, _ int) error {
		return sshProbeFn(ctx, probeArgs)
	})
}

// runSSHTee runs ssh with the given stdio, passing stderr through to the user
// while keeping its tail, and classifies the result (classifySSHRun).
func runSSHTee(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, args []string) error {
	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		return fmt.Errorf("ssh not found in PATH: %w", err)
	}
	// #nosec G204 -- sshBin is the resolved `ssh` binary; args are built from
	// a validated box name + daemon-resolved target + user flags. Running ssh
	// is precisely the caller's job.
	c := exec.CommandContext(ctx, sshBin, args...)
	c.Stdin = stdin
	c.Stdout = stdout
	tw := &tailWriter{dst: stderr}
	c.Stderr = tw
	return classifySSHRun(c.Run(), tw.String())
}
