package connectcore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// Key-propagation wait (#2013).
//
// Authorizing a key (or creating a box) updates the box's host-side
// authorized_keys at once, but the sentinel only mirrors it into sshpiper on
// its next keysync — up to a couple of minutes when the daemon's immediate
// resync notification is not wired or is lost. During that window ssh answers
// `Permission denied (publickey)` although nothing is wrong. KeyWait retries
// exactly that failure, for a bounded window, and only for an invocation that
// itself just created the box or authorized the key: an invocation that did
// neither has no reason to expect lag, so it fails once as before.

// DefaultKeyWaitWindow bounds the retry: comfortably over one keysync tick.
const DefaultKeyWaitWindow = 150 * time.Second

// DefaultKeyWaitInterval is the pause between attempts.
const DefaultKeyWaitInterval = 5 * time.Second

// KeyWaitEnv overrides the window when no flag is given ("0" disables).
const KeyWaitEnv = "CONTAINARIUM_KEY_WAIT"

// ErrKeyNotLearned is returned (wrapped) when the window ran out with ssh
// still answering publickey-denied.
var ErrKeyNotLearned = errors.New("the sentinel has not learned your key")

// SSHError is a failure of the local ssh client itself (exit 255), carrying
// what it printed on stderr so the failure can be classified.
type SSHError struct {
	ExitCode int
	Stderr   string
	// Err, when set, is the underlying process error; its message is kept
	// so a failure that is not retried reads exactly as it did before.
	Err error
}

func (e *SSHError) Unwrap() error { return e.Err }

func (e *SSHError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	msg := lastLine(e.Stderr)
	if msg == "" {
		return fmt.Sprintf("ssh exited %d", e.ExitCode)
	}
	return fmt.Sprintf("ssh exited %d: %s", e.ExitCode, msg)
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

// IsPublickeyDenied reports whether err is ssh's own "Permission denied
// (publickey…)" — the server rejected every key offered. Only an *SSHError
// with ssh's exit code 255 counts: a remote command that merely printed the
// same words is not an auth failure.
func IsPublickeyDenied(err error) bool {
	var se *SSHError
	if !errors.As(err, &se) || se.ExitCode != 255 {
		return false
	}
	return strings.Contains(se.Stderr, "Permission denied (publickey")
}

// Clock is the time source KeyWait uses; injected so tests never sleep.
type Clock interface {
	Now() time.Time
	Sleep(ctx context.Context, d time.Duration) error
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func (realClock) Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// KeyWait is the bounded retry of publickey denials.
type KeyWait struct {
	// Armed is true only when this invocation created the box or
	// authorized the key. Unarmed, Do makes exactly one attempt.
	Armed bool
	// Window bounds the retry; 0 disables it.
	Window time.Duration
	// Interval between attempts; DefaultKeyWaitInterval when 0.
	Interval time.Duration
	// Status receives the single in-place progress line; nil = discard.
	Status io.Writer
	// Clock defaults to the wall clock.
	Clock Clock
}

// Do calls dial (attempt is 1-based) until it succeeds, fails with anything
// other than a publickey denial, or — armed — the window runs out. Nothing is
// printed when the first attempt succeeds or fails for another reason.
func (k KeyWait) Do(ctx context.Context, dial func(ctx context.Context, attempt int) error) error {
	clk := k.Clock
	if clk == nil {
		clk = realClock{}
	}
	interval := k.Interval
	if interval <= 0 {
		interval = DefaultKeyWaitInterval
	}
	status := k.Status
	if status == nil {
		status = io.Discard
	}

	start := clk.Now()
	printed := false
	endLine := func() {
		if printed {
			fmt.Fprintln(status)
			printed = false
		}
	}
	for attempt := 1; ; attempt++ {
		err := dial(ctx, attempt)
		if err == nil || !k.Armed || k.Window <= 0 || !IsPublickeyDenied(err) {
			endLine()
			return err
		}
		elapsed := clk.Now().Sub(start)
		if elapsed >= k.Window {
			endLine()
			return fmt.Errorf("%w after waiting %s: ssh still answers publickey-denied. "+
				"A new box or key reaches the sentinel on its periodic keysync; if this persists, "+
				"check the key and the box with `containarium debug`, or raise the wait with --key-wait / %s: %w",
				ErrKeyNotLearned, k.Window, KeyWaitEnv, err)
		}
		fmt.Fprintf(status, "\rwaiting for the sentinel to learn your key (up to %s)... %ds",
			approxWindow(k.Window), int(elapsed.Round(time.Second)/time.Second))
		printed = true
		pause := interval
		if left := k.Window - elapsed; left < pause {
			pause = left
		}
		if serr := clk.Sleep(ctx, pause); serr != nil {
			endLine()
			return serr
		}
	}
}

// approxWindow renders the window the way a person reads it: 150s → "~2 min".
func approxWindow(d time.Duration) string {
	if d >= time.Minute {
		return fmt.Sprintf("~%d min", int(d/time.Minute))
	}
	return fmt.Sprintf("%ds", int(d/time.Second))
}

// ResolveKeyWaitWindow picks the window: the flag if set, else the
// CONTAINARIUM_KEY_WAIT value if set, else DefaultKeyWaitWindow. Both accept
// a Go duration ("90s", "3m") or bare seconds ("90"); "0" disables.
func ResolveKeyWaitWindow(flag, env string) (time.Duration, error) {
	src, v := "--key-wait", strings.TrimSpace(flag)
	if v == "" {
		src, v = KeyWaitEnv, strings.TrimSpace(env)
	}
	if v == "" {
		return DefaultKeyWaitWindow, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		n, nerr := strconv.Atoi(v)
		if nerr != nil {
			return 0, fmt.Errorf("%s %q: want a duration like 150s or 3m (0 disables)", src, v)
		}
		d = time.Duration(n) * time.Second
	}
	if d < 0 {
		return 0, fmt.Errorf("%s %q: must not be negative", src, v)
	}
	return d, nil
}
