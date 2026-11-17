package guardraildropin

import (
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"time"
)

// DefaultExecTimeout bounds one command inside a box.
const DefaultExecTimeout = 10 * time.Second

// execGrace is how long the daemon waits past the in-box deadline before it
// stops waiting for the exec to return.
const execGrace = 5 * time.Second

// pushTimeout bounds one file push. The hook binary is large.
const pushTimeout = 2 * time.Minute

// errExecTimeout is a command in a box that did not finish in time.
var errExecTimeout = errors.New("timed out")

// Box is the daemon's root path into a box: exec and file push as root.
// *incus.Client satisfies it.
type Box interface {
	ExecWithExitCode(container string, command []string) (stdout, stderr string, exitCode int, err error)
	WriteFile(container, path string, content []byte, mode string) error
	PushFile(container, path string, content io.ReadSeeker, mode string) error
}

// runner runs commands as root in a box, each under two deadlines. Much of
// what the check reads is chosen by the box user (a managed file can be a
// link to a FIFO, the client binary is the user's own file), and the
// daemon's exec has no useful deadline of its own.
//
//   - `timeout` inside the box kills the command, so nothing is left running;
//   - a timer on the daemon's side stops the wait if even that does not
//     return. The exec's goroutine is then left to finish by itself.
type runner struct {
	box     Box
	timeout time.Duration
	grace   time.Duration
}

type execResult struct {
	out  string
	code int
	err  error
}

// run executes argv. A non-zero exit is not an error; a timeout is.
func (r runner) run(container string, argv ...string) (string, int, error) {
	secs := strconv.Itoa(int(math.Ceil(r.timeout.Seconds())))
	full := append([]string{"timeout", "-k", "2", secs}, argv...)
	ch := make(chan execResult, 1)
	go func() {
		out, _, code, err := r.box.ExecWithExitCode(container, full)
		ch <- execResult{out, code, err}
	}()
	select {
	case v := <-ch:
		switch {
		case v.err != nil:
			return "", v.code, fmt.Errorf("%s in %q: %w", argv[0], container, v.err)
		case v.code == 124 || v.code == 137: // timeout(1): timed out, or killed after -k
			return "", v.code, fmt.Errorf("%s in %q: %w", argv[0], container, errExecTimeout)
		}
		return v.out, v.code, nil
	case <-time.After(r.timeout + r.grace):
		return "", -1, fmt.Errorf("%s in %q: %w", argv[0], container, errExecTimeout)
	}
}

// mustRun is run for a command whose non-zero exit is a failure.
func (r runner) mustRun(container string, argv ...string) error {
	_, code, err := r.run(container, argv...)
	if err == nil && code != 0 {
		err = fmt.Errorf("%s in %q: exit %d", argv[0], container, code)
	}
	return err
}

// script runs a POSIX shell script with positional arguments.
func (r runner) script(container, script string, args ...string) (string, int, error) {
	return r.run(container, append([]string{"sh", "-c", script, "sh"}, args...)...)
}

// push runs a file push under pushTimeout.
func (r runner) push(container string, do func() error) error {
	ch := make(chan error, 1)
	go func() { ch <- do() }()
	select {
	case err := <-ch:
		return err
	case <-time.After(pushTimeout):
		return fmt.Errorf("file push to %q: %w", container, errExecTimeout)
	}
}
