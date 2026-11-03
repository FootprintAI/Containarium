package incus

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Operation wait deadlines (#3470).
//
// op.Wait() on an Incus operation has no deadline of its own. A wedged
// operation (a stuck liblxc socket, a hung storage driver) used to hold the
// request goroutine, and any lock it held, forever. Every wait in this
// package now goes through waitOp, which bounds it by one of these classes.
// A caller that already has a context with a deadline (WaitOperation) gets
// that deadline instead.
//
// Hitting a deadline does not cancel the operation on the server: Incus may
// still finish it. The caller only stops waiting and gets an error that
// matches ErrOperationTimeout.
const (
	// DefaultOperationTimeout bounds control-plane operations that Incus
	// finishes in seconds when healthy: state changes (start, stop, freeze;
	// Incus's own action timeout for these is 30s), config, label and
	// device updates, renames, deletes. Ten minutes is far past the slowest
	// healthy case (deleting a large dataset with snapshots) while still
	// turning a wedge into an error.
	DefaultOperationTimeout = 10 * time.Minute

	// LongOperationTimeout bounds operations whose length grows with the
	// data they move: creating an instance (may pull and unpack an image),
	// publishing an image from an instance, creating a backup, importing an
	// instance from a backup. Multi-hour transfers of large boxes are
	// legitimate, so this is a ceiling against a wedge, not a performance
	// target.
	LongOperationTimeout = 6 * time.Hour

	// ExecOperationTimeout bounds a command run inside an instance with no
	// explicit timeout (Exec, ExecWithOutput, ExecWithExitCode). How long
	// it runs is up to the command (package installs, database dumps), not
	// Incus, so the ceiling is a day. ExecWithTimeout keeps its own
	// caller-chosen deadline.
	ExecOperationTimeout = 24 * time.Hour
)

// The deadlines waits actually use. vars, not consts, so tests can shrink
// them; production keeps the named defaults above.
var (
	opTimeout     = DefaultOperationTimeout
	longOpTimeout = LongOperationTimeout
	execOpTimeout = ExecOperationTimeout
)

// ErrOperationTimeout matches (errors.Is) every error a wait returns because
// its deadline passed before the operation completed. An operation that
// completed with an error returns that error instead, and a caller that
// cancels its context gets context.Canceled, so "timed out" can be told
// apart from "failed" and from "gave up".
var ErrOperationTimeout = errors.New("incus operation did not complete before its deadline")

// OperationTimeoutError is the error a wait returns on timeout. It matches
// ErrOperationTimeout and context.DeadlineExceeded.
type OperationTimeoutError struct {
	// Timeout is the deadline this package applied. Zero means the deadline
	// came from the caller's context.
	Timeout time.Duration
}

func (e *OperationTimeoutError) Error() string {
	if e.Timeout == 0 {
		return "incus operation did not complete before the caller's deadline (it may still finish on the server)"
	}
	return fmt.Sprintf("incus operation did not complete within %s (likely wedged; it may still finish on the server)", e.Timeout)
}

// Is makes errors.Is(err, ErrOperationTimeout) true.
func (e *OperationTimeoutError) Is(target error) bool { return target == ErrOperationTimeout }

// Unwrap makes errors.Is(err, context.DeadlineExceeded) true.
func (e *OperationTimeoutError) Unwrap() error { return context.DeadlineExceeded }

// OperationWaiter is the part of an Incus operation a wait needs.
// incus.Operation satisfies it.
type OperationWaiter interface {
	WaitContext(ctx context.Context) error
}

// WaitOperation waits for op until ctx's deadline, or for
// DefaultOperationTimeout when ctx has none. For code outside this package
// that holds a raw Incus operation.
func WaitOperation(ctx context.Context, op OperationWaiter) error {
	return waitOp(ctx, op, opTimeout)
}

// waitOp waits for op to complete. ctx's own deadline wins; without one,
// fallback applies. It returns op's own result when op completes in time,
// an *OperationTimeoutError when the deadline passes first, and ctx's error
// when the caller cancels.
//
// The wait runs in a goroutine so the bound holds even for an operation
// whose WaitContext does not watch ctx. Incus's does, so that goroutine
// normally ends with the wait.
func waitOp(ctx context.Context, op OperationWaiter, fallback time.Duration) error {
	if ctx == nil {
		ctx = context.Background()
	}
	var applied time.Duration
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, fallback)
		defer cancel()
		applied = fallback
	}

	done := make(chan error, 1)
	go func() { done <- op.WaitContext(ctx) }()

	var err error
	select {
	case err = <-done:
	case <-ctx.Done():
		select {
		case err = <-done: // finished at the deadline: keep its own result
		default:
			err = ctx.Err()
		}
	}
	if err != nil && errors.Is(err, context.DeadlineExceeded) && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return &OperationTimeoutError{Timeout: applied}
	}
	return err
}
