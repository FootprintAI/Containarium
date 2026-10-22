package tracker

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// An ambiguous upstream create (#2045): the request reached the forge but
// no answer came back before the budget, so the issue may exist upstream.
// RecordChild must say so with ErrUpstreamOutcomeUnknown and keep the
// fan-out slot claimed, so a blind retry cannot file past the cap.
func TestRecordChild_AmbiguousCreateKeepsTheSlotAndSaysOutcomeUnknown(t *testing.T) {
	store, ctx := newTrackerTestStore(t)
	const user = "tracker-store-outcome-unknown"
	resetReservationFixture(t, store, ctx, user)
	l := Lineage{Username: user, Connection: "default", ParentNumber: 10, CreatedByRun: "run-slow-forge"}

	_, err := store.RecordChild(ctx, l, 0, 1, func(context.Context) (int64, error) {
		// What the adapters return when the HTTP client's timeout fires
		// after the POST was sent.
		return 0, fmt.Errorf("%w: %w", ErrUnreachable, context.DeadlineExceeded)
	})
	if !errors.Is(err, ErrUpstreamOutcomeUnknown) {
		t.Fatalf("RecordChild err = %v, want ErrUpstreamOutcomeUnknown", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("RecordChild err = %v, want the upstream cause kept in the chain", err)
	}
	rows, err := store.ListLineageReservations(ctx, user, "default")
	if err != nil {
		t.Fatalf("ListLineageReservations: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("reservations after an ambiguous create = %d, want 1 (the slot stays claimed)", len(rows))
	}

	called := false
	_, err = store.RecordChild(ctx, l, 0, 1, func(context.Context) (int64, error) { called = true; return 77, nil })
	if !errors.Is(err, ErrFanoutExceeded) {
		t.Fatalf("retry after an ambiguous create: err = %v, want ErrFanoutExceeded", err)
	}
	if called {
		t.Error("retry reached the upstream create; the cap must reject it first")
	}
}

// A definite upstream failure (the forge answered with an error) still
// frees the slot: nothing was created, so the run may try again.
func TestRecordChild_DefiniteFailureReleasesTheSlot(t *testing.T) {
	store, ctx := newTrackerTestStore(t)
	const user = "tracker-store-definite-failure"
	resetReservationFixture(t, store, ctx, user)
	l := Lineage{Username: user, Connection: "default", ParentNumber: 10, CreatedByRun: "run-rejected"}

	_, err := store.RecordChild(ctx, l, 0, 1, func(context.Context) (int64, error) {
		return 0, errors.New("github: HTTP 422: validation failed")
	})
	if err == nil || errors.Is(err, ErrUpstreamOutcomeUnknown) {
		t.Fatalf("RecordChild err = %v, want a plain (definite) failure", err)
	}
	if rows, _ := store.ListLineageReservations(ctx, user, "default"); len(rows) != 0 {
		t.Fatalf("reservations after a definite failure = %d, want 0", len(rows))
	}
}

func TestIsAmbiguousUpstreamError(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"deadline", context.DeadlineExceeded, true},
		{"wrapped deadline", fmt.Errorf("%w: %w", ErrUnreachable, context.DeadlineExceeded), true},
		{"net timeout", fmt.Errorf("%w: %w", ErrUnreachable, timeoutErr{}), true},
		{"http status", errors.New("github: HTTP 500: boom"), false},
		{"credential", ErrCredentialInvalid, false},
		{"refused", fmt.Errorf("%w: connection refused", ErrUnreachable), false},
	} {
		if got := IsAmbiguousUpstreamError(c.err); got != c.want {
			t.Errorf("%s: IsAmbiguousUpstreamError(%v) = %v, want %v", c.name, c.err, got, c.want)
		}
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }
