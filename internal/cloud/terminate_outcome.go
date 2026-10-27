package cloud

import (
	"context"
	"errors"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelmetric "go.opentelemetry.io/otel/metric"
)

// ErrUserNotMapped is returned by a SessionTerminator when the assignment's
// user_id resolves to no local login on this host (#2602): neither a login
// recorded from a managed AuthorizeSSH decision nor a known local user. The
// reconciler reports it apart from a walk that ended no sessions.
var ErrUserNotMapped = errors.New("user id maps to no local login on this host")

// terminationOutcome is what one TERMINATE_USER_SESSIONS delivery did.
type terminationOutcome int

const (
	terminationIgnored  terminationOutcome = iota // no terminator wired, or no user_id
	terminationReplayed                           // assignment_id already handled; no-op
	terminationEnded                              // walk ran (it may have found no live session)
	terminationUnmapped                           // user_id maps to no local login
	terminationFailed                             // walk failed; the next delivery retries
)

func (o terminationOutcome) String() string {
	switch o {
	case terminationReplayed:
		return "replayed"
	case terminationEnded:
		return "ended"
	case terminationUnmapped:
		return "unmapped"
	case terminationFailed:
		return "failed"
	default:
		return "ignored"
	}
}

var (
	terminationCounterOnce sync.Once
	terminationCounter     otelmetric.Int64Counter
)

// recordTerminationOutcome counts a handled assignment on the daemon's global
// OTel meter (a no-op provider when monitoring is off), labelled by outcome.
func recordTerminationOutcome(ctx context.Context, o terminationOutcome) {
	terminationCounterOnce.Do(func() {
		c, err := otel.GetMeterProvider().Meter("containarium").Int64Counter("ssh_sessions.terminate_assignments",
			otelmetric.WithDescription("TERMINATE_USER_SESSIONS assignments handled, by outcome (ended, unmapped, failed)"))
		if err == nil {
			terminationCounter = c
		}
	})
	if terminationCounter != nil {
		terminationCounter.Add(ctx, 1, otelmetric.WithAttributes(attribute.String("outcome", o.String())))
	}
}
