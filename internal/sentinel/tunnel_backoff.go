package sentinel

import (
	cryptorand "crypto/rand"
	"math/big"
	"time"
)

const (
	reconnectInitialDelay = 1 * time.Second
	reconnectMaxDelay     = 60 * time.Second
	// reconnectStableAfter is how long a session must have lasted for its
	// disconnect to count as "the sentinel went away" and not "the connection
	// is flapping". A session at least this long resets the backoff.
	reconnectStableAfter = 30 * time.Second
)

// reconnectBackoff is the tunnel client's reconnect delay policy. Delays double
// across CONSECUTIVE failed or short-lived sessions, up to a cap, and start over
// after a session that stayed up. Without the reset a client that had been
// through enough disconnects over its life stayed at the cap forever, so every
// later sentinel restart cost it a full minute however healthy it had been.
type reconnectBackoff struct {
	cur time.Duration
}

func newReconnectBackoff() *reconnectBackoff {
	return &reconnectBackoff{cur: reconnectInitialDelay}
}

// next returns how long to wait before the next connection attempt, given how
// long the session that just ended lasted (0 for an attempt that never
// connected).
func (b *reconnectBackoff) next(sessionLasted time.Duration) time.Duration {
	if sessionLasted >= reconnectStableAfter {
		b.cur = reconnectInitialDelay
	}
	d := b.cur
	b.cur *= 2
	if b.cur > reconnectMaxDelay {
		b.cur = reconnectMaxDelay
	}
	return d
}

// jitterDelay spreads d by up to ±20% so several clients that lost the same
// sentinel do not all retry in the same instant. It reads crypto/rand because
// the cost is irrelevant at reconnect frequency and it keeps the weak-RNG
// scanner quiet; if the read ever fails it returns d unjittered.
func jitterDelay(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	span := int64(d / 5)
	n, err := cryptorand.Int(cryptorand.Reader, big.NewInt(2*span+1))
	if err != nil {
		return d
	}
	return d - time.Duration(span) + time.Duration(n.Int64())
}
