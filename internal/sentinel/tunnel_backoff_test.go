package sentinel

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestReconnectBackoff_EscalatesAcrossConsecutiveFailures(t *testing.T) {
	b := newReconnectBackoff()
	var got []time.Duration
	for i := 0; i < 9; i++ {
		got = append(got, b.next(0)) // every attempt failed immediately
	}
	assert.Equal(t, []time.Duration{
		1 * time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second,
		16 * time.Second, 32 * time.Second, 60 * time.Second, 60 * time.Second, 60 * time.Second,
	}, got, "delays double and stay at the cap")
}

// The production bug: a client that had been through many disconnects sat at
// the cap forever, even when each session before a disconnect was long and
// healthy, so every sentinel restart cost it a full minute.
func TestReconnectBackoff_ResetsAfterAStableSession(t *testing.T) {
	b := newReconnectBackoff()
	for i := 0; i < 8; i++ {
		b.next(0)
	}
	assert.Equal(t, 60*time.Second, b.next(0), "precondition: pinned at the cap")

	// The next session ran for an hour, then the sentinel restarted.
	assert.Equal(t, 1*time.Second, b.next(time.Hour), "a stable session resets the next delay to the initial value")
	// And escalation starts over from there, not from the cap.
	assert.Equal(t, 2*time.Second, b.next(0))
	assert.Equal(t, 4*time.Second, b.next(0))
}

func TestReconnectBackoff_ShortSessionDoesNotReset(t *testing.T) {
	b := newReconnectBackoff()
	b.next(0)
	b.next(0)
	b.next(0) // next would be 8s
	// A session that connected but died within the stability threshold is a
	// flapping peer, not a recovery: keep escalating.
	assert.Equal(t, 8*time.Second, b.next(reconnectStableAfter-time.Second))
	assert.Equal(t, 16*time.Second, b.next(0))
}

func TestReconnectBackoff_ThresholdIsInclusive(t *testing.T) {
	b := newReconnectBackoff()
	for i := 0; i < 5; i++ {
		b.next(0)
	}
	assert.Equal(t, 1*time.Second, b.next(reconnectStableAfter))
}

func TestJitterStaysWithinBounds(t *testing.T) {
	const d = 10 * time.Second
	for i := 0; i < 2000; i++ {
		got := jitterDelay(d)
		assert.GreaterOrEqual(t, got, d-d/5, "at most 20%% below")
		assert.LessOrEqual(t, got, d+d/5, "at most 20%% above")
	}
	assert.Equal(t, time.Duration(0), jitterDelay(0))
	// It must actually vary, or it is not jitter.
	seen := map[time.Duration]bool{}
	for i := 0; i < 200; i++ {
		seen[jitterDelay(d)] = true
	}
	assert.Greater(t, len(seen), 20)
}
