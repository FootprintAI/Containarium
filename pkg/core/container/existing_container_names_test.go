package container

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// countingListBackend embeds UnavailableBackend (every other method returns
// ErrUnavailable, none of which ExistingContainerNames calls) and overrides
// only ListContainers, counting real calls so tests can prove batching.
type countingListBackend struct {
	*incus.UnavailableBackend
	calls atomic.Int32
	names []string
	err   error
}

func newCountingListBackend(names ...string) *countingListBackend {
	return &countingListBackend{UnavailableBackend: incus.NewUnavailableBackend(), names: names}
}

func (b *countingListBackend) ListContainers() ([]incus.ContainerInfo, error) {
	b.calls.Add(1)
	if b.err != nil {
		return nil, b.err
	}
	out := make([]incus.ContainerInfo, len(b.names))
	for i, n := range b.names {
		out[i] = incus.ContainerInfo{Name: n}
	}
	return out, nil
}

// TestExistingContainerNames_BatchesWithinTTL is the regression guard for
// the /authorized-keys latency this exists to fix: many lookups inside one
// TTL window must cost exactly one ListContainers call, not one per lookup.
func TestExistingContainerNames_BatchesWithinTTL(t *testing.T) {
	backend := newCountingListBackend("alice-container", "bob-container")
	m := NewWithBackend(backend)

	const lookups = 50
	for i := 0; i < lookups; i++ {
		names, err := m.ExistingContainerNames()
		if err != nil {
			t.Fatalf("lookup %d: %v", i, err)
		}
		if !names["alice-container"] || !names["bob-container"] {
			t.Fatalf("lookup %d: missing expected names: %v", i, names)
		}
		if names["orphan-container"] {
			t.Fatalf("lookup %d: unexpected name present: %v", i, names)
		}
	}
	if got := backend.calls.Load(); got != 1 {
		t.Fatalf("ListContainers called %d times for %d lookups within the TTL, want 1", got, lookups)
	}
}

// TestExistingContainerNames_RefreshesAfterTTL proves the cache is not
// permanent: past the TTL, a lookup must trigger a fresh ListContainers
// call, so a deleted container is eventually reflected (bounded staleness,
// not indefinite staleness).
func TestExistingContainerNames_RefreshesAfterTTL(t *testing.T) {
	backend := newCountingListBackend("alice-container")
	m := NewWithBackend(backend)
	m.nameCacheTTL = 20 * time.Millisecond // test seam, not the real 2s default

	if _, err := m.ExistingContainerNames(); err != nil {
		t.Fatal(err)
	}
	if got := backend.calls.Load(); got != 1 {
		t.Fatalf("after first call: ListContainers called %d times, want 1", got)
	}

	time.Sleep(30 * time.Millisecond)
	backend.names = nil // simulate alice's container having been deleted
	names, err := m.ExistingContainerNames()
	if err != nil {
		t.Fatal(err)
	}
	if got := backend.calls.Load(); got != 2 {
		t.Fatalf("after TTL expiry: ListContainers called %d times, want 2", got)
	}
	if names["alice-container"] {
		t.Error("expected alice-container to be gone from the refreshed snapshot")
	}
}

// TestExistingContainerNames_ServesStaleSnapshotOnRefreshError is the
// blast-radius guard: a batched check that failed open by dropping every
// tenant on one Incus hiccup would be strictly worse than the per-container
// ContainerExists it replaces (which only ever failed one tenant at a time).
// A refresh error after at least one successful snapshot must serve that
// last-good snapshot, not propagate the error.
func TestExistingContainerNames_ServesStaleSnapshotOnRefreshError(t *testing.T) {
	backend := newCountingListBackend("alice-container")
	m := NewWithBackend(backend)
	m.nameCacheTTL = 20 * time.Millisecond

	if _, err := m.ExistingContainerNames(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	backend.err = errors.New("incus: connection refused")

	names, err := m.ExistingContainerNames()
	if err != nil {
		t.Fatalf("expected the stale-but-good snapshot to be served, got error: %v", err)
	}
	if !names["alice-container"] {
		t.Errorf("expected the last-good snapshot to still list alice-container, got %v", names)
	}
}

// TestExistingContainerNames_PropagatesErrorWithNoPriorSnapshot is the other
// half: with nothing cached yet (e.g. right after daemon start with Incus
// unreachable), there is no stale snapshot to fall back to, so the error
// must surface rather than silently returning an empty (all-orphan) set.
func TestExistingContainerNames_PropagatesErrorWithNoPriorSnapshot(t *testing.T) {
	backend := newCountingListBackend()
	backend.err = errors.New("incus: connection refused")
	m := NewWithBackend(backend)

	if _, err := m.ExistingContainerNames(); err == nil {
		t.Fatal("expected an error with no prior snapshot to fall back to")
	}
}
