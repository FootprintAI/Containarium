package sentinel

import (
	"fmt"
	"testing"
)

// TestPreferredOctet_Deterministic asserts the hash → slot mapping is
// stable across calls. The whole point of #342 is that a spot that
// disconnects and reconnects lands on the same loopback alias; that
// requires preferredOctet(id) to be a pure function of id.
func TestPreferredOctet_Deterministic(t *testing.T) {
	ids := []string{"spot-1", "spot-2", "tunnel-vm-alpha", "x"}
	for _, id := range ids {
		first := preferredOctet(id)
		for i := 0; i < 100; i++ {
			if got := preferredOctet(id); got != first {
				t.Fatalf("preferredOctet(%q) is non-deterministic: first=%d, again=%d", id, first, got)
			}
		}
		if first < 2 || first > 254 {
			t.Fatalf("preferredOctet(%q)=%d, want in [2, 254]", id, first)
		}
	}
}

// TestAllocateOctet_StableAcrossReconnect simulates the #342 scenario:
// a backend registers, fully unregisters (clearing usedIPs), and then
// reconnects. The new allocation must land on the same octet.
func TestAllocateOctet_StableAcrossReconnect(t *testing.T) {
	r := NewTunnelRegistry()
	first, err := r.allocateOctet("spot-A")
	if err != nil {
		t.Fatal(err)
	}

	// Simulate full unregister: drop the usedIPs entry.
	delete(r.usedIPs, first)

	second, err := r.allocateOctet("spot-A")
	if err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Fatalf("reconnect drift: first allocation = %d, post-disconnect reconnect = %d (want stable)", first, second)
	}
}

// TestAllocateOctet_NoDriftAcrossSequentialDisconnects guards against
// the original allocator bug — `nextIP` advanced monotonically, so
// 100 disconnect/reconnect cycles produced 100 different IPs even
// though only one was ever in use. With hashed allocation the slot
// should never change.
func TestAllocateOctet_NoDriftAcrossSequentialDisconnects(t *testing.T) {
	r := NewTunnelRegistry()
	const id = "spot-stable"

	first, err := r.allocateOctet(id)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 50; i++ {
		delete(r.usedIPs, first)
		got, err := r.allocateOctet(id)
		if err != nil {
			t.Fatalf("cycle %d: %v", i, err)
		}
		if got != first {
			t.Fatalf("cycle %d: drift from %d to %d", i, first, got)
		}
	}
}

// TestAllocateOctet_CollisionLinearProbes confirms the fallback path:
// when two distinct spotIDs hash to the same preferred slot, the
// second one falls forward to the next free octet. We can't easily
// force a hash collision against an arbitrary id, so we instead
// pre-occupy a spot's preferred slot and confirm it lands elsewhere.
func TestAllocateOctet_CollisionLinearProbes(t *testing.T) {
	r := NewTunnelRegistry()
	const id = "spot-collide"
	pref := preferredOctet(id)

	// Occupy the preferred slot with someone else.
	r.usedIPs[pref] = "squatter"

	got, err := r.allocateOctet(id)
	if err != nil {
		t.Fatal(err)
	}
	if got == pref {
		t.Fatalf("expected fallback away from occupied preferred slot %d, got %d", pref, got)
	}
	if got < 2 || got > 254 {
		t.Fatalf("allocation out of range: %d", got)
	}
}

// TestAllocateOctet_FullExhausted asserts the error path — once
// every slot is claimed, allocateOctet returns an error rather than
// looping forever or returning a bogus octet.
func TestAllocateOctet_FullExhausted(t *testing.T) {
	r := NewTunnelRegistry()
	for o := 2; o <= 254; o++ {
		r.usedIPs[byte(o)] = fmt.Sprintf("filler-%d", o)
	}
	_, err := r.allocateOctet("late-arrival")
	if err == nil {
		t.Fatal("expected error when all slots are occupied")
	}
}
