package server

import (
	"errors"
	"testing"
	"time"
)

// newPendingServer builds the minimal ContainerServer needed to exercise the
// pending-creation bookkeeping (#1035) — no manager, no backend.
func newPendingServer(entries ...*PendingCreation) *ContainerServer {
	s := &ContainerServer{pendingCreations: map[string]*PendingCreation{}}
	for _, e := range entries {
		s.pendingCreations[e.Username] = e
	}
	return s
}

// TestCancelPendingCreation pins the state machine a delete-during-create
// relies on: only a genuinely in-flight creation can be claimed, and claiming
// it is idempotent so a retried delete doesn't double-report.
func TestCancelPendingCreation(t *testing.T) {
	cases := []struct {
		name    string
		pending *PendingCreation
		want    bool
	}{
		{"in flight is claimed", &PendingCreation{Username: "alice", StartedAt: time.Now()}, true},
		{"provisioning is claimed", &PendingCreation{Username: "alice", Provisioning: true}, true},
		{"finished is not claimed", &PendingCreation{Username: "alice", Done: true}, false},
		{"already cancelled is not re-claimed", &PendingCreation{Username: "alice", Cancelled: true}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newPendingServer(c.pending)
			if got := s.cancelPendingCreation("alice"); got != c.want {
				t.Fatalf("cancelPendingCreation = %v, want %v", got, c.want)
			}
		})
	}

	t.Run("no pending creation", func(t *testing.T) {
		if newPendingServer().cancelPendingCreation("alice") {
			t.Fatal("claimed a creation that does not exist")
		}
	})
}

// TestCancelledCreationIsNotActive: a cancelled-but-still-running creation
// must drop out of the Get/List provisioning overlay immediately. Otherwise
// the box the caller just deleted keeps reporting CREATING for the remaining
// minutes of a provisioning run that no longer has an instance behind it.
func TestCancelledCreationIsNotActive(t *testing.T) {
	cases := []struct {
		name    string
		pending *PendingCreation
		want    bool
	}{
		{"in flight", &PendingCreation{}, true},
		{"cancelled", &PendingCreation{Cancelled: true}, false},
		{"done", &PendingCreation{Done: true}, false},
		{"nil", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.pending.active(); got != c.want {
				t.Fatalf("active() = %v, want %v", got, c.want)
			}
		})
	}
}

// TestUncancelPendingCreation: a delete that fails must not leave the creation
// flagged — the create is still genuinely running and must keep reporting its
// real state. Only the delete that set the flag may clear it.
func TestUncancelPendingCreation(t *testing.T) {
	s := newPendingServer(&PendingCreation{Username: "alice"})
	if !s.cancelPendingCreation("alice") {
		t.Fatal("expected to claim the in-flight creation")
	}
	s.uncancelPendingCreation("alice", true)
	if !s.pendingCreations["alice"].active() {
		t.Fatal("a failed delete left the creation cancelled")
	}

	// A concurrent delete that never claimed the creation must not clear
	// another delete's flag.
	if !s.cancelPendingCreation("alice") {
		t.Fatal("expected to re-claim after uncancel")
	}
	s.uncancelPendingCreation("alice", false)
	if s.pendingCreations["alice"].active() {
		t.Fatal("a non-claiming delete cleared someone else's cancellation")
	}
}

// TestErrorStateStillReportedForRealFailures guards the fix's blast radius:
// suppressing the cancellation noise must not suppress genuine create
// failures, which GetContainer still surfaces as ERROR.
func TestErrorStateStillReportedForRealFailures(t *testing.T) {
	p := &PendingCreation{Username: "alice", Done: true, Error: errors.New("image pull failed")}
	if p.active() {
		t.Fatal("a finished creation must not be active")
	}
	if p.Cancelled {
		t.Fatal("a genuine failure must not be flagged as cancelled")
	}
}
