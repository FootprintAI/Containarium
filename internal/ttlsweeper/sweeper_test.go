package ttlsweeper

import (
	"reflect"
	"sort"
	"testing"
	"time"
)

// ptr is a tiny helper so the table literals stay readable —
// `TTLExpiresAt: ptr(now.Add(-time.Hour))` reads better than
// declaring a local variable per case.
func ptr(t time.Time) *time.Time { return &t }

func TestDecide(t *testing.T) {
	now := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name       string
		containers []ContainerView
		// want is order-independent; the test sorts both sides before
		// comparing. Decide doesn't guarantee any particular order
		// and we don't want the test to lock in an accidental order.
		want []string
	}{
		{
			name:       "empty list returns no names",
			containers: nil,
			want:       nil,
		},
		{
			name: "containers with no TTL are skipped",
			containers: []ContainerView{
				{Name: "alice", TTLExpiresAt: nil},
				{Name: "bob", TTLExpiresAt: nil},
			},
			want: nil,
		},
		{
			name: "all expired containers are returned",
			containers: []ContainerView{
				{Name: "alice", TTLExpiresAt: ptr(now.Add(-time.Hour))},
				{Name: "bob", TTLExpiresAt: ptr(now.Add(-5 * time.Minute))},
			},
			want: []string{"alice", "bob"},
		},
		{
			name: "all active (future) TTLs are skipped",
			containers: []ContainerView{
				{Name: "alice", TTLExpiresAt: ptr(now.Add(time.Hour))},
				{Name: "bob", TTLExpiresAt: ptr(now.Add(24 * time.Hour))},
			},
			want: nil,
		},
		{
			name: "mixed: only expired ones are returned",
			containers: []ContainerView{
				{Name: "alice-no-ttl", TTLExpiresAt: nil},
				{Name: "bob-future", TTLExpiresAt: ptr(now.Add(time.Hour))},
				{Name: "carol-expired", TTLExpiresAt: ptr(now.Add(-time.Hour))},
				{Name: "dave-just-expired", TTLExpiresAt: ptr(now.Add(-time.Minute))},
				{Name: "eve-no-ttl", TTLExpiresAt: nil},
			},
			want: []string{"carol-expired", "dave-just-expired"},
		},
		{
			name: "exactly at cutoff (now - graceMargin) is treated as expired",
			containers: []ContainerView{
				{Name: "edge", TTLExpiresAt: ptr(now.Add(-graceMargin))},
			},
			want: []string{"edge"},
		},
		{
			name: "inside the grace window is NOT yet expired",
			// TTL was a tiny moment ago — still inside graceMargin,
			// so we wait for the next sweep. This is the whole point
			// of the grace margin: protect against clock skew between
			// the TTL-setter and the daemon host.
			containers: []ContainerView{
				{Name: "skewed", TTLExpiresAt: ptr(now.Add(-graceMargin / 2))},
			},
			want: nil,
		},
		{
			name: "TTL exactly at now is inside grace window — skipped",
			containers: []ContainerView{
				{Name: "right-now", TTLExpiresAt: ptr(now)},
			},
			want: nil,
		},
		{
			name: "TTL one nanosecond past the cutoff is skipped",
			containers: []ContainerView{
				{Name: "almost", TTLExpiresAt: ptr(now.Add(-graceMargin + time.Nanosecond))},
			},
			want: nil,
		},
		{
			name: "TTL set to the zero time is treated as long-expired",
			// Defensive: a caller setting *time.Time to &time.Time{}
			// rather than nil should not silently mean "never delete".
			// Decide treats the zero value as a past time (the unix
			// epoch is way before any plausible "now"), so the
			// container is flagged for deletion. The persistence layer
			// in the wiring PR is responsible for normalizing "clear
			// TTL" to a literal nil; this assertion locks in the
			// fail-loud behavior if it ever forgets.
			containers: []ContainerView{
				{Name: "zero", TTLExpiresAt: ptr(time.Time{})},
			},
			want: []string{"zero"},
		},
		{
			name: "ordering does not affect which containers are returned",
			// Same mix as the "mixed" case but reversed — defensively
			// checks Decide does not depend on input order.
			containers: []ContainerView{
				{Name: "eve-no-ttl", TTLExpiresAt: nil},
				{Name: "dave-just-expired", TTLExpiresAt: ptr(now.Add(-time.Minute))},
				{Name: "carol-expired", TTLExpiresAt: ptr(now.Add(-time.Hour))},
				{Name: "bob-future", TTLExpiresAt: ptr(now.Add(time.Hour))},
				{Name: "alice-no-ttl", TTLExpiresAt: nil},
			},
			want: []string{"carol-expired", "dave-just-expired"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Decide(tc.containers, now)
			gotSorted := append([]string(nil), got...)
			wantSorted := append([]string(nil), tc.want...)
			sort.Strings(gotSorted)
			sort.Strings(wantSorted)
			if !reflect.DeepEqual(gotSorted, wantSorted) {
				t.Errorf("Decide returned %v, want %v", got, tc.want)
			}
		})
	}
}

// dur is the *time.Duration analogue of ptr — keeps the stopped→delete
// table literals readable.
func dur(d time.Duration) *time.Duration { return &d }

// TestDecide_StoppedDelete covers the #525 stopped→delete timer: a box left
// STOPPED past its opted-in window is deleted (disk reclaim), but only if it's
// stopped, has a stop timestamp, and opted in. Idle→stop lives in autosleep,
// so a RUNNING idle box is never returned here.
func TestDecide_StoppedDelete(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	window := time.Hour

	tests := []struct {
		name       string
		containers []ContainerView
		want       []string
	}{
		{
			name: "running box is never stopped→deleted (idle→stop is autosleep's job)",
			containers: []ContainerView{
				// Stopped=false even though it has a window + an old StoppedAt.
				{Name: "running", Stopped: false, StoppedAt: ptr(now.Add(-24 * time.Hour)), DeleteAfterStopped: dur(window)},
			},
			want: nil,
		},
		{
			name: "stopped but young (within window) is kept",
			containers: []ContainerView{
				{Name: "young", Stopped: true, StoppedAt: ptr(now.Add(-30 * time.Minute)), DeleteAfterStopped: dur(window)},
			},
			want: nil,
		},
		{
			name: "stopped past the window is deleted",
			containers: []ContainerView{
				{Name: "old", Stopped: true, StoppedAt: ptr(now.Add(-2 * time.Hour)), DeleteAfterStopped: dur(window)},
			},
			want: []string{"old"},
		},
		{
			name: "stopped but never opted in (nil window) is kept — scale-to-zero safety",
			containers: []ContainerView{
				{Name: "sleeper", Stopped: true, StoppedAt: ptr(now.Add(-24 * time.Hour)), DeleteAfterStopped: nil},
			},
			want: nil,
		},
		{
			name: "woken box has no StoppedAt (cleared on start) → timer reset, kept",
			containers: []ContainerView{
				{Name: "woken", Stopped: false, StoppedAt: nil, DeleteAfterStopped: dur(window)},
			},
			want: nil,
		},
		{
			name: "stopped exactly at cutoff (StoppedAt+window == now-grace) is deleted",
			containers: []ContainerView{
				{Name: "edge", Stopped: true, StoppedAt: ptr(now.Add(-window - graceMargin)), DeleteAfterStopped: dur(window)},
			},
			want: []string{"edge"},
		},
		{
			name: "absolute TTL still fires independently of stopped→delete",
			containers: []ContainerView{
				// Running, no stopped→delete, but an expired absolute TTL.
				{Name: "ttl-expired", TTLExpiresAt: ptr(now.Add(-time.Hour))},
				// Stopped past window AND would also be TTL'd — returned once.
				{Name: "both", TTLExpiresAt: ptr(now.Add(-time.Hour)), Stopped: true, StoppedAt: ptr(now.Add(-2 * time.Hour)), DeleteAfterStopped: dur(window)},
			},
			want: []string{"ttl-expired", "both"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Decide(tc.containers, now)
			gotSorted := append([]string(nil), got...)
			wantSorted := append([]string(nil), tc.want...)
			sort.Strings(gotSorted)
			sort.Strings(wantSorted)
			if !reflect.DeepEqual(gotSorted, wantSorted) {
				t.Errorf("Decide returned %v, want %v", got, tc.want)
			}
		})
	}
}

// TestDecide_PureFunction locks in the "no side effects, no input
// mutation" contract. Decide is called from a tick loop that holds
// no locks on the input slice — silently rewriting an element would
// be a subtle source of bugs in the wiring PR.
func TestDecide_PureFunction(t *testing.T) {
	now := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	expiry := now.Add(-time.Hour)
	containers := []ContainerView{
		{Name: "alice", TTLExpiresAt: &expiry},
		{Name: "bob", TTLExpiresAt: nil},
	}
	// Snapshot the field values before the call.
	beforeName0 := containers[0].Name
	beforeTTL0 := *containers[0].TTLExpiresAt
	beforeName1 := containers[1].Name
	beforeNil1 := containers[1].TTLExpiresAt

	_ = Decide(containers, now)

	if containers[0].Name != beforeName0 ||
		*containers[0].TTLExpiresAt != beforeTTL0 ||
		containers[1].Name != beforeName1 ||
		containers[1].TTLExpiresAt != beforeNil1 {
		t.Errorf("Decide mutated its input slice")
	}
}
