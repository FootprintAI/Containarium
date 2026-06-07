package cmd

import (
	"sort"
	"testing"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
)

func names(cs []incus.ContainerInfo) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Name)
	}
	sort.Strings(out)
	return out
}

// TestFilterForPrune covers the selection logic that decides which containers
// a `prune` would delete — the safety-critical part of bulk delete.
func TestFilterForPrune(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	fleet := []incus.ContainerInfo{
		{Name: "core-pg", Role: incus.RolePostgres, State: "Running", CreatedAt: now.Add(-72 * time.Hour)},
		{Name: "run-old", State: "Running", CreatedAt: now.Add(-2 * time.Hour), Labels: map[string]string{"managed_by": "ci"}},
		{Name: "run-new", State: "Running", CreatedAt: now.Add(-10 * time.Minute)},
		{Name: "stop-old", State: "Stopped", CreatedAt: now.Add(-3 * time.Hour)},
		{Name: "stop-new", State: "Stopped", CreatedAt: now.Add(-5 * time.Minute)},
		{Name: "pr-42-box", State: "Running", CreatedAt: now.Add(-26 * time.Hour)},
		{Name: "no-age", State: "Stopped"}, // CreatedAt zero
	}

	cases := []struct {
		name         string
		state        string
		nameContains string
		olderThan    time.Duration
		labels       map[string]string
		want         []string
	}{
		{
			name:  "core is never matched (state=running)",
			state: "running",
			want:  []string{"pr-42-box", "run-new", "run-old"}, // core-pg excluded
		},
		{
			name:  "stopped only",
			state: "stopped",
			want:  []string{"no-age", "stop-new", "stop-old"},
		},
		{
			name:      "stopped + older-than 1h",
			state:     "stopped",
			olderThan: time.Hour,
			want:      []string{"stop-old"}, // stop-new too young; no-age has no CreatedAt → excluded
		},
		{
			// Every non-core box created >1h ago; no-age (zero CreatedAt) is
			// excluded because we can't prove its age.
			name:      "older-than 1h, no other filter",
			olderThan: time.Hour,
			want:      []string{"pr-42-box", "run-old", "stop-old"},
		},
		{
			name:         "name-contains",
			nameContains: "pr-",
			want:         []string{"pr-42-box"},
		},
		{
			name:   "label filter",
			labels: map[string]string{"managed_by": "ci"},
			want:   []string{"run-old"},
		},
		{
			name: "no filters matches all non-core",
			want: []string{"no-age", "pr-42-box", "run-new", "run-old", "stop-new", "stop-old"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := names(filterForPrune(fleet, tc.state, tc.nameContains, tc.olderThan, tc.labels, now))
			want := append([]string(nil), tc.want...)
			sort.Strings(want)
			if len(got) != len(want) {
				t.Fatalf("got %v, want %v", got, want)
			}
			for i := range got {
				if got[i] != want[i] {
					t.Fatalf("got %v, want %v", got, want)
				}
			}
		})
	}
}

// TestPruneDeleteKey: delete is addressed by Username (the cld-<id> on cloud /
// bare user on OSS), falling back to the name minus "-container".
func TestPruneDeleteKey(t *testing.T) {
	if got := pruneDeleteKey(incus.ContainerInfo{Name: "alice-container", Username: "cld-abc123"}); got != "cld-abc123" {
		t.Errorf("got %q, want cld-abc123 (Username preferred)", got)
	}
	if got := pruneDeleteKey(incus.ContainerInfo{Name: "alice-container"}); got != "alice" {
		t.Errorf("got %q, want alice (name fallback)", got)
	}
}

// TestFilterForPrune_SkipsProtected: a protected box (#284) is never selected
// for prune, even when it matches every other filter — the guard that would
// have prevented a "clean up leaked boxes" sweep from deleting a runner.
func TestFilterForPrune_SkipsProtected(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	fleet := []incus.ContainerInfo{
		{Name: "ci-runner-1", State: "Running", CreatedAt: now.Add(-26 * time.Hour), DeletePolicy: incus.DeletePolicyProtected},
		{Name: "leaked-box", State: "Running", CreatedAt: now.Add(-26 * time.Hour)},
	}
	// Broad filter (all running, >1h old) that matches BOTH boxes on every
	// axis; only the unprotected one should come back.
	got := names(filterForPrune(fleet, "running", "", time.Hour, nil, now))
	if len(got) != 1 || got[0] != "leaked-box" {
		t.Fatalf("filterForPrune = %v; want only [leaked-box] (protected runner must be skipped)", got)
	}
}
