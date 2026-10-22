//go:build !windows && !containarium_client

package cmd

import (
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// #2617: the startup reconcile must not touch core service containers or
// stopped ones.
func TestBaseScriptTargets_SkipsCoreAndStopped(t *testing.T) {
	in := []incus.ContainerInfo{
		{Name: "alice-container", State: "Running"},
		{Name: "bob-container", State: "Stopped"},
		{Name: "containarium-core-caddy", State: "Running", Role: incus.RoleCaddy},
		{Name: "containarium-core-postgres", State: "Running", Role: incus.RolePostgres},
		{Name: "hand-made", State: "Running"},
	}
	got := baseScriptTargets(in)
	var names []string
	for _, c := range got {
		names = append(names, c.Name)
	}
	if len(names) != 2 || names[0] != "alice-container" || names[1] != "hand-made" {
		t.Fatalf("targets = %v, want [alice-container hand-made]", names)
	}
}

func TestFailedSuffix(t *testing.T) {
	if got := failedSuffix(nil); got != "" {
		t.Errorf("no failures = %q, want empty", got)
	}
	if got := failedSuffix([]string{"a", "b"}); got != " (a, b)" {
		t.Errorf("two failures = %q", got)
	}
	if got := failedSuffix([]string{"a", "b", "c", "d", "e", "f", "g"}); got != " (a, b, c, d, e, +2 more)" {
		t.Errorf("seven failures = %q", got)
	}
}
