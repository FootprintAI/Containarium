package cluster

// Isolation defaulting (#1428). The both-impls round-trip lives in the
// tagged store_integration_test.go; this is the untagged half so the
// fast lane also fails when the safe default stops being the default.

import (
	"context"
	"testing"
)

func TestIsolation_OrDefault(t *testing.T) {
	cases := []struct {
		name string
		in   Isolation
		want Isolation
	}{
		{"unset resolves to the strong class", "", IsolationVM},
		{"vm stays vm", IsolationVM, IsolationVM},
		{"container is never silently upgraded away", IsolationContainer, IsolationContainer},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.in.OrDefault(); got != tc.want {
				t.Fatalf("Isolation(%q).OrDefault() = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestMemStore_NodeIsolationRoundTrips(t *testing.T) {
	ctx := context.Background()
	s := NewMemStore()
	for _, tc := range []struct {
		name string
		in   Isolation
		want Isolation
	}{
		{"unset", "", IsolationVM},
		{"vm", IsolationVM, IsolationVM},
		{"container", IsolationContainer, IsolationContainer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := s.Create(ctx, &Cluster{
				ID: tc.name, Owner: "alice", Name: tc.name,
				State: StateProvisioning, NodeIsolation: tc.in,
				NodeGroups: DefaultNodeGroups(),
			}); err != nil {
				t.Fatalf("Create: %v", err)
			}
			got, err := s.Get(ctx, "alice", tc.name)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if got.NodeIsolation != tc.want {
				t.Fatalf("isolation = %q, want %q", got.NodeIsolation, tc.want)
			}
		})
	}
}
