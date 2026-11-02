package zap

import (
	"context"
	"errors"
	"testing"

	"github.com/footprintai/containarium/internal/app"
)

// #3332: the ZAP manager reads routes through app.RouteLister, so the daemon
// can hand it the live accessor that resolves to the route store installed
// so far instead of the store present at boot. A nil lister is a daemon with
// no route persistence and yields no targets, as before.

type fakeRouteLister struct {
	routes []*app.RouteRecord
	err    error
}

func (f *fakeRouteLister) List(context.Context, bool) ([]*app.RouteRecord, error) {
	return f.routes, f.err
}

func TestCollectTargets_ListsRoutesThroughRouteLister(t *testing.T) {
	lister := &fakeRouteLister{}
	m := NewManager(nil, lister, ManagerConfig{})

	if got := m.collectTargets(context.Background(), ""); len(got) != 0 {
		t.Fatalf("targets with no routes = %v, want none", got)
	}

	// The store arrives after the manager was built.
	lister.routes = []*app.RouteRecord{
		{FullDomain: "web.example.test", ContainerName: "alice-container"},
		{FullDomain: "web.example.test", ContainerName: "alice-container"},
		{FullDomain: "api.example.test", ContainerName: "bob-container"},
	}
	got := m.collectTargets(context.Background(), "")
	if len(got) != 2 {
		t.Fatalf("targets = %v, want 2 distinct URLs", got)
	}
	if got[0].url != "https://web.example.test" || got[1].url != "https://api.example.test" {
		t.Fatalf("targets = %v, want https URLs of both domains", got)
	}

	scoped := m.collectTargets(context.Background(), "bob-container")
	if len(scoped) != 1 || scoped[0].containerName != "bob-container" {
		t.Fatalf("scoped targets = %v, want only bob-container's route", scoped)
	}
}

func TestCollectTargets_RouteListerErrorOrNilYieldsNoTargets(t *testing.T) {
	failing := NewManager(nil, &fakeRouteLister{err: errors.New("route store is not available yet")}, ManagerConfig{})
	if got := failing.collectTargets(context.Background(), ""); len(got) != 0 {
		t.Fatalf("targets from a failing lister = %v, want none", got)
	}
	none := NewManager(nil, nil, ManagerConfig{})
	if got := none.collectTargets(context.Background(), ""); len(got) != 0 {
		t.Fatalf("targets with no route lister = %v, want none", got)
	}
}
