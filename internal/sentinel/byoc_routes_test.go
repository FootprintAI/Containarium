package sentinel

import (
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestBYOCRouteRegistry_ReplaceAllAndLookup(t *testing.T) {
	r := NewBYOCRouteRegistry()

	if _, ok := r.Lookup("nope.containarium.dev"); ok {
		t.Fatal("empty registry should not resolve anything")
	}

	r.ReplaceAll([]BYOCRoute{
		{Hostname: "a-acme.containarium.dev", BackendID: "tunnel-h1", Port: 8080},
		{Hostname: "b-acme.containarium.dev", BackendID: "tunnel-h2", Port: 3000},
		// malformed entries must be dropped, not stored:
		{Hostname: "", BackendID: "tunnel-h3", Port: 8080},
		{Hostname: "c.containarium.dev", BackendID: "", Port: 8080},
		{Hostname: "d.containarium.dev", BackendID: "tunnel-h4", Port: 0},
	})

	got, ok := r.Lookup("a-acme.containarium.dev")
	if !ok || got.BackendID != "tunnel-h1" || got.Port != 8080 {
		t.Fatalf("lookup a = %+v ok=%v", got, ok)
	}
	if _, ok := r.Lookup("c.containarium.dev"); ok {
		t.Fatal("malformed (empty backend) entry must be dropped")
	}
	if _, ok := r.Lookup("d.containarium.dev"); ok {
		t.Fatal("malformed (zero port) entry must be dropped")
	}
	if n := len(r.Snapshot()); n != 2 {
		t.Fatalf("snapshot len = %d, want 2 (malformed dropped)", n)
	}

	// ReplaceAll is a full swap: a hostname absent from the new set is gone.
	r.ReplaceAll([]BYOCRoute{{Hostname: "b-acme.containarium.dev", BackendID: "tunnel-h2", Port: 3000}})
	if _, ok := r.Lookup("a-acme.containarium.dev"); ok {
		t.Fatal("ReplaceAll must drop hostnames not in the new set")
	}
	if _, ok := r.Lookup("b-acme.containarium.dev"); !ok {
		t.Fatal("ReplaceAll must keep hostnames in the new set")
	}
}

func TestBYOCRouteStore_SaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "byoc-routes.json")

	// Loading a missing file is not an error.
	if routes, err := LoadBYOCRouteStore(path); err != nil || routes != nil {
		t.Fatalf("missing file: routes=%v err=%v", routes, err)
	}

	want := []BYOCRoute{
		{Hostname: "a.containarium.dev", BackendID: "tunnel-h1", Port: 8080},
		{Hostname: "b.containarium.dev", BackendID: "tunnel-h2", Port: 3000},
	}
	if err := SaveBYOCRouteStore(path, want); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := LoadBYOCRouteStore(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	byHost := func(s []BYOCRoute) { sort.Slice(s, func(i, j int) bool { return s[i].Hostname < s[j].Hostname }) }
	byHost(got)
	byHost(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("roundtrip mismatch:\n got=%+v\nwant=%+v", got, want)
	}
}
