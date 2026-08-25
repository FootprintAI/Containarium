package traffic

import (
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// fakeContainerLister is a containerLister that never touches a real Incus
// server, so the incremental-refresh logic (#1541) is testable directly.
type fakeContainerLister struct {
	names       []string
	byName      map[string]*incus.ContainerInfo
	fetchCalls  []string // records every name GetContainerWithNetwork was asked for, in order
	namesErr    error
	fetchErrFor map[string]error
}

func (f *fakeContainerLister) GetInstanceNames() ([]string, error) {
	return f.names, f.namesErr
}

func (f *fakeContainerLister) GetContainerWithNetwork(name string) (*incus.ContainerInfo, error) {
	f.fetchCalls = append(f.fetchCalls, name)
	if err, ok := f.fetchErrFor[name]; ok {
		return nil, err
	}
	info, ok := f.byName[name]
	if !ok {
		return nil, errNotFound
	}
	return info, nil
}

func newCacheWithFake(f *fakeContainerLister) *ContainerCache {
	return &ContainerCache{
		incusClient: f,
		ipToName:    make(map[string]string),
		nameToIP:    make(map[string]string),
		nameToID:    make(map[string]string),
	}
}

// TestRefresh_FirstCallFetchesEveryName is the baseline: an empty cache has
// nothing to skip, so the first Refresh must still fetch everything (same
// cost as the old full-relist — the fix is about NOT repeating that cost
// every cycle, not skipping it entirely on a cold cache).
func TestRefresh_FirstCallFetchesEveryName(t *testing.T) {
	f := &fakeContainerLister{
		names: []string{"a-container", "b-container"},
		byName: map[string]*incus.ContainerInfo{
			"a-container": {Name: "a-container", IPAddress: "10.0.0.1"},
			"b-container": {Name: "b-container", IPAddress: "10.0.0.2"},
		},
	}
	c := newCacheWithFake(f)

	if err := c.Refresh(); err != nil {
		t.Fatalf("Refresh() err = %v, want nil", err)
	}
	if len(f.fetchCalls) != 2 {
		t.Fatalf("fetch calls = %v, want 2 (both names, cold cache)", f.fetchCalls)
	}
	if got := c.LookupName("a-container"); got != "10.0.0.1" {
		t.Errorf("LookupName(a-container) = %q, want 10.0.0.1", got)
	}
	if got := c.LookupIP("10.0.0.2"); got != "b-container" {
		t.Errorf("LookupIP(10.0.0.2) = %q, want b-container", got)
	}
}

// TestRefresh_UnchangedNamesAreNotRefetched is the regression test for
// #1541 itself: a second Refresh over the same, unchanged set of names must
// not re-fetch any of them — that's the entire point of the fix (the old
// behavior refetched all N every cycle, which was the real, unconditional
// contributor to Incus daemon CPU load at high container counts).
func TestRefresh_UnchangedNamesAreNotRefetched(t *testing.T) {
	f := &fakeContainerLister{
		names: []string{"a-container", "b-container"},
		byName: map[string]*incus.ContainerInfo{
			"a-container": {Name: "a-container", IPAddress: "10.0.0.1"},
			"b-container": {Name: "b-container", IPAddress: "10.0.0.2"},
		},
	}
	c := newCacheWithFake(f)
	if err := c.Refresh(); err != nil {
		t.Fatalf("first Refresh() err = %v", err)
	}
	f.fetchCalls = nil // reset the recorder; only the second call matters

	if err := c.Refresh(); err != nil {
		t.Fatalf("second Refresh() err = %v", err)
	}
	if len(f.fetchCalls) != 0 {
		t.Fatalf("second Refresh() re-fetched %v, want no calls (both names unchanged)", f.fetchCalls)
	}
	if got := c.LookupName("a-container"); got != "10.0.0.1" {
		t.Errorf("LookupName(a-container) after no-op refresh = %q, want 10.0.0.1 (cache should be untouched)", got)
	}
}

// TestRefresh_OnlyFetchesGenuinelyNewNames: adding one new container to an
// otherwise-unchanged set must fetch only that one name, not re-fetch the
// existing ones.
func TestRefresh_OnlyFetchesGenuinelyNewNames(t *testing.T) {
	f := &fakeContainerLister{
		names: []string{"a-container"},
		byName: map[string]*incus.ContainerInfo{
			"a-container": {Name: "a-container", IPAddress: "10.0.0.1"},
		},
	}
	c := newCacheWithFake(f)
	if err := c.Refresh(); err != nil {
		t.Fatalf("first Refresh() err = %v", err)
	}

	f.names = []string{"a-container", "c-container"}
	f.byName["c-container"] = &incus.ContainerInfo{Name: "c-container", IPAddress: "10.0.0.3"}
	f.fetchCalls = nil

	if err := c.Refresh(); err != nil {
		t.Fatalf("second Refresh() err = %v", err)
	}
	if len(f.fetchCalls) != 1 || f.fetchCalls[0] != "c-container" {
		t.Fatalf("second Refresh() fetched %v, want exactly [c-container]", f.fetchCalls)
	}
	if got := c.LookupName("a-container"); got != "10.0.0.1" {
		t.Errorf("existing entry a-container = %q, want unchanged 10.0.0.1", got)
	}
	if got := c.LookupName("c-container"); got != "10.0.0.3" {
		t.Errorf("new entry c-container = %q, want 10.0.0.3", got)
	}
}

// TestRefresh_DropsDeletedNames: a name that disappears from the current
// instance list must be removed from all three maps (nameToIP, ipToName,
// nameToID), not left stale.
func TestRefresh_DropsDeletedNames(t *testing.T) {
	f := &fakeContainerLister{
		names: []string{"a-container", "b-container"},
		byName: map[string]*incus.ContainerInfo{
			"a-container": {Name: "a-container", IPAddress: "10.0.0.1", Labels: map[string]string{"cloud_container_id": "cid-a"}},
			"b-container": {Name: "b-container", IPAddress: "10.0.0.2"},
		},
	}
	c := newCacheWithFake(f)
	if err := c.Refresh(); err != nil {
		t.Fatalf("first Refresh() err = %v", err)
	}

	f.names = []string{"b-container"} // a-container deleted
	if err := c.Refresh(); err != nil {
		t.Fatalf("second Refresh() err = %v", err)
	}

	if got := c.LookupName("a-container"); got != "" {
		t.Errorf("deleted a-container nameToIP = %q, want empty", got)
	}
	if got := c.LookupIP("10.0.0.1"); got != "" {
		t.Errorf("deleted a-container's old IP still resolves to %q, want empty", got)
	}
	if got := c.LookupID("a-container"); got != "" {
		t.Errorf("deleted a-container's label still resolves to %q, want empty", got)
	}
	if got := c.LookupName("b-container"); got != "10.0.0.2" {
		t.Errorf("surviving b-container = %q, want unchanged 10.0.0.2", got)
	}
}

// TestRefresh_FetchFailureIsSkippedNotFatal: a name that fails to fetch
// (e.g. deleted between GetInstanceNames and the fetch) should be skipped
// for this cycle, not fail the whole Refresh — same as ListContainers'
// long-standing "skip what we can't get" behavior.
func TestRefresh_FetchFailureIsSkippedNotFatal(t *testing.T) {
	f := &fakeContainerLister{
		names:       []string{"a-container", "gone-container"},
		byName:      map[string]*incus.ContainerInfo{"a-container": {Name: "a-container", IPAddress: "10.0.0.1"}},
		fetchErrFor: map[string]error{"gone-container": errNotFound},
	}
	c := newCacheWithFake(f)

	if err := c.Refresh(); err != nil {
		t.Fatalf("Refresh() err = %v, want nil (per-name fetch failures are non-fatal)", err)
	}
	if got := c.LookupName("a-container"); got != "10.0.0.1" {
		t.Errorf("a-container = %q, want 10.0.0.1", got)
	}
	if got := c.LookupName("gone-container"); got != "" {
		t.Errorf("gone-container = %q, want empty (fetch failed, never cached)", got)
	}
}

var errNotFound = &notFoundError{}

type notFoundError struct{}

func (*notFoundError) Error() string { return "not found" }
