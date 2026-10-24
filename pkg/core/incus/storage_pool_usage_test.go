package incus

import (
	"errors"
	"testing"

	incusclient "github.com/lxc/incus/v7/client"
	"github.com/lxc/incus/v7/shared/api"
)

// fakePoolServer answers only the per-pool calls. GetServerResources is not
// implemented: the embedded nil interface panics if StoragePoolUsages ever
// reaches for the heavy /1.0/resources read (#2325).
type fakePoolServer struct {
	incusclient.InstanceServer
	pools   []api.StoragePool
	listErr error
	res     map[string]*api.ResourcesStoragePool
}

func (f *fakePoolServer) GetStoragePools() ([]api.StoragePool, error) {
	return f.pools, f.listErr
}

func (f *fakePoolServer) GetStoragePoolResources(name string) (*api.ResourcesStoragePool, error) {
	if r, ok := f.res[name]; ok {
		return r, nil
	}
	return nil, errors.New("pool read failed")
}

func poolRes(used, total uint64) *api.ResourcesStoragePool {
	r := &api.ResourcesStoragePool{}
	r.Space.Used, r.Space.Total = used, total
	return r
}

func TestStoragePoolUsages_PerPoolAndSkipsFailedPool(t *testing.T) {
	srv := &fakePoolServer{
		pools: []api.StoragePool{{Name: "a", Driver: "zfs"}, {Name: "broken", Driver: "dir"}, {Name: "b", Driver: "dir"}},
		res:   map[string]*api.ResourcesStoragePool{"a": poolRes(96, 100), "b": poolRes(1, 1000)},
	}
	got, err := (&Client{server: srv}).StoragePoolUsages()
	if err != nil {
		t.Fatal(err)
	}
	want := []StoragePoolUsage{
		{Name: "a", Driver: "zfs", UsedBytes: 96, TotalBytes: 100},
		{Name: "b", Driver: "dir", UsedBytes: 1, TotalBytes: 1000},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("pool %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestStoragePoolUsages_ListErrorIsReturned(t *testing.T) {
	_, err := (&Client{server: &fakePoolServer{listErr: errors.New("down")}}).StoragePoolUsages()
	if err == nil {
		t.Fatal("want an error when the pool list fails")
	}
}
