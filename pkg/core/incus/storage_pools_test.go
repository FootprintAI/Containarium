package incus

import (
	"errors"
	"testing"

	"github.com/lxc/incus/v7/shared/api"
)

type fakePoolSource struct {
	listErr error
	pools   map[string][2]uint64 // name -> total, used
	badPool string
	order   []string
}

func (f *fakePoolSource) GetStoragePools() ([]api.StoragePool, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []api.StoragePool
	for _, n := range f.order {
		out = append(out, api.StoragePool{Name: n})
	}
	return out, nil
}

func (f *fakePoolSource) GetStoragePoolResources(name string) (*api.ResourcesStoragePool, error) {
	if name == f.badPool {
		return nil, errors.New("pool offline")
	}
	v := f.pools[name]
	r := &api.ResourcesStoragePool{}
	r.Space.Total, r.Space.Used = v[0], v[1]
	return r, nil
}

func TestSumStoragePools(t *testing.T) {
	src := &fakePoolSource{
		order: []string{"a", "b", "c"},
		pools: map[string][2]uint64{"a": {1000, 100}, "b": {500, 50}, "c": {7, 7}},
	}
	got, err := SumStoragePools(src)
	if err != nil {
		t.Fatal(err)
	}
	if got != (PoolTotals{TotalBytes: 1507, UsedBytes: 157, Pools: 3}) {
		t.Errorf("got %+v", got)
	}

	src.badPool = "c" // a failing pool is skipped, not fatal
	got, err = SumStoragePools(src)
	if err != nil || got != (PoolTotals{TotalBytes: 1500, UsedBytes: 150, Pools: 2}) {
		t.Errorf("bad pool: got %+v err %v", got, err)
	}

	if _, err := SumStoragePools(&fakePoolSource{listErr: errors.New("down")}); err == nil {
		t.Error("list failure must be reported")
	}
}

// The capability profile (SystemResources) and the host status probe both
// read the pool sum through SumStoragePools, so they agree on the same
// pools (#3449).
func TestProfileAndProbeAgreeOnPools(t *testing.T) {
	src := &fakePoolSource{order: []string{"a", "b"}, pools: map[string][2]uint64{"a": {1000, 100}, "b": {500, 50}}}
	res := &SystemResources{}
	applyPoolTotals(res, src)
	probe, err := SumStoragePools(src)
	if err != nil {
		t.Fatal(err)
	}
	if res.TotalDiskBytes != probe.TotalBytes || res.UsedDiskBytes != probe.UsedBytes {
		t.Errorf("profile %d/%d != probe %d/%d", res.TotalDiskBytes, res.UsedDiskBytes, probe.TotalBytes, probe.UsedBytes)
	}
	if res.TotalDiskBytes != 1500 {
		t.Errorf("total = %d, want 1500", res.TotalDiskBytes)
	}
}
