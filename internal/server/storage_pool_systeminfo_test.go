package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/poolcapacity"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// SystemInfo.storage_pools comes from the monitor's snapshot (#2823): no
// Incus call, typed driver and level, and the read time.
func TestStoragePoolCapacities_FromSnapshot(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	s := &ContainerServer{}
	if got := s.storagePoolCapacities(); got != nil {
		t.Fatalf("no monitor wired: want nil, got %v", got)
	}
	s.SetStoragePoolSource(func() poolcapacity.Snapshot {
		return poolcapacity.Snapshot{At: at, Pools: []poolcapacity.Sample{
			{StoragePoolUsage: incus.StoragePoolUsage{Name: "p1", Driver: "zfs", UsedBytes: 90, TotalBytes: 100}, Level: poolcapacity.LevelWarning},
			{StoragePoolUsage: incus.StoragePoolUsage{Name: "p2", Driver: "dir", UsedBytes: 96, TotalBytes: 100}, Level: poolcapacity.LevelCritical},
		}}
	})
	got := s.storagePoolCapacities()
	if len(got) != 2 {
		t.Fatalf("got %d pools, want 2", len(got))
	}
	p := got[0]
	if p.GetPool() != "p1" || p.GetDriver() != pb.StorageDriver_STORAGE_DRIVER_ZFS || p.GetUsedBytes() != 90 ||
		p.GetTotalBytes() != 100 || p.GetLevel() != pb.StoragePoolCapacityLevel_STORAGE_POOL_CAPACITY_LEVEL_WARNING ||
		!p.GetObservedAt().AsTime().Equal(at) {
		t.Errorf("pool 0 = %v", p)
	}
	if got[1].GetLevel() != pb.StoragePoolCapacityLevel_STORAGE_POOL_CAPACITY_LEVEL_CRITICAL {
		t.Errorf("pool 1 level = %v, want CRITICAL", got[1].GetLevel())
	}
}

// A peer's pools reach the metrics host through the forwarded GetSystemInfo,
// so the collector can record them under the peer's backend id.
func TestFetchPeerSystemMetrics_CarriesStoragePools(t *testing.T) {
	peerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"info":{"totalCpus":8,"totalDiskBytes":"1000","availableDiskBytes":"400",
			"someFieldFromANewerDaemon":true,
			"storagePools":[{"pool":"p1","driver":"STORAGE_DRIVER_ZFS","usedBytes":"96","totalBytes":"100",
				"level":"STORAGE_POOL_CAPACITY_LEVEL_CRITICAL"}]}}`))
	}))
	defer peerSrv.Close()

	pool := NewPeerPool("local", "", nil, "")
	pool.mu.Lock()
	pool.peers["peer-a"] = &PeerClient{ID: "peer-a", Addr: peerSrv.Listener.Addr().String(), Healthy: true, client: peerSrv.Client()}
	pool.mu.Unlock()

	got := (&PeerMetricsFetcherAdapter{Pool: pool}).FetchPeerSystemMetrics("tok")
	if len(got) != 1 {
		t.Fatalf("got %d peers, want 1", len(got))
	}
	m := got[0]
	if m.BackendID != "peer-a" || m.TotalCPUs != 8 || m.TotalDiskBytes != 1000 || m.UsedDiskBytes != 600 {
		t.Errorf("existing fields regressed: %+v", m)
	}
	want := incus.StoragePoolUsage{Name: "p1", Driver: "zfs", UsedBytes: 96, TotalBytes: 100}
	if len(m.StoragePools) != 1 || m.StoragePools[0] != want {
		t.Errorf("StoragePools = %+v, want [%+v]", m.StoragePools, want)
	}
}
