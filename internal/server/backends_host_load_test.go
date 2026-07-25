package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestHostLoadFromSystemInfo_ProjectsMeasuredSample(t *testing.T) {
	sampled := time.Date(2026, 7, 25, 10, 30, 0, 0, time.UTC)
	info := &pb.SystemInfo{
		TotalCpus:            16,
		CpuLoad_1Min:         4.5,
		CpuLoad_5Min:         3.25,
		CpuLoad_15Min:        2,
		TotalMemoryBytes:     64 << 30,
		AvailableMemoryBytes: 20 << 30,
		TotalDiskBytes:       2000 << 30,
		AvailableDiskBytes:   1500 << 30,
	}

	got := hostLoadFromSystemInfo(info, sampled)
	if got == nil {
		t.Fatal("host load is nil for a usable sample")
	}
	if got.CpuLoad_1M != 4.5 || got.CpuLoad_5M != 3.25 || got.CpuLoad_15M != 2 {
		t.Errorf("load averages = %v/%v/%v, want 4.5/3.25/2", got.CpuLoad_1M, got.CpuLoad_5M, got.CpuLoad_15M)
	}
	if got.CpuCores != 16 {
		t.Errorf("CpuCores = %d, want 16 (the denominator that makes load interpretable)", got.CpuCores)
	}
	if want := int64(44 << 30); got.MemoryUsedBytes != want {
		t.Errorf("MemoryUsedBytes = %d, want %d (total - available)", got.MemoryUsedBytes, want)
	}
	if got.MemoryTotalBytes != 64<<30 {
		t.Errorf("MemoryTotalBytes = %d, want %d", got.MemoryTotalBytes, int64(64<<30))
	}
	if want := int64(500 << 30); got.DiskUsedBytes != want {
		t.Errorf("DiskUsedBytes = %d, want %d (total - available)", got.DiskUsedBytes, want)
	}
	if got.DiskTotalBytes != 2000<<30 {
		t.Errorf("DiskTotalBytes = %d, want %d", got.DiskTotalBytes, int64(2000<<30))
	}
	if got.SampledAt != "2026-07-25T10:30:00Z" {
		t.Errorf("SampledAt = %q, want RFC3339 UTC", got.SampledAt)
	}
}

// GetSystemInfo swallows a failed GetSystemResources probe and substitutes an
// empty struct, so an all-zero sample means "we couldn't measure" at least as
// often as it means "idle". Reporting it as a HostLoad of zeros would render
// a struggling host as 0% used — worse than rendering nothing.
func TestHostLoadFromSystemInfo_NilWhenNothingWasMeasured(t *testing.T) {
	cases := map[string]*pb.SystemInfo{
		"nil info":     nil,
		"failed probe": {},
		"partial probe (load but no memory figure)": {CpuLoad_1Min: 3.5, TotalCpus: 8},
	}
	for name, info := range cases {
		t.Run(name, func(t *testing.T) {
			if got := hostLoadFromSystemInfo(info, time.Now()); got != nil {
				t.Fatalf("host load = %+v, want nil so callers can tell unknown from idle", got)
			}
		})
	}
}

// available and total come from separate probes on the host, so a skewed read
// can invert them. A negative "bytes in use" in a dashboard reads as a
// product bug rather than as the bad sample it is.
func TestUsedFromTotalAndAvailable_ClampsBadSamples(t *testing.T) {
	cases := []struct {
		name             string
		total, available int64
		want             int64
	}{
		{"normal", 100, 40, 60},
		{"available exceeds total", 100, 140, 0},
		{"negative available reads as fully used", 100, -10, 100},
		{"nothing available", 100, 0, 100},
		{"nothing used", 100, 100, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := usedFromTotalAndAvailable(tc.total, tc.available); got != tc.want {
				t.Fatalf("used(total=%d, available=%d) = %d, want %d", tc.total, tc.available, got, tc.want)
			}
		})
	}
}

// The core of cloud #966 for BYOC: a tunnel peer's live load must reach
// BackendInfo. ListBackends already forwards GetSystemInfo to each healthy
// peer — this proves the load fields survive the projection instead of being
// dropped, which is why BYOC hosts had no load signal anywhere.
func TestContainerServer_ListBackends_PeerReportsHostLoad(t *testing.T) {
	peerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/system/info" {
			http.NotFound(w, r)
			return
		}
		// Field names are protojson's (lowerCamel of the proto names) —
		// this is the wire shape a real peer daemon emits through
		// grpc-gateway, and the shape ListBackends parses with protojson.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"info":{
			"hostname":"byoc-host",
			"totalCpus":8,
			"cpuLoad1min":6.5,
			"cpuLoad5min":5,
			"cpuLoad15min":4,
			"totalMemoryBytes":"34359738368",
			"availableMemoryBytes":"8589934592",
			"totalDiskBytes":"1073741824000",
			"availableDiskBytes":"536870912000"
		}}`))
	}))
	defer peerSrv.Close()

	pool := NewPeerPool("local-spot", "", nil, "")
	pool.mu.Lock()
	pool.peers["tunnel-byoc"] = &PeerClient{
		ID:      "tunnel-byoc",
		Addr:    peerSrv.Listener.Addr().String(),
		Healthy: true,
		client:  peerSrv.Client(),
	}
	pool.mu.Unlock()

	s := &ContainerServer{peerPool: pool, startTime: time.Now().Add(-time.Minute)}
	ctx := auth.ContextWithTestSubject(context.Background(), "ops", auth.RoleAdmin)

	resp, err := s.ListBackends(ctx, &pb.ListBackendsRequest{})
	if err != nil {
		t.Fatalf("ListBackends: %v", err)
	}

	var peer *pb.BackendInfo
	for _, b := range resp.Backends {
		if b.Id == "tunnel-byoc" {
			peer = b
		}
	}
	if peer == nil {
		t.Fatal("tunnel-byoc missing from the backend list")
	}
	// Assert a field from outside the load block too: protojson rejects an
	// unknown field by failing the WHOLE decode, so without this a payload
	// that drifts from the real wire shape would look like "load dropped"
	// rather than "the test's JSON is wrong".
	if peer.Hostname != "byoc-host" {
		t.Fatalf("Hostname = %q, want %q — the peer's SystemInfo did not decode at all", peer.Hostname, "byoc-host")
	}
	if peer.HostLoad == nil {
		t.Fatal("peer HostLoad is nil — the load fields GetSystemInfo already carries were dropped again (#966)")
	}
	if peer.HostLoad.CpuLoad_1M != 6.5 {
		t.Errorf("CpuLoad_1M = %v, want 6.5", peer.HostLoad.CpuLoad_1M)
	}
	if peer.HostLoad.CpuCores != 8 {
		t.Errorf("CpuCores = %d, want 8", peer.HostLoad.CpuCores)
	}
	if want := int64(25769803776); peer.HostLoad.MemoryUsedBytes != want {
		t.Errorf("MemoryUsedBytes = %d, want %d", peer.HostLoad.MemoryUsedBytes, want)
	}
	if want := int64(536870912000); peer.HostLoad.DiskUsedBytes != want {
		t.Errorf("DiskUsedBytes = %d, want %d", peer.HostLoad.DiskUsedBytes, want)
	}
	if peer.HostLoad.SampledAt == "" {
		t.Error("SampledAt is empty — a load figure with no timestamp can't be aged out by a caller")
	}
}

// An unreachable peer must report no load rather than a stale or zeroed one:
// "we couldn't ask" and "the host is idle" are different answers.
func TestContainerServer_ListBackends_UnhealthyPeerHasNoHostLoad(t *testing.T) {
	pool := NewPeerPool("local-spot", "", nil, "")
	pool.mu.Lock()
	pool.peers["tunnel-down"] = &PeerClient{
		ID:      "tunnel-down",
		Healthy: false,
		client:  &http.Client{},
	}
	pool.mu.Unlock()

	s := &ContainerServer{peerPool: pool, startTime: time.Now().Add(-time.Minute)}
	ctx := auth.ContextWithTestSubject(context.Background(), "ops", auth.RoleAdmin)

	resp, err := s.ListBackends(ctx, &pb.ListBackendsRequest{})
	if err != nil {
		t.Fatalf("ListBackends: %v", err)
	}
	for _, b := range resp.Backends {
		if b.Id == "tunnel-down" && b.HostLoad != nil {
			t.Fatalf("unhealthy peer reported HostLoad = %+v, want nil", b.HostLoad)
		}
	}
}
