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

// shrinkProbeTimeout makes the per-backend probe budget small for a test.
func shrinkProbeTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	old := listBackendsProbeTimeout
	listBackendsProbeTimeout = d
	t.Cleanup(func() { listBackendsProbeTimeout = old })
}

func addTestPeer(pool *PeerPool, id string, srv *httptest.Server, healthy bool) {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	pool.peers[id] = &PeerClient{ID: id, Addr: srv.Listener.Addr().String(), Healthy: healthy, client: srv.Client()}
}

// Peers that never answer must be probed concurrently and bounded by the
// per-call budget: the listing returns promptly, the hung peers keep identity
// and health but carry no load, and a responsive peer still reports.
func TestListBackends_UnresponsivePeersDoNotBlockListing(t *testing.T) {
	shrinkProbeTimeout(t, 300*time.Millisecond)

	release := make(chan struct{})
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { close(release); hang.Close() })
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"info":{"hostname":"peer-ok","os":"linux"}}`))
	}))
	t.Cleanup(ok.Close)

	pool := NewPeerPool("local-spot", "", nil, "")
	addTestPeer(pool, "peer-hang-1", hang, true)
	addTestPeer(pool, "peer-hang-2", hang, true)
	addTestPeer(pool, "peer-hang-3", hang, true)
	addTestPeer(pool, "peer-ok", ok, true)

	s := &ContainerServer{peerPool: pool}
	ctx := auth.ContextWithTestSubject(context.Background(), "ops", auth.RoleAdmin)

	start := time.Now()
	resp, err := s.ListBackends(ctx, &pb.ListBackendsRequest{})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ListBackends: %v", err)
	}
	// Serial probing of 3 hung peers would take >= 900ms.
	if elapsed > 700*time.Millisecond {
		t.Fatalf("listing took %v; hung peers must be probed in parallel under the per-call budget", elapsed)
	}
	byID := map[string]*pb.BackendInfo{}
	for _, b := range resp.Backends {
		byID[b.Id] = b
	}
	if len(resp.Backends) != 5 {
		t.Fatalf("got %d backends, want local + 4 peers", len(resp.Backends))
	}
	for _, id := range []string{"peer-hang-1", "peer-hang-2", "peer-hang-3"} {
		b := byID[id]
		if b == nil || !b.Healthy || b.HostLoad != nil || b.Hostname != "" {
			t.Errorf("%s: want identity+health only, got %+v", id, b)
		}
	}
	if byID["peer-ok"].Hostname != "peer-ok" {
		t.Errorf("responsive peer lost its info: %+v", byID["peer-ok"])
	}
}

// The response keeps the pool's peer order regardless of which probe
// finishes first.
func TestListBackends_PeerOrderIsStable(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(150 * time.Millisecond)
		_, _ = w.Write([]byte(`{"info":{"hostname":"slow"}}`))
	}))
	t.Cleanup(slow.Close)
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"info":{"hostname":"fast"}}`))
	}))
	t.Cleanup(fast.Close)

	pool := NewPeerPool("local-spot", "", nil, "")
	addTestPeer(pool, "p-slow", slow, true)
	addTestPeer(pool, "p-fast", fast, true)
	want := pool.Peers()

	s := &ContainerServer{peerPool: pool}
	ctx := auth.ContextWithTestSubject(context.Background(), "ops", auth.RoleAdmin)
	resp, err := s.ListBackends(ctx, &pb.ListBackendsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Backends) != 1+len(want) {
		t.Fatalf("got %d backends", len(resp.Backends))
	}
	for i, p := range want {
		if got := resp.Backends[i+1].Id; got != p.ID {
			t.Errorf("position %d: got %s want %s", i+1, got, p.ID)
		}
	}
}

// A wedged local GetSystemInfo must not block the listing: the local backend
// keeps identity and health, with no load block.
func TestListBackends_WedgedLocalSystemInfoIsBounded(t *testing.T) {
	shrinkProbeTimeout(t, 200*time.Millisecond)
	unwedge := make(chan struct{})
	t.Cleanup(func() { close(unwedge) })

	pool := NewPeerPool("local-spot", "", nil, "")
	s := &ContainerServer{
		peerPool:  pool,
		manager:   nil,
		startTime: time.Now(),
	}
	s.systemInfoFn = func(context.Context, *pb.GetSystemInfoRequest) (*pb.GetSystemInfoResponse, error) {
		<-unwedge
		return &pb.GetSystemInfoResponse{Info: &pb.SystemInfo{Hostname: "late"}}, nil
	}
	ctx := auth.ContextWithTestSubject(context.Background(), "ops", auth.RoleAdmin)

	info := s.probeLocalSystemInfo(ctx)
	if info != nil {
		t.Fatalf("wedged probe should yield nil, got %+v", info)
	}
	start := time.Now()
	_ = s.probeLocalSystemInfo(ctx)
	if d := time.Since(start); d > 600*time.Millisecond {
		t.Fatalf("probe took %v, want about the 200ms budget", d)
	}
}

func TestProbeLocalSystemInfo_ReturnsInfoWhenResponsive(t *testing.T) {
	s := &ContainerServer{}
	s.systemInfoFn = func(context.Context, *pb.GetSystemInfoRequest) (*pb.GetSystemInfoResponse, error) {
		return &pb.GetSystemInfoResponse{Info: &pb.SystemInfo{Hostname: "h"}}, nil
	}
	info := s.probeLocalSystemInfo(context.Background())
	if info == nil || info.Hostname != "h" {
		t.Fatalf("got %+v", info)
	}
}
