package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
)

// fakeSystemInfoPeer serves /v1/system/info the way a real peer daemon does
// through grpc-gateway (protojson of GetSystemInfoResponse), or a 500 when
// fail is set. It counts requests and records the bearer token it was called
// with, so tests can pin both the per-peer call budget and that the caller's
// token is what gets forwarded.
type fakeSystemInfoPeer struct {
	srv       *httptest.Server
	calls     atomic.Int32
	authSeen  atomic.Value
	unrelated atomic.Int32
}

func newFakeSystemInfoPeer(t *testing.T, info *pb.SystemInfo, fail bool) *fakeSystemInfoPeer {
	t.Helper()
	body, err := protojson.Marshal(&pb.GetSystemInfoResponse{Info: info})
	if err != nil {
		t.Fatalf("marshal peer SystemInfo: %v", err)
	}
	p := &fakeSystemInfoPeer{}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/system/info" {
			p.unrelated.Add(1)
			http.NotFound(w, r)
			return
		}
		p.calls.Add(1)
		p.authSeen.Store(r.Header.Get("Authorization"))
		if fail {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *fakeSystemInfoPeer) client(id string, healthy bool) *PeerClient {
	return &PeerClient{
		ID:      id,
		Addr:    p.srv.Listener.Addr().String(),
		Healthy: healthy,
		client:  p.srv.Client(),
	}
}

// TestContainerServer_ListBackends_PeerCapacitySignals covers #2135: a
// peer's spare-capacity advertisement (#680) and capability profile (#681)
// reach its BackendInfo through the GetSystemInfo fan-out ListBackends
// already makes — one forwarded call per healthy peer, none for an
// unhealthy one — and each stays null when the peer has nothing to report
// or could not be asked.
func TestContainerServer_ListBackends_PeerCapacitySignals(t *testing.T) {
	headroom := &pb.CapacityHeadroom{
		Advertised:       true,
		SpareCpus:        6,
		SpareMemoryBytes: 16 << 30,
		SpareDiskBytes:   200 << 30,
		IdleFraction:     0.75,
		AdvertisedAt:     "2026-10-06T01:00:00Z",
	}
	profile := &pb.CapabilityProfile{
		CpuCores:      32,
		CpuModel:      "EPYC 9354",
		GpuAvailable:  true,
		GpuModel:      "L4",
		Region:        "asia-east1",
		MeasuredClass: "gpu-inference",
		ProfiledAt:    "2026-10-05T00:00:00Z",
	}

	advertising := newFakeSystemInfoPeer(t, &pb.SystemInfo{Hostname: "advertising", Headroom: headroom}, false)
	profiled := newFakeSystemInfoPeer(t, &pb.SystemInfo{Hostname: "profiled", CapabilityProfile: profile}, false)
	neither := newFakeSystemInfoPeer(t, &pb.SystemInfo{Hostname: "neither"}, false)
	failing := newFakeSystemInfoPeer(t, nil, true)
	unhealthy := newFakeSystemInfoPeer(t, &pb.SystemInfo{Hostname: "unhealthy", Headroom: headroom, CapabilityProfile: profile}, false)

	pool := NewPeerPool("local", "", nil, "")
	pool.mu.Lock()
	pool.peers["tunnel-advertising"] = advertising.client("tunnel-advertising", true)
	pool.peers["tunnel-profiled"] = profiled.client("tunnel-profiled", true)
	pool.peers["tunnel-neither"] = neither.client("tunnel-neither", true)
	pool.peers["tunnel-failing"] = failing.client("tunnel-failing", true)
	pool.peers["tunnel-unhealthy"] = unhealthy.client("tunnel-unhealthy", false)
	pool.mu.Unlock()

	s := &ContainerServer{peerPool: pool, startTime: time.Now().Add(-time.Minute)}
	// ContextWithTestSubject replaces the incoming metadata, so the caller's
	// bearer token is joined onto the subject metadata it built.
	ctx := auth.ContextWithTestSubject(context.Background(), "ops", auth.RoleAdmin)
	md, _ := metadata.FromIncomingContext(ctx)
	ctx = metadata.NewIncomingContext(ctx, metadata.Join(md, metadata.Pairs("authorization", "Bearer caller-admin-token")))

	resp, err := s.ListBackends(ctx, &pb.ListBackendsRequest{})
	if err != nil {
		t.Fatalf("ListBackends: %v", err)
	}
	byID := map[string]*pb.BackendInfo{}
	for _, b := range resp.Backends {
		byID[b.Id] = b
	}
	get := func(id string) *pb.BackendInfo {
		t.Helper()
		b := byID[id]
		if b == nil {
			t.Fatalf("%s missing from the backend list", id)
		}
		return b
	}

	t.Run("peer advertising", func(t *testing.T) {
		b := get("tunnel-advertising")
		// Hostname proves the SystemInfo decoded at all; protojson fails the
		// whole decode on an unknown field, which would otherwise read as
		// "headroom dropped".
		if b.Hostname != "advertising" {
			t.Fatalf("Hostname = %q — the peer's SystemInfo did not decode", b.Hostname)
		}
		if b.Headroom == nil {
			t.Fatal("Headroom is nil — the peer's advertisement was dropped from the fan-out")
		}
		if b.Headroom.SpareCpus != 6 || b.Headroom.SpareMemoryBytes != 16<<30 || !b.Headroom.Advertised {
			t.Errorf("Headroom = %+v, want the peer's advertisement verbatim", b.Headroom)
		}
		if b.CapabilityProfile != nil {
			t.Errorf("CapabilityProfile = %+v, want nil for an unprofiled peer", b.CapabilityProfile)
		}
	})

	t.Run("peer profiled", func(t *testing.T) {
		b := get("tunnel-profiled")
		if b.CapabilityProfile == nil {
			t.Fatal("CapabilityProfile is nil — the peer's profile was dropped from the fan-out")
		}
		if b.CapabilityProfile.MeasuredClass != "gpu-inference" || b.CapabilityProfile.CpuCores != 32 {
			t.Errorf("CapabilityProfile = %+v, want the peer's profile verbatim", b.CapabilityProfile)
		}
		if b.Headroom != nil {
			t.Errorf("Headroom = %+v, want nil for a peer advertising nothing", b.Headroom)
		}
	})

	t.Run("peer neither", func(t *testing.T) {
		b := get("tunnel-neither")
		if b.Hostname != "neither" {
			t.Fatalf("Hostname = %q — the peer's SystemInfo did not decode", b.Hostname)
		}
		if b.Headroom != nil || b.CapabilityProfile != nil {
			t.Errorf("Headroom = %+v, CapabilityProfile = %+v; want both nil", b.Headroom, b.CapabilityProfile)
		}
	})

	t.Run("peer failing", func(t *testing.T) {
		b := get("tunnel-failing")
		if !b.Healthy {
			t.Error("a failed probe must not rewrite the peer's pool health")
		}
		if b.Headroom != nil || b.CapabilityProfile != nil {
			t.Errorf("Headroom = %+v, CapabilityProfile = %+v; want both nil when the peer could not be asked", b.Headroom, b.CapabilityProfile)
		}
	})

	t.Run("peer unhealthy", func(t *testing.T) {
		b := get("tunnel-unhealthy")
		if b.Headroom != nil || b.CapabilityProfile != nil {
			t.Errorf("Headroom = %+v, CapabilityProfile = %+v; want both nil for an unhealthy peer", b.Headroom, b.CapabilityProfile)
		}
		if n := unhealthy.calls.Load(); n != 0 {
			t.Errorf("unhealthy peer was queried %d time(s), want 0", n)
		}
	})

	t.Run("one forwarded call per healthy peer, with the caller's token", func(t *testing.T) {
		for name, p := range map[string]*fakeSystemInfoPeer{
			"advertising": advertising, "profiled": profiled, "neither": neither, "failing": failing,
		} {
			if n := p.calls.Load(); n != 1 {
				t.Errorf("%s: %d system-info call(s), want exactly 1 (no extra call for headroom/profile)", name, n)
			}
			if n := p.unrelated.Load(); n != 0 {
				t.Errorf("%s: %d call(s) to other endpoints, want 0", name, n)
			}
			if got, _ := p.authSeen.Load().(string); got != "Bearer caller-admin-token" {
				t.Errorf("%s: Authorization = %q, want the caller's token forwarded", name, got)
			}
		}
	})
}

// TestHostStateFrom_MatchesSnapshotMath pins the snapshot GetSystemInfo now
// builds from its own already-fetched figures (#2135) to the same math
// hostStateSnapshot always used, so a peer's advertised headroom is computed
// exactly as the local one is.
func TestHostStateFrom_MatchesSnapshotMath(t *testing.T) {
	now := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)

	st := hostStateFrom(nil, nil, now)
	if st.AvailableCPUs != 0 || st.AvailableMemoryBytes != 0 || st.AvailableDiskBytes != 0 || !st.Now.Equal(now) {
		t.Errorf("nil resources: %+v, want a zero-resource snapshot at now", st)
	}

	cases := []struct {
		name     string
		total    int32
		load     float64
		wantCPUs int32
	}{
		{"load below cores", 16, 4.5, 11},
		{"load above cores clamps to zero", 4, 9, 0},
		{"negative load clamps to total", 8, -3, 8},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := newTestSystemResources(tc.total, tc.load)
			st := hostStateFrom(nil, res, now)
			if st.AvailableCPUs != tc.wantCPUs {
				t.Errorf("AvailableCPUs = %d, want %d", st.AvailableCPUs, tc.wantCPUs)
			}
			if st.AvailableMemoryBytes != 24<<30 || st.AvailableDiskBytes != 300<<30 {
				t.Errorf("available mem/disk = %d/%d, want total-used", st.AvailableMemoryBytes, st.AvailableDiskBytes)
			}
		})
	}
}

func newTestSystemResources(totalCPUs int32, load1 float64) *incus.SystemResources {
	return &incus.SystemResources{
		TotalCPUs:        totalCPUs,
		CPULoad1Min:      load1,
		TotalMemoryBytes: 64 << 30,
		UsedMemoryBytes:  40 << 30,
		TotalDiskBytes:   500 << 30,
		UsedDiskBytes:    200 << 30,
	}
}
