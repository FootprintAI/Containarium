package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// TestBackendStorageFromPool_MapsDriverAndIsolation pins the projection from
// the incus driver onto the wire contract.
//
// The isolation column is the point of #1209: an operator asking "which of my
// backends can have one tenant stall another's fsync?" (#1206) has to be able
// to answer it from the API, not from a startup log on each host.
func TestBackendStorageFromPool_MapsDriverAndIsolation(t *testing.T) {
	tests := []struct {
		name          string
		driver        incus.StorageDriver
		wantDriver    pb.StorageDriver
		wantIsolation pb.StorageIsolation
	}{
		{
			name:          "zfs isolates",
			driver:        incus.StorageDriverZFS,
			wantDriver:    pb.StorageDriver_STORAGE_DRIVER_ZFS,
			wantIsolation: pb.StorageIsolation_STORAGE_ISOLATION_PER_CONTAINER,
		},
		{
			name:          "btrfs isolates",
			driver:        incus.StorageDriverBtrfs,
			wantDriver:    pb.StorageDriver_STORAGE_DRIVER_BTRFS,
			wantIsolation: pb.StorageIsolation_STORAGE_ISOLATION_PER_CONTAINER,
		},
		{
			name:          "lvm isolates",
			driver:        incus.StorageDriverLVM,
			wantDriver:    pb.StorageDriver_STORAGE_DRIVER_LVM,
			wantIsolation: pb.StorageIsolation_STORAGE_ISOLATION_PER_CONTAINER,
		},
		{
			name:          "ceph isolates",
			driver:        incus.StorageDriverCeph,
			wantDriver:    pb.StorageDriver_STORAGE_DRIVER_CEPH,
			wantIsolation: pb.StorageIsolation_STORAGE_ISOLATION_PER_CONTAINER,
		},
		{
			name:          "dir shares one filesystem across tenants",
			driver:        incus.StorageDriverDir,
			wantDriver:    pb.StorageDriver_STORAGE_DRIVER_DIR,
			wantIsolation: pb.StorageIsolation_STORAGE_ISOLATION_SHARED_FILESYSTEM,
		},
		{
			name:   "a driver we do not classify is OTHER, not UNSPECIFIED",
			driver: incus.StorageDriver("some-future-driver"),
			// OTHER means "read, but not classified"; UNSPECIFIED is reserved
			// for "could not read the pool at all". Collapsing them would make
			// an observed-but-unknown driver indistinguishable from a failure.
			wantDriver:    pb.StorageDriver_STORAGE_DRIVER_OTHER,
			wantIsolation: pb.StorageIsolation_STORAGE_ISOLATION_UNKNOWN_DRIVER,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := backendStorageFromPool("default", tt.driver)
			if got == nil {
				t.Fatal("got nil for an observed driver")
			}
			if got.Driver != tt.wantDriver {
				t.Errorf("Driver = %v, want %v", got.Driver, tt.wantDriver)
			}
			if got.Isolation != tt.wantIsolation {
				t.Errorf("Isolation = %v, want %v", got.Isolation, tt.wantIsolation)
			}
			if got.Pool != "default" {
				t.Errorf("Pool = %q, want %q", got.Pool, "default")
			}
			// The raw name always travels, so a STORAGE_DRIVER_OTHER value is
			// still actionable for an operator.
			if got.DriverName != string(tt.driver) {
				t.Errorf("DriverName = %q, want %q", got.DriverName, tt.driver)
			}
		})
	}
}

// TestBackendStorageFromPool_NilWhenNothingObserved is the "we don't know"
// case. A pool the daemon could not read must come back absent, not as a
// zero-valued struct — the same rule host_load already follows, and the
// difference between an operator seeing "unknown" and wrongly seeing an
// isolated-looking default.
func TestBackendStorageFromPool_NilWhenNothingObserved(t *testing.T) {
	if got := backendStorageFromPool("default", ""); got != nil {
		t.Errorf("expected nil for an unread pool, got %+v", got)
	}
}

// TestContainerServer_ListBackends_PeerReportsStorage proves the fleet view
// actually carries a peer's storage property end to end.
//
// This is the whole point of #1209: a BYOC tunnel host sitting on a
// shared-filesystem pool is invisible today unless someone reads that host's
// own startup log. It has to show up in the fleet listing.
func TestContainerServer_ListBackends_PeerReportsStorage(t *testing.T) {
	peerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/system/info" {
			http.NotFound(w, r)
			return
		}
		// protojson wire shape a real peer daemon emits through grpc-gateway.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"info":{
			"hostname":"byoc-host",
			"storage":{
				"pool":"default",
				"driver":"STORAGE_DRIVER_DIR",
				"isolation":"STORAGE_ISOLATION_SHARED_FILESYSTEM",
				"driverName":"dir"
			}
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
	// protojson fails the WHOLE decode on an unknown field, so assert a field
	// from outside the storage block: otherwise a drifted payload reads as
	// "storage dropped" rather than "this test's JSON is wrong".
	if peer.Hostname != "byoc-host" {
		t.Fatalf("Hostname = %q — the peer's SystemInfo did not decode at all", peer.Hostname)
	}
	if peer.Storage == nil {
		t.Fatal("peer Storage is nil — a shared-filesystem BYOC host is invisible in the fleet view (#1209)")
	}
	if peer.Storage.Isolation != pb.StorageIsolation_STORAGE_ISOLATION_SHARED_FILESYSTEM {
		t.Errorf("Isolation = %v, want SHARED_FILESYSTEM", peer.Storage.Isolation)
	}
	if peer.Storage.DriverName != "dir" {
		t.Errorf("DriverName = %q, want %q", peer.Storage.DriverName, "dir")
	}
}

// TestContainerServer_ListBackends_PeerWithoutStorageReportsNil is the
// "we don't know" half. An older peer daemon that predates this field must
// come back with Storage nil, not a zero-valued struct that would render as
// an isolated-looking default.
func TestContainerServer_ListBackends_PeerWithoutStorageReportsNil(t *testing.T) {
	peerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/system/info" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"info":{"hostname":"old-peer"}}`))
	}))
	defer peerSrv.Close()

	pool := NewPeerPool("local-spot", "", nil, "")
	pool.mu.Lock()
	pool.peers["tunnel-old"] = &PeerClient{
		ID:      "tunnel-old",
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
	for _, b := range resp.Backends {
		if b.Id == "tunnel-old" && b.Storage != nil {
			t.Errorf("Storage = %+v, want nil for a peer that reported none", b.Storage)
		}
	}
}
