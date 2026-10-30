package server

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/poolcapacity"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Pool headroom floor (#3128): creates and snapshots succeed above the floor
// and fail closed below it, against a fake pool-capacity source.

// headroomGuard builds a guard over a fixed snapshot: each pool at usedPct of
// 100 GiB, "default" as the daemon's default pool, default floors.
func headroomGuard(usedPct map[string]int64) *poolcapacity.Guard {
	snap := poolcapacity.Snapshot{}
	for name, pct := range usedPct {
		u := incus.StoragePoolUsage{Name: name, Driver: "zfs", UsedBytes: pct << 30, TotalBytes: 100 << 30}
		snap.Pools = append(snap.Pools, poolcapacity.Sample{StoragePoolUsage: u, Level: poolcapacity.Classify(u.UsedBytes, u.TotalBytes)})
	}
	return poolcapacity.NewGuard(nil, func() poolcapacity.Snapshot { return snap },
		func() string { return "default" }, func(string, ...any) {})
}

func wantHeadroomRefusal(t *testing.T, err error, pool string) {
	t.Helper()
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("err = %v (code %v), want ResourceExhausted", err, status.Code(err))
	}
	if !strings.Contains(err.Error(), `"`+pool+`"`) || !strings.Contains(err.Error(), "headroom") {
		t.Errorf("refusal does not name pool %q and its headroom: %v", pool, err)
	}
}

func TestCreateContainerSnapshot_PoolHeadroomFloor(t *testing.T) {
	tests := []struct {
		name      string
		poolOf    map[string]string
		usedPct   map[string]int64
		refusedOn string
	}{
		{name: "above the floor", usedPct: map[string]int64{"default": 94}},
		{name: "below the floor", usedPct: map[string]int64{"default": 96}, refusedOn: "default"},
		{
			name:      "checks the container's own pool, not the default",
			poolOf:    map[string]string{"bob-container": "containarium-tenant-bob"},
			usedPct:   map[string]int64{"default": 10, "containarium-tenant-bob": 97},
			refusedOn: "containarium-tenant-bob",
		},
		{
			name:    "a full default pool does not block a container on another pool",
			poolOf:  map[string]string{"bob-container": "containarium-tenant-bob"},
			usedPct: map[string]int64{"default": 99, "containarium-tenant-bob": 40},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			z := newZFSFake()
			s := snapshotFixture(t, z, tt.poolOf)
			s.SetPoolHeadroomGuard(headroomGuard(tt.usedPct))

			// A nightly backup-* name goes through the same path.
			_, err := s.CreateContainerSnapshot(writeCtx("bob"),
				&pb.CreateContainerSnapshotRequest{Username: "bob", Name: "backup-20261026-030001"})
			if tt.refusedOn == "" {
				if err != nil {
					t.Fatalf("CreateContainerSnapshot: %v", err)
				}
				return
			}
			wantHeadroomRefusal(t, err, tt.refusedOn)
			for _, c := range z.calls {
				if strings.HasPrefix(c, "snapshot ") {
					t.Errorf("zfs snapshot ran despite the refusal: %v", z.calls)
				}
			}
		})
	}
}

func TestCreateContainer_PoolHeadroomFloor(t *testing.T) {
	tests := []struct {
		name    string
		usedPct map[string]int64
		refused bool
	}{
		{name: "above the floor", usedPct: map[string]int64{"default": 90}},
		{name: "below the floor", usedPct: map[string]int64{"default": 95}, refused: true},
		{name: "pool size never read: allowed", usedPct: map[string]int64{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &ContainerServer{}
			s.SetPoolHeadroomGuard(headroomGuard(tt.usedPct))
			// Dry run: every pre-provisioning check runs, nothing is created.
			resp, err := dryRunNoPanic(t, s, &pb.CreateContainerRequest{Username: "alice", DryRun: true})
			if tt.refused {
				wantHeadroomRefusal(t, err, "default")
				return
			}
			if err != nil || !resp.GetDryRun() {
				t.Fatalf("create refused above the floor: resp=%v err=%v", resp, err)
			}
		})
	}
}

func TestMoveContainer_PoolHeadroomFloor(t *testing.T) {
	runner := &fakeRunner{hasRemote: true}
	cs := newTestContainerServer(t, runner, "vm2")
	cs.SetPoolHeadroomGuard(headroomGuard(map[string]int64{"default": 98}))

	_, err := cs.MoveContainer(testCtx(), &pb.MoveContainerRequest{Username: "alice", TargetBackendId: "vm2"})
	wantHeadroomRefusal(t, err, "default")
	for _, c := range runner.calls {
		if strings.HasPrefix(c, "snapshot ") {
			t.Errorf("a migration snapshot ran despite the refusal: %v", runner.calls)
		}
	}
}
