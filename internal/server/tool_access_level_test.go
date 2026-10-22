package server

import (
	"sync"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// newToolAccessTestServer wires a ContainerServer to a mock backend whose
// SetConfig mirrors the tool-access key into the stored container, as real
// Incus would, so a Set followed by a Get round-trips.
func newToolAccessTestServer(t *testing.T, seed map[string]*incus.ContainerInfo) (*ContainerServer, *[]setConfigCall) {
	t.Helper()
	mock := incustest.NewMockBackend()
	for name, info := range seed {
		mock.Containers[name] = info
	}
	var mu sync.Mutex
	calls := make([]setConfigCall, 0, 2)
	mock.SetConfigFunc = func(name, key, value string) error {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, setConfigCall{name: name, key: key, value: value})
		if c, ok := mock.Containers[name]; ok && key == incus.ToolAccessLevelKey {
			c.ToolAccessLevel = value
		}
		return nil
	}
	return &ContainerServer{manager: container.NewWithBackend(mock)}, &calls
}

func aliceBox() map[string]*incus.ContainerInfo {
	return map[string]*incus.ContainerInfo{
		"alice-container": {Name: "alice-container", State: "Running", Tenant: "alice"},
	}
}

func TestGetToolAccessLevel_DefaultsToNone(t *testing.T) {
	s, _ := newToolAccessTestServer(t, aliceBox())
	resp, err := s.GetToolAccessLevel(testCtx(), &pb.GetToolAccessLevelRequest{Username: "alice"})
	if err != nil {
		t.Fatalf("GetToolAccessLevel: %v", err)
	}
	if resp.Level != pb.ToolAccessLevel_TOOL_ACCESS_LEVEL_NONE {
		t.Fatalf("level = %v, want NONE for a box that never had one set", resp.Level)
	}
}

// A stored value we do not recognise must read as the safest level, never as
// a broader one.
func TestGetToolAccessLevel_UnrecognisedStoredValueFailsClosed(t *testing.T) {
	seed := aliceBox()
	seed["alice-container"].ToolAccessLevel = "root_everything"
	s, _ := newToolAccessTestServer(t, seed)
	resp, err := s.GetToolAccessLevel(testCtx(), &pb.GetToolAccessLevelRequest{Username: "alice"})
	if err != nil {
		t.Fatalf("GetToolAccessLevel: %v", err)
	}
	if resp.Level != pb.ToolAccessLevel_TOOL_ACCESS_LEVEL_NONE {
		t.Fatalf("level = %v, want NONE for an unrecognised stored value", resp.Level)
	}
}

func TestSetToolAccessLevel_RoundTripsEveryLevel(t *testing.T) {
	cases := []struct {
		level  pb.ToolAccessLevel
		stored string
	}{
		{pb.ToolAccessLevel_TOOL_ACCESS_LEVEL_BUILD_TOOLS, "build_tools"},
		{pb.ToolAccessLevel_TOOL_ACCESS_LEVEL_FULL_SUDO, "full_sudo"},
		{pb.ToolAccessLevel_TOOL_ACCESS_LEVEL_NONE, "none"},
	}
	for _, tc := range cases {
		t.Run(tc.stored, func(t *testing.T) {
			// Start from a different level so the write is not a no-op.
			seed := aliceBox()
			if tc.level == pb.ToolAccessLevel_TOOL_ACCESS_LEVEL_NONE {
				seed["alice-container"].ToolAccessLevel = "full_sudo"
			}
			s, calls := newToolAccessTestServer(t, seed)
			resp, err := s.SetToolAccessLevel(testCtx(), &pb.SetToolAccessLevelRequest{Username: "alice", Level: tc.level})
			if err != nil {
				t.Fatalf("SetToolAccessLevel: %v", err)
			}
			if resp.Level != tc.level {
				t.Fatalf("response level = %v, want %v", resp.Level, tc.level)
			}
			if len(*calls) != 1 || (*calls)[0].name != "alice-container" ||
				(*calls)[0].key != incus.ToolAccessLevelKey || (*calls)[0].value != tc.stored {
				t.Fatalf("SetConfig calls = %+v, want one write of %q to %s", *calls, tc.stored, incus.ToolAccessLevelKey)
			}
			got, err := s.GetToolAccessLevel(testCtx(), &pb.GetToolAccessLevelRequest{Username: "alice"})
			if err != nil || got.Level != tc.level {
				t.Fatalf("Get after Set = %v, %v; want %v", got, err, tc.level)
			}
		})
	}
}

func TestSetToolAccessLevel_SameLevelIsIdempotentNoWrite(t *testing.T) {
	seed := aliceBox()
	seed["alice-container"].ToolAccessLevel = "build_tools"
	s, calls := newToolAccessTestServer(t, seed)
	resp, err := s.SetToolAccessLevel(testCtx(), &pb.SetToolAccessLevelRequest{
		Username: "alice", Level: pb.ToolAccessLevel_TOOL_ACCESS_LEVEL_BUILD_TOOLS,
	})
	if err != nil {
		t.Fatalf("SetToolAccessLevel: %v", err)
	}
	if resp.Level != pb.ToolAccessLevel_TOOL_ACCESS_LEVEL_BUILD_TOOLS {
		t.Fatalf("level = %v", resp.Level)
	}
	if len(*calls) != 0 {
		t.Fatalf("setting the level the box already has wrote config: %+v", *calls)
	}
}

func TestSetToolAccessLevel_Rejects(t *testing.T) {
	cases := []struct {
		name string
		seed map[string]*incus.ContainerInfo
		req  *pb.SetToolAccessLevelRequest
		want codes.Code
	}{
		{"unspecified level", aliceBox(),
			&pb.SetToolAccessLevelRequest{Username: "alice", Level: pb.ToolAccessLevel_TOOL_ACCESS_LEVEL_UNSPECIFIED}, codes.InvalidArgument},
		{"out-of-range level", aliceBox(),
			&pb.SetToolAccessLevelRequest{Username: "alice", Level: pb.ToolAccessLevel(99)}, codes.InvalidArgument},
		{"empty username", aliceBox(),
			&pb.SetToolAccessLevelRequest{Level: pb.ToolAccessLevel_TOOL_ACCESS_LEVEL_FULL_SUDO}, codes.InvalidArgument},
		{"unknown box", map[string]*incus.ContainerInfo{},
			&pb.SetToolAccessLevelRequest{Username: "alice", Level: pb.ToolAccessLevel_TOOL_ACCESS_LEVEL_FULL_SUDO}, codes.NotFound},
		{"core container", map[string]*incus.ContainerInfo{
			"alice-container": {Name: "alice-container", Tenant: "alice", Role: incus.RolePostgres},
		}, &pb.SetToolAccessLevelRequest{Username: "alice", Level: pb.ToolAccessLevel_TOOL_ACCESS_LEVEL_FULL_SUDO}, codes.InvalidArgument},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, calls := newToolAccessTestServer(t, tc.seed)
			_, err := s.SetToolAccessLevel(testCtx(), tc.req)
			if status.Code(err) != tc.want {
				t.Fatalf("code = %v (%v), want %v", status.Code(err), err, tc.want)
			}
			if len(*calls) != 0 {
				t.Fatalf("a rejected request wrote config: %+v", *calls)
			}
		})
	}
}

func TestToolAccessLevel_ScopeAndTenantGates(t *testing.T) {
	s, calls := newToolAccessTestServer(t, aliceBox())

	// Set needs containers:write; Get needs containers:read.
	readOnly := tenantWithScopes("alice", auth.ScopeContainersRead)
	if _, err := s.SetToolAccessLevel(readOnly, &pb.SetToolAccessLevelRequest{
		Username: "alice", Level: pb.ToolAccessLevel_TOOL_ACCESS_LEVEL_FULL_SUDO,
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("Set without containers:write: got %v", err)
	}
	writeOnly := tenantWithScopes("alice", auth.ScopeContainersWrite)
	if _, err := s.GetToolAccessLevel(writeOnly, &pb.GetToolAccessLevelRequest{Username: "alice"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("Get without containers:read: got %v", err)
	}

	// Another tenant, even with the right scopes, must not read or raise alice's level.
	bob := tenantWithScopes("bob", auth.ScopeContainersRead, auth.ScopeContainersWrite)
	if _, err := s.SetToolAccessLevel(bob, &pb.SetToolAccessLevelRequest{
		Username: "alice", Level: pb.ToolAccessLevel_TOOL_ACCESS_LEVEL_FULL_SUDO,
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("Set across tenants: got %v", err)
	}
	if _, err := s.GetToolAccessLevel(bob, &pb.GetToolAccessLevelRequest{Username: "alice"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("Get across tenants: got %v", err)
	}
	if len(*calls) != 0 {
		t.Fatalf("a denied request wrote config: %+v", *calls)
	}
}

// Setting NONE over an unrecognised stored value rewrites it to the canonical
// spelling instead of treating the box as already at NONE.
func TestSetToolAccessLevel_NoneOverwritesUnrecognisedStoredValue(t *testing.T) {
	seed := aliceBox()
	seed["alice-container"].ToolAccessLevel = "root_everything"
	s, calls := newToolAccessTestServer(t, seed)
	if _, err := s.SetToolAccessLevel(testCtx(), &pb.SetToolAccessLevelRequest{
		Username: "alice", Level: pb.ToolAccessLevel_TOOL_ACCESS_LEVEL_NONE,
	}); err != nil {
		t.Fatalf("SetToolAccessLevel: %v", err)
	}
	if len(*calls) != 1 || (*calls)[0].value != "none" {
		t.Fatalf("SetConfig calls = %+v, want one write of \"none\"", *calls)
	}
}
