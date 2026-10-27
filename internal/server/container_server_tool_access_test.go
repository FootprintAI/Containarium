package server

import (
	"sync"
	"testing"

	"github.com/footprintai/containarium/pkg/core/box"
	boxlxc "github.com/footprintai/containarium/pkg/core/box/lxc"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// newToolAccessTestServer wires a ContainerServer over a MockBackend seeded with
// the given containers. Writes to the tool-access key land in the mock, so a
// follow-up Get reflects them, and every Set/UnsetConfig is captured.
func newToolAccessTestServer(t *testing.T, seed map[string]*incus.ContainerInfo) (*ContainerServer, *incustest.MockBackend, *[]dpMockCall) {
	t.Helper()
	mock := incustest.NewMockBackend()
	for name, info := range seed {
		mock.Containers[name] = info
	}
	var mu sync.Mutex
	calls := make([]dpMockCall, 0, 2)
	mock.SetConfigFunc = func(name, key, value string) error {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, dpMockCall{kind: "set", name: name, key: key, value: value})
		if c, ok := mock.Containers[name]; ok && key == incus.ToolAccessKey {
			c.ToolAccess = value
		}
		return nil
	}
	mock.UnsetConfigFunc = func(name, key string) error {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, dpMockCall{kind: "unset", name: name, key: key})
		if c, ok := mock.Containers[name]; ok && key == incus.ToolAccessKey {
			c.ToolAccess = ""
		}
		return nil
	}
	mgr := container.NewWithBackend(mock)
	return &ContainerServer{manager: mgr, boxBackend: boxlxc.New(mgr)}, mock, &calls
}

// Each level is stored as its stable string under the documented key, and the
// response echoes the level.
func TestSetContainerToolAccess_StoresEachLevel(t *testing.T) {
	for _, tc := range []struct {
		level pb.BoxToolAccess
		want  string
	}{
		{pb.BoxToolAccess_BOX_TOOL_ACCESS_NONE, "none"},
		{pb.BoxToolAccess_BOX_TOOL_ACCESS_BUILD_TOOLS, "build_tools"},
		{pb.BoxToolAccess_BOX_TOOL_ACCESS_FULL_SUDO, "full_sudo"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			s, _, calls := newToolAccessTestServer(t, map[string]*incus.ContainerInfo{
				"alice-container": {Name: "alice-container", State: "Running"},
			})
			resp, err := s.SetContainerToolAccess(testCtx(), &pb.SetContainerToolAccessRequest{Name: "alice", ToolAccess: tc.level})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.GetToolAccess() != tc.level {
				t.Errorf("response level = %v, want %v", resp.GetToolAccess(), tc.level)
			}
			if len(*calls) != 1 {
				t.Fatalf("expected 1 SetConfig call, got %d: %+v", len(*calls), *calls)
			}
			c := (*calls)[0]
			if c.kind != "set" || c.name != "alice-container" || c.key != "user.containarium.tool_access" || c.value != tc.want {
				t.Errorf("call = %+v, want set alice-container/user.containarium.tool_access=%s", c, tc.want)
			}
		})
	}
}

// UNSPECIFIED removes the key ("none recorded"), and the response says so.
func TestSetContainerToolAccess_UnspecifiedClearsKey(t *testing.T) {
	s, _, calls := newToolAccessTestServer(t, map[string]*incus.ContainerInfo{
		"alice-container": {Name: "alice-container", State: "Running", ToolAccess: incus.ToolAccessBuildTools},
	})
	resp, err := s.SetContainerToolAccess(testCtx(), &pb.SetContainerToolAccessRequest{Name: "alice", ToolAccess: pb.BoxToolAccess_BOX_TOOL_ACCESS_UNSPECIFIED})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.GetToolAccess() != pb.BoxToolAccess_BOX_TOOL_ACCESS_UNSPECIFIED {
		t.Errorf("response level = %v, want UNSPECIFIED", resp.GetToolAccess())
	}
	if len(*calls) != 1 || (*calls)[0].kind != "unset" || (*calls)[0].key != incus.ToolAccessKey {
		t.Fatalf("calls = %+v, want one unset of %s", *calls, incus.ToolAccessKey)
	}
}

// An enum value this daemon does not know is refused and writes nothing.
func TestSetContainerToolAccess_UnknownLevelRefusedAndNothingWritten(t *testing.T) {
	s, _, calls := newToolAccessTestServer(t, map[string]*incus.ContainerInfo{
		"alice-container": {Name: "alice-container", State: "Running"},
	})
	_, err := s.SetContainerToolAccess(testCtx(), &pb.SetContainerToolAccessRequest{Name: "alice", ToolAccess: pb.BoxToolAccess(99)})
	if st, ok := status.FromError(err); !ok || st.Code() != codes.InvalidArgument {
		t.Fatalf("error = %v, want InvalidArgument", err)
	}
	if len(*calls) != 0 {
		t.Errorf("a refused request must not write: %+v", *calls)
	}
}

func TestSetContainerToolAccess_MissingNameAndUnknownBox(t *testing.T) {
	_, err := (&ContainerServer{}).SetContainerToolAccess(testCtx(), &pb.SetContainerToolAccessRequest{ToolAccess: pb.BoxToolAccess_BOX_TOOL_ACCESS_NONE})
	if st, ok := status.FromError(err); !ok || st.Code() != codes.InvalidArgument {
		t.Errorf("missing name: error = %v, want InvalidArgument", err)
	}
	s, _, calls := newToolAccessTestServer(t, nil)
	_, err = s.SetContainerToolAccess(testCtx(), &pb.SetContainerToolAccessRequest{Name: "ghost", ToolAccess: pb.BoxToolAccess_BOX_TOOL_ACCESS_NONE})
	if st, ok := status.FromError(err); !ok || st.Code() != codes.NotFound {
		t.Errorf("unknown box: error = %v, want NotFound", err)
	}
	if len(*calls) != 0 {
		t.Errorf("an unknown box must not be written: %+v", *calls)
	}
}

// The recorded level reads back on the real container view (toProtoContainer),
// and a hand-edited bad value reads back as "none recorded" instead of granting
// anything.
func TestToProtoContainer_ToolAccessReadBack(t *testing.T) {
	for _, tc := range []struct {
		stored string
		want   pb.BoxToolAccess
	}{
		{"", pb.BoxToolAccess_BOX_TOOL_ACCESS_UNSPECIFIED},
		{"none", pb.BoxToolAccess_BOX_TOOL_ACCESS_NONE},
		{"build_tools", pb.BoxToolAccess_BOX_TOOL_ACCESS_BUILD_TOOLS},
		{"full_sudo", pb.BoxToolAccess_BOX_TOOL_ACCESS_FULL_SUDO},
		{"FULL_SUDO", pb.BoxToolAccess_BOX_TOOL_ACCESS_UNSPECIFIED},
		{"root", pb.BoxToolAccess_BOX_TOOL_ACCESS_UNSPECIFIED},
	} {
		pc := toProtoContainer(&box.BoxStatus{
			Ref:        box.BoxRef{Name: "alice-container"},
			State:      pb.ContainerState_CONTAINER_STATE_RUNNING,
			ToolAccess: tc.stored,
		})
		if pc.ToolAccess != tc.want {
			t.Errorf("stored %q -> container view %v, want %v", tc.stored, pc.ToolAccess, tc.want)
		}
	}
}
