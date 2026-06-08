package server

import (
	"errors"
	"sync"
	"testing"

	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// dpMockCall captures a single Set/UnsetConfig invocation the handler makes,
// mirroring ttlMockCall in container_server_ttl_test.go.
type dpMockCall struct {
	kind  string // "set" or "unset"
	name  string
	key   string
	value string
}

// newDeletePolicyTestServer wires a ContainerServer over a *MockBackend seeded
// with the given containers, persisting delete-policy writes into the mock so a
// follow-up Get reflects them. Returns the captured-call slice for inspection.
func newDeletePolicyTestServer(t *testing.T, seed map[string]*incus.ContainerInfo) (*ContainerServer, *[]dpMockCall) {
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
		if c, ok := mock.Containers[name]; ok && key == incus.DeletePolicyKey {
			c.DeletePolicy = value
		}
		return nil
	}
	mock.UnsetConfigFunc = func(name, key string) error {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, dpMockCall{kind: "unset", name: name, key: key})
		if c, ok := mock.Containers[name]; ok && key == incus.DeletePolicyKey {
			c.DeletePolicy = ""
		}
		return nil
	}
	mgr := container.NewWithBackend(mock)
	return &ContainerServer{manager: mgr}, &calls
}

// TestSetContainerDeletePolicy_ProtectStampsKey — PROTECTED writes one SetConfig
// with the canonical "protected" value, and the response echoes the policy.
func TestSetContainerDeletePolicy_ProtectStampsKey(t *testing.T) {
	s, calls := newDeletePolicyTestServer(t, map[string]*incus.ContainerInfo{
		"alice-container": {Name: "alice-container", State: "Running"},
	})
	resp, err := s.SetContainerDeletePolicy(testCtx(), &pb.SetContainerDeletePolicyRequest{
		Name:         "alice",
		DeletePolicy: pb.DeletePolicy_DELETE_POLICY_PROTECTED,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.DeletePolicy != pb.DeletePolicy_DELETE_POLICY_PROTECTED {
		t.Fatalf("response = %+v, want DELETE_POLICY_PROTECTED", resp)
	}
	if len(*calls) != 1 {
		t.Fatalf("expected 1 SetConfig call, got %d: %+v", len(*calls), *calls)
	}
	c := (*calls)[0]
	if c.kind != "set" || c.name != "alice-container" || c.key != incus.DeletePolicyKey || c.value != incus.DeletePolicyProtected {
		t.Errorf("call = %+v, want set alice-container/%s=%s", c, incus.DeletePolicyKey, incus.DeletePolicyProtected)
	}
}

// TestSetContainerDeletePolicy_UnspecifiedClearsKey — UNSPECIFIED removes the
// key (so the prune filter / ttlsweeper see "absent"), response unprotected.
func TestSetContainerDeletePolicy_UnspecifiedClearsKey(t *testing.T) {
	s, calls := newDeletePolicyTestServer(t, map[string]*incus.ContainerInfo{
		"alice-container": {
			Name:         "alice-container",
			State:        "Running",
			DeletePolicy: incus.DeletePolicyProtected,
		},
	})
	resp, err := s.SetContainerDeletePolicy(testCtx(), &pb.SetContainerDeletePolicyRequest{
		Name:         "alice",
		DeletePolicy: pb.DeletePolicy_DELETE_POLICY_UNSPECIFIED,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.DeletePolicy != pb.DeletePolicy_DELETE_POLICY_UNSPECIFIED {
		t.Fatalf("response = %+v, want DELETE_POLICY_UNSPECIFIED", resp)
	}
	if len(*calls) != 1 {
		t.Fatalf("expected 1 UnsetConfig call, got %d: %+v", len(*calls), *calls)
	}
	c := (*calls)[0]
	if c.kind != "unset" || c.name != "alice-container" || c.key != incus.DeletePolicyKey {
		t.Errorf("call = %+v, want unset alice-container/%s", c, incus.DeletePolicyKey)
	}
}

// TestSetContainerDeletePolicy_UnknownContainer — NotFound, not Internal.
func TestSetContainerDeletePolicy_UnknownContainer(t *testing.T) {
	mock := incustest.NewMockBackend()
	mock.GetContainerFunc = func(name string) (*incus.ContainerInfo, error) {
		return nil, errors.New("container not found: " + name)
	}
	s := &ContainerServer{manager: container.NewWithBackend(mock)}
	_, err := s.SetContainerDeletePolicy(testCtx(), &pb.SetContainerDeletePolicyRequest{
		Name:         "ghost",
		DeletePolicy: pb.DeletePolicy_DELETE_POLICY_PROTECTED,
	})
	if err == nil {
		t.Fatal("expected error for missing container")
	}
	if st, ok := status.FromError(err); !ok || st.Code() != codes.NotFound {
		t.Errorf("error = %v, want NotFound status", err)
	}
}

// TestSetContainerDeletePolicy_MissingName — universal precondition check.
func TestSetContainerDeletePolicy_MissingName(t *testing.T) {
	s := &ContainerServer{}
	_, err := s.SetContainerDeletePolicy(testCtx(), &pb.SetContainerDeletePolicyRequest{
		DeletePolicy: pb.DeletePolicy_DELETE_POLICY_PROTECTED,
	})
	if err == nil {
		t.Fatal("expected error for empty name")
	}
	if st, ok := status.FromError(err); !ok || st.Code() != codes.InvalidArgument {
		t.Errorf("error = %v, want InvalidArgument status", err)
	}
}

// TestSetContainerDeletePolicy_CoreContainerRejected — delete policy is for user
// containers only; an operator must not pin "protected" on a core LXC by
// accident (symmetry with the TTL handler's core guard).
func TestSetContainerDeletePolicy_CoreContainerRejected(t *testing.T) {
	s, calls := newDeletePolicyTestServer(t, map[string]*incus.ContainerInfo{
		"caddy-container": {
			Name:  "caddy-container",
			State: "Running",
			Role:  incus.RoleCaddy,
		},
	})
	_, err := s.SetContainerDeletePolicy(testCtx(), &pb.SetContainerDeletePolicyRequest{
		Name:         "caddy",
		DeletePolicy: pb.DeletePolicy_DELETE_POLICY_PROTECTED,
	})
	if err == nil {
		t.Fatal("expected error for core container")
	}
	if st, ok := status.FromError(err); !ok || st.Code() != codes.InvalidArgument {
		t.Errorf("error = %v, want InvalidArgument status", err)
	}
	if len(*calls) != 0 {
		t.Errorf("core rejection must not call Set/UnsetConfig, got %d calls: %+v", len(*calls), *calls)
	}
}

// TestToProtoContainer_DeletePolicySurfaced — a protected box surfaces as the
// PROTECTED enum on the read path; an unprotected box as UNSPECIFIED.
func TestToProtoContainer_DeletePolicySurfaced(t *testing.T) {
	protected := toProtoContainer(&incus.ContainerInfo{
		Name:         "alice-container",
		State:        "Running",
		DeletePolicy: incus.DeletePolicyProtected,
	})
	if protected.DeletePolicy != pb.DeletePolicy_DELETE_POLICY_PROTECTED {
		t.Errorf("protected box delete_policy = %v, want PROTECTED", protected.DeletePolicy)
	}
	unprotected := toProtoContainer(&incus.ContainerInfo{
		Name:  "bob-container",
		State: "Running",
	})
	if unprotected.DeletePolicy != pb.DeletePolicy_DELETE_POLICY_UNSPECIFIED {
		t.Errorf("unprotected box delete_policy = %v, want UNSPECIFIED", unprotected.DeletePolicy)
	}
}
