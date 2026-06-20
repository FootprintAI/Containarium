package server

import (
	"errors"
	"sync"
	"testing"

	boxlxc "github.com/footprintai/containarium/pkg/core/box/lxc"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// newAttributionTestServer wires a ContainerServer over a *MockBackend seeded
// with the given containers. AddLabel merges into an in-memory label store
// (prefix-stripped, like the real GetLabels) and GetLabels reads it back, so a
// test can assert the merged result the handler returns.
func newAttributionTestServer(t *testing.T, seed map[string]*incus.ContainerInfo) (*ContainerServer, map[string]map[string]string) {
	t.Helper()
	mock := incustest.NewMockBackend()
	for name, info := range seed {
		mock.Containers[name] = info
	}
	var mu sync.Mutex
	// per-container label store (unprefixed keys, mirroring extractLabelsFromConfig).
	labels := make(map[string]map[string]string)
	mock.AddLabelFunc = func(name, key, value string) error {
		mu.Lock()
		defer mu.Unlock()
		if labels[name] == nil {
			labels[name] = map[string]string{}
		}
		labels[name][key] = value
		return nil
	}
	mock.GetLabelsFunc = func(name string) (map[string]string, error) {
		mu.Lock()
		defer mu.Unlock()
		out := map[string]string{}
		for k, v := range labels[name] {
			out[k] = v
		}
		return out, nil
	}
	mgr := container.NewWithBackend(mock)
	return &ContainerServer{manager: mgr, boxBackend: boxlxc.New(mgr)}, labels
}

// TestSetContainerAttribution_MergesLabels — the happy path: each provided
// label is stamped and the response echoes the merged set.
func TestSetContainerAttribution_MergesLabels(t *testing.T) {
	s, store := newAttributionTestServer(t, map[string]*incus.ContainerInfo{
		"alice-container": {Name: "alice-container", State: "Running"},
	})
	// Pre-existing unrelated label must survive the merge.
	store["alice-container"] = map[string]string{"os-type": "ubuntu"}

	resp, err := s.SetContainerAttribution(testCtx(), &pb.SetContainerAttributionRequest{
		Name: "alice",
		Labels: map[string]string{
			"cloud_org_id":       "org-A",
			"cloud_container_id": "cc-1",
			"managed_by":         "containarium-cloud",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("nil response")
	}
	for k, want := range map[string]string{
		"cloud_org_id": "org-A", "cloud_container_id": "cc-1",
		"managed_by": "containarium-cloud", "os-type": "ubuntu",
	} {
		if resp.Labels[k] != want {
			t.Errorf("label %q = %q, want %q (full: %+v)", k, resp.Labels[k], want, resp.Labels)
		}
	}
}

// TestSetContainerAttribution_EmptyLabelsRejected — an empty map is a no-op the
// caller shouldn't make; reject it rather than silently succeed.
func TestSetContainerAttribution_EmptyLabelsRejected(t *testing.T) {
	s, _ := newAttributionTestServer(t, map[string]*incus.ContainerInfo{
		"alice-container": {Name: "alice-container", State: "Running"},
	})
	_, err := s.SetContainerAttribution(testCtx(), &pb.SetContainerAttributionRequest{Name: "alice"})
	if st, ok := status.FromError(err); !ok || st.Code() != codes.InvalidArgument {
		t.Errorf("error = %v, want InvalidArgument", err)
	}
}

// TestSetContainerAttribution_MissingName — universal precondition check.
func TestSetContainerAttribution_MissingName(t *testing.T) {
	s := &ContainerServer{}
	_, err := s.SetContainerAttribution(testCtx(), &pb.SetContainerAttributionRequest{
		Labels: map[string]string{"cloud_org_id": "org-A"},
	})
	if st, ok := status.FromError(err); !ok || st.Code() != codes.InvalidArgument {
		t.Errorf("error = %v, want InvalidArgument", err)
	}
}

// TestSetContainerAttribution_UnknownContainer — NotFound, not Internal.
func TestSetContainerAttribution_UnknownContainer(t *testing.T) {
	mock := incustest.NewMockBackend()
	mock.GetContainerFunc = func(name string) (*incus.ContainerInfo, error) {
		return nil, errors.New("container not found: " + name)
	}
	mgr := container.NewWithBackend(mock)
	s := &ContainerServer{manager: mgr, boxBackend: boxlxc.New(mgr)}
	_, err := s.SetContainerAttribution(testCtx(), &pb.SetContainerAttributionRequest{
		Name:   "ghost",
		Labels: map[string]string{"cloud_org_id": "org-A"},
	})
	if st, ok := status.FromError(err); !ok || st.Code() != codes.NotFound {
		t.Errorf("error = %v, want NotFound", err)
	}
}

// TestSetContainerAttribution_CoreContainerRejected — attribution is for user
// containers only (symmetry with the TTL / delete-policy core guards).
func TestSetContainerAttribution_CoreContainerRejected(t *testing.T) {
	s, _ := newAttributionTestServer(t, map[string]*incus.ContainerInfo{
		"caddy-container": {Name: "caddy-container", State: "Running", Role: incus.RoleCaddy},
	})
	_, err := s.SetContainerAttribution(testCtx(), &pb.SetContainerAttributionRequest{
		Name:   "caddy",
		Labels: map[string]string{"cloud_org_id": "org-A"},
	})
	if st, ok := status.FromError(err); !ok || st.Code() != codes.InvalidArgument {
		t.Errorf("error = %v, want InvalidArgument", err)
	}
}
