package server

import (
	"context"
	"errors"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/box"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #1525 — ListContainers called s.manager.List() unconditionally, which on a
// K8s-backed daemon wraps incus.UnavailableBackend and fails every call with
// "incus backend not available on this host". create/delete/get already
// dispatch through the runtime-neutral box.BoxBackend seam; list didn't.

// fakeListBoxBackend is a minimal box.BoxBackend reporting a fixed status
// list, following the same "embed box.BoxBackend, override just what's
// needed" pattern as stubBoxes in container_rollback_test.go.
type fakeListBoxBackend struct {
	box.BoxBackend
	kind     box.BackendKind
	statuses []box.BoxStatus
	listErr  error
}

func (f *fakeListBoxBackend) Kind() box.BackendKind { return f.kind }

func (f *fakeListBoxBackend) List(context.Context) ([]box.BoxStatus, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.statuses, nil
}

func adminListCtx() context.Context {
	return auth.ContextWithTestSubjectScopes(context.Background(),
		"admin", []string{auth.RoleAdmin}, []string{auth.ScopeContainersRead})
}

func TestListContainers_DispatchesThroughK8sBoxBackend(t *testing.T) {
	fake := &fakeListBoxBackend{
		kind: box.KindK8s,
		statuses: []box.BoxStatus{
			{Ref: box.BoxRef{Tenant: "alice", Name: "alice-container"}, State: pb.ContainerState_CONTAINER_STATE_RUNNING},
			{Ref: box.BoxRef{Tenant: "bob", Name: "bob-container"}, State: pb.ContainerState_CONTAINER_STATE_RUNNING},
		},
	}
	s := &ContainerServer{boxBackend: fake, pendingCreations: map[string]*PendingCreation{}}

	resp, err := s.ListContainers(adminListCtx(), &pb.ListContainersRequest{})
	if err != nil {
		t.Fatalf("ListContainers: %v (this is the #1525 bug if it says \"incus backend not available\")", err)
	}
	if len(resp.Containers) != 2 {
		t.Fatalf("got %d containers, want 2: %+v", len(resp.Containers), resp.Containers)
	}
}

func TestListContainers_K8sExcludesCoreContainers(t *testing.T) {
	fake := &fakeListBoxBackend{
		kind: box.KindK8s,
		statuses: []box.BoxStatus{
			{Ref: box.BoxRef{Tenant: "postgres", Name: "core-postgres"}, IsCore: true},
			{Ref: box.BoxRef{Tenant: "alice", Name: "alice-container"}},
		},
	}
	s := &ContainerServer{boxBackend: fake, pendingCreations: map[string]*PendingCreation{}}

	resp, err := s.ListContainers(adminListCtx(), &pb.ListContainersRequest{})
	if err != nil {
		t.Fatalf("ListContainers: %v", err)
	}
	if len(resp.Containers) != 1 || resp.Containers[0].Username != "alice" {
		t.Fatalf("got %+v, want only alice's container (core-role box excluded)", resp.Containers)
	}
}

func TestListContainers_K8sFiltersByUsername(t *testing.T) {
	fake := &fakeListBoxBackend{
		kind: box.KindK8s,
		statuses: []box.BoxStatus{
			{Ref: box.BoxRef{Tenant: "alice", Name: "alice-container"}},
			{Ref: box.BoxRef{Tenant: "bob", Name: "bob-container"}},
		},
	}
	s := &ContainerServer{boxBackend: fake, pendingCreations: map[string]*PendingCreation{}}

	resp, err := s.ListContainers(adminListCtx(), &pb.ListContainersRequest{Username: "bob"})
	if err != nil {
		t.Fatalf("ListContainers: %v", err)
	}
	if len(resp.Containers) != 1 || resp.Containers[0].Username != "bob" {
		t.Fatalf("got %+v, want only bob's container", resp.Containers)
	}
}

func TestListContainers_K8sFiltersByLabel(t *testing.T) {
	fake := &fakeListBoxBackend{
		kind: box.KindK8s,
		statuses: []box.BoxStatus{
			{Ref: box.BoxRef{Tenant: "alice", Name: "alice-container"}, Labels: map[string]string{"team": "a"}},
			{Ref: box.BoxRef{Tenant: "bob", Name: "bob-container"}, Labels: map[string]string{"team": "b"}},
		},
	}
	s := &ContainerServer{boxBackend: fake, pendingCreations: map[string]*PendingCreation{}}

	resp, err := s.ListContainers(adminListCtx(), &pb.ListContainersRequest{LabelFilter: map[string]string{"team": "b"}})
	if err != nil {
		t.Fatalf("ListContainers: %v", err)
	}
	if len(resp.Containers) != 1 || resp.Containers[0].Username != "bob" {
		t.Fatalf("got %+v, want only bob's container (team=b)", resp.Containers)
	}
}

func TestListContainers_K8sPropagatesBackendError(t *testing.T) {
	fake := &fakeListBoxBackend{kind: box.KindK8s, listErr: errors.New("backend unavailable")}
	s := &ContainerServer{boxBackend: fake, pendingCreations: map[string]*PendingCreation{}}

	if _, err := s.ListContainers(adminListCtx(), &pb.ListContainersRequest{}); err == nil {
		t.Fatal("expected an error when the backend's List call fails")
	}
}
