package server

import (
	"context"
	"testing"

	"github.com/footprintai/containarium/internal/tracker"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Scope-route RPCs (#2021). Route CRUD is tracker:admin, like connection
// CRUD: which skill a label starts is an operator decision, never
// something a run's tracker:read/write token can change.

func TestTrackerRoute_RequiresTrackerAdmin(t *testing.T) {
	s := &ContainerServer{}
	tests := []struct {
		name string
		ctx  context.Context
		want codes.Code
	}{
		{"no auth context", context.Background(), codes.Unauthenticated},
		{"tracker:write is not enough", kmsKeyTestCtx("alice", "member", "tracker:write"), codes.PermissionDenied},
		{"tracker:read is not enough", kmsKeyTestCtx("alice", "member", "tracker:read"), codes.PermissionDenied},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := s.SetTrackerRoute(tt.ctx, &pb.SetTrackerRouteRequest{Username: "alice", Connection: "default", Scope: "product", SkillId: "product-define"})
			if status.Code(err) != tt.want {
				t.Errorf("SetTrackerRoute code = %v, want %v", status.Code(err), tt.want)
			}
			_, err = s.ListTrackerRoutes(tt.ctx, &pb.ListTrackerRoutesRequest{Username: "alice", Connection: "default"})
			if status.Code(err) != tt.want {
				t.Errorf("ListTrackerRoutes code = %v, want %v", status.Code(err), tt.want)
			}
			_, err = s.DeleteTrackerRoute(tt.ctx, &pb.DeleteTrackerRouteRequest{Username: "alice", Connection: "default", Scope: "product"})
			if status.Code(err) != tt.want {
				t.Errorf("DeleteTrackerRoute code = %v, want %v", status.Code(err), tt.want)
			}
		})
	}
}

func TestTrackerRoute_NilStoreUnavailable(t *testing.T) {
	s := &ContainerServer{}
	ctx := kmsKeyTestCtx("alice", "member", "tracker:admin")
	if _, err := s.ListTrackerRoutes(ctx, &pb.ListTrackerRoutesRequest{Username: "alice", Connection: "default"}); status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", status.Code(err))
	}
}

func TestTrackerRoute_CrossTenantDenied(t *testing.T) {
	s := &ContainerServer{trackerStore: mustTestTrackerStore(t)}
	ctx := kmsKeyTestCtx("tracker-route-rpc-alice", "member", "tracker:admin")
	_, err := s.SetTrackerRoute(ctx, &pb.SetTrackerRouteRequest{
		Username: "tracker-route-rpc-bob", Connection: "default", Scope: "product", SkillId: "product-define",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", status.Code(err))
	}
}

func TestTrackerRoute_CRUDRoundTrip(t *testing.T) {
	store := mustTestTrackerStore(t)
	s := &ContainerServer{trackerStore: store}
	const user = "tracker-route-rpc-crud"
	ctx := context.Background()
	_ = store.Delete(ctx, user, "default")
	if _, err := store.Set(ctx, tracker.Connection{
		Username: user, Name: "default", Provider: pb.TrackerProvider_TRACKER_PROVIDER_GITHUB,
		Project: "acme/widgets", CredentialSecret: "GH_TOKEN",
	}); err != nil {
		t.Fatalf("seed connection: %v", err)
	}

	admin := kmsKeyTestCtx(user, "member", "tracker:admin")
	setResp, err := s.SetTrackerRoute(admin, &pb.SetTrackerRouteRequest{
		Username: user, Connection: "default", Scope: "product", SkillId: "product-define",
	})
	if err != nil {
		t.Fatalf("SetTrackerRoute: %v", err)
	}
	if setResp.GetRoute().GetSkillId() != "product-define" || setResp.GetRoute().GetScope() != "product" {
		t.Fatalf("SetTrackerRoute route = %+v, want scope=product skill=product-define", setResp.GetRoute())
	}
	if setResp.GetMessage() != "route created" {
		t.Errorf("SetTrackerRoute message = %q, want %q", setResp.GetMessage(), "route created")
	}

	// Repoint — idempotent upsert reports an update.
	setResp, err = s.SetTrackerRoute(admin, &pb.SetTrackerRouteRequest{
		Username: user, Connection: "default", Scope: "product", SkillId: "product-define-v2",
	})
	if err != nil {
		t.Fatalf("SetTrackerRoute (update): %v", err)
	}
	if setResp.GetMessage() != "route updated" {
		t.Errorf("SetTrackerRoute (update) message = %q, want %q", setResp.GetMessage(), "route updated")
	}

	listResp, err := s.ListTrackerRoutes(admin, &pb.ListTrackerRoutesRequest{Username: user, Connection: "default"})
	if err != nil {
		t.Fatalf("ListTrackerRoutes: %v", err)
	}
	if len(listResp.GetRoutes()) != 1 {
		t.Fatalf("ListTrackerRoutes = %+v, want one route", listResp.GetRoutes())
	}
	r := listResp.GetRoutes()[0]
	if r.GetUsername() != user || r.GetConnection() != "default" || r.GetScope() != "product" || r.GetSkillId() != "product-define-v2" {
		t.Errorf("ListTrackerRoutes[0] = %+v, want the repointed product route", r)
	}

	if _, err := s.DeleteTrackerRoute(admin, &pb.DeleteTrackerRouteRequest{Username: user, Connection: "default", Scope: "product"}); err != nil {
		t.Fatalf("DeleteTrackerRoute: %v", err)
	}
	if _, err := s.DeleteTrackerRoute(admin, &pb.DeleteTrackerRouteRequest{Username: user, Connection: "default", Scope: "product"}); status.Code(err) != codes.NotFound {
		t.Fatalf("DeleteTrackerRoute (gone) code = %v, want NotFound", status.Code(err))
	}
}

func TestSetTrackerRoute_ValidationAndMissingConnection(t *testing.T) {
	store := mustTestTrackerStore(t)
	s := &ContainerServer{trackerStore: store}
	const user = "tracker-route-rpc-validate"
	ctx := context.Background()
	_ = store.Delete(ctx, user, "default")
	_ = store.Delete(ctx, user, "missing")
	if _, err := store.Set(ctx, tracker.Connection{
		Username: user, Name: "default", Provider: pb.TrackerProvider_TRACKER_PROVIDER_GITHUB,
		Project: "acme/widgets", CredentialSecret: "GH_TOKEN",
	}); err != nil {
		t.Fatalf("seed connection: %v", err)
	}
	admin := kmsKeyTestCtx(user, "member", "tracker:admin")

	tests := []struct {
		name string
		req  *pb.SetTrackerRouteRequest
		want codes.Code
	}{
		{"missing skill", &pb.SetTrackerRouteRequest{Username: user, Connection: "default", Scope: "product"}, codes.InvalidArgument},
		{"prefixed scope", &pb.SetTrackerRouteRequest{Username: user, Connection: "default", Scope: "scope:product", SkillId: "s"}, codes.InvalidArgument},
		{"empty scope", &pb.SetTrackerRouteRequest{Username: user, Connection: "default", SkillId: "s"}, codes.InvalidArgument},
		{"unknown connection", &pb.SetTrackerRouteRequest{Username: user, Connection: "missing", Scope: "product", SkillId: "s"}, codes.NotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := s.SetTrackerRoute(admin, tt.req)
			if status.Code(err) != tt.want {
				t.Fatalf("code = %v (%v), want %v", status.Code(err), err, tt.want)
			}
		})
	}
}
