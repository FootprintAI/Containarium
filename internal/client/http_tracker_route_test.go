package client

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Scope-route REST calls (#2021) — method + path must match the
// google.api.http mapping on TrackerService in tracker.proto.

func TestTrackerRoutes_HTTPPathsAndDecoding(t *testing.T) {
	var gotMethod, gotPath string
	var respBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.EscapedPath()
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, respBody)
	}))
	defer srv.Close()

	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}

	respBody = `{"message":"route created","route":{"username":"alice","connection":"a/b","scope":"product","skillId":"product-define"}}`
	route, msg, err := c.SetTrackerRoute(&pb.SetTrackerRouteRequest{Username: "alice", Connection: "a/b", Scope: "product", SkillId: "product-define"})
	if err != nil {
		t.Fatalf("SetTrackerRoute: %v", err)
	}
	if gotMethod != http.MethodPut || gotPath != "/v1/tracker/alice/a%2Fb/routes/product" {
		t.Errorf("SetTrackerRoute %s %s, want PUT /v1/tracker/alice/a%%2Fb/routes/product", gotMethod, gotPath)
	}
	if msg != "route created" || route.GetSkillId() != "product-define" {
		t.Errorf("SetTrackerRoute = %+v %q", route, msg)
	}

	respBody = `{"routes":[{"username":"alice","connection":"default","scope":"product","skillId":"product-define"},{"username":"alice","connection":"default","scope":"qa","skillId":"qa-e2e-test"}]}`
	routes, err := c.ListTrackerRoutes("alice", "default")
	if err != nil {
		t.Fatalf("ListTrackerRoutes: %v", err)
	}
	if gotMethod != http.MethodGet || gotPath != "/v1/tracker/alice/default/routes" {
		t.Errorf("ListTrackerRoutes %s %s, want GET /v1/tracker/alice/default/routes", gotMethod, gotPath)
	}
	if len(routes) != 2 || routes[1].GetScope() != "qa" || routes[1].GetSkillId() != "qa-e2e-test" {
		t.Errorf("ListTrackerRoutes = %+v", routes)
	}

	respBody = `{"message":"route product deleted"}`
	msg, err = c.DeleteTrackerRoute(&pb.DeleteTrackerRouteRequest{Username: "alice", Connection: "default", Scope: "product"})
	if err != nil {
		t.Fatalf("DeleteTrackerRoute: %v", err)
	}
	if gotMethod != http.MethodDelete || gotPath != "/v1/tracker/alice/default/routes/product" {
		t.Errorf("DeleteTrackerRoute %s %s, want DELETE /v1/tracker/alice/default/routes/product", gotMethod, gotPath)
	}
	if msg != "route product deleted" {
		t.Errorf("DeleteTrackerRoute msg = %q", msg)
	}
}
