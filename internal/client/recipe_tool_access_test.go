package client

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3679: both typed clients carry DeployRecipeOptions.ToolAccess as the
// request's tool_access, and return the deploy's workspace_path; without a
// level the HTTP body has no tool_access.

func TestHTTPDeployRecipe_ToolAccessAndWorkspacePath(t *testing.T) {
	var bodies []string
	var decoded []*pb.DeployRecipeRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		req := &pb.DeployRecipeRequest{}
		if err := protojson.Unmarshal(b, req); err != nil {
			t.Errorf("body %s is not a DeployRecipeRequest: %v", b, err)
		}
		bodies = append(bodies, string(b))
		decoded = append(decoded, req)
		_, _ = w.Write([]byte(`{"message":"ok","workspacePath":"/home/ctn-run/slides"}`))
	}))
	defer srv.Close()
	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.DeployRecipe("slides-agent", "alice", DeployRecipeOptions{ToolAccess: pb.BoxToolAccess_BOX_TOOL_ACCESS_BUILD_TOOLS})
	if err != nil {
		t.Fatal(err)
	}
	if got := resp.GetWorkspacePath(); got != "/home/ctn-run/slides" {
		t.Errorf("workspace_path = %q, want /home/ctn-run/slides", got)
	}
	if _, err := c.DeployRecipe("slides-agent", "alice", DeployRecipeOptions{}); err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 {
		t.Fatalf("got %d requests", len(decoded))
	}
	if got := decoded[0].GetToolAccess(); got != pb.BoxToolAccess_BOX_TOOL_ACCESS_BUILD_TOOLS {
		t.Errorf("server decoded tool_access %v, want BUILD_TOOLS", got)
	}
	if strings.Contains(bodies[1], "tool_access") {
		t.Errorf("a deploy without a level sent tool_access: %s", bodies[1])
	}
}

func TestGRPCDeployRecipe_SendsToolAccess(t *testing.T) {
	fixture := &recipeGRPCFixture{}
	listener := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	pb.RegisterRecipeServiceServer(srv, fixture)
	go func() { _ = srv.Serve(listener) }()
	defer srv.Stop()
	conn, err := grpc.NewClient("passthrough:///fixture", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	c := &GRPCClient{conn: conn, recipeClient: pb.NewRecipeServiceClient(conn)}
	defer func() { _ = c.Close() }()

	if _, err := c.DeployRecipe("slides-agent", "alice", DeployRecipeOptions{ToolAccess: pb.BoxToolAccess_BOX_TOOL_ACCESS_FULL_SUDO}); err != nil {
		t.Fatal(err)
	}
	if got := fixture.received.GetToolAccess(); got != pb.BoxToolAccess_BOX_TOOL_ACCESS_FULL_SUDO {
		t.Errorf("server received tool_access %v, want FULL_SUDO", got)
	}
}
