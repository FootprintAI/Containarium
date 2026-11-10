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

// #3514: both typed clients carry DeployRecipeOptions.SSHKeys as the
// request's ssh_keys, in order; without keys the body has no ssh_keys.

func TestHTTPDeployRecipe_SendsSSHKeys(t *testing.T) {
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
		_, _ = w.Write([]byte(`{"message":"ok"}`))
	}))
	defer srv.Close()
	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{"ssh-ed25519 AAAA first", "ssh-ed25519 BBBB second"}
	if _, err := c.DeployRecipe("plain", "alice", DeployRecipeOptions{SSHKeys: keys}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DeployRecipe("plain", "alice", DeployRecipeOptions{}); err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 {
		t.Fatalf("got %d requests", len(decoded))
	}
	if got := decoded[0].GetSshKeys(); strings.Join(got, "|") != strings.Join(keys, "|") {
		t.Errorf("server decoded ssh_keys %q, want %q", got, keys)
	}
	if strings.Contains(bodies[1], "ssh_keys") {
		t.Errorf("a deploy without keys sent ssh_keys: %s", bodies[1])
	}
}

type recipeGRPCFixture struct {
	pb.UnimplementedRecipeServiceServer
	received *pb.DeployRecipeRequest
}

func (f *recipeGRPCFixture) DeployRecipe(_ context.Context, req *pb.DeployRecipeRequest) (*pb.DeployRecipeResponse, error) {
	f.received = req
	return &pb.DeployRecipeResponse{Message: "ok"}, nil
}

func TestGRPCDeployRecipe_SendsSSHKeys(t *testing.T) {
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

	keys := []string{"ssh-ed25519 AAAA first", "ssh-ed25519 BBBB second"}
	if _, err := c.DeployRecipe("plain", "alice", DeployRecipeOptions{GPU: "0", SSHKeys: keys}); err != nil {
		t.Fatal(err)
	}
	if got := fixture.received.GetSshKeys(); strings.Join(got, "|") != strings.Join(keys, "|") {
		t.Errorf("server received ssh_keys %q, want %q", got, keys)
	}
	if fixture.received.GetGpu() != "0" || fixture.received.GetRecipeId() != "plain" || fixture.received.GetName() != "alice" {
		t.Errorf("other fields lost: %v", fixture.received)
	}
}
