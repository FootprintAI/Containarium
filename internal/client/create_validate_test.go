package client

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func validateTestRequest() *pb.CreateContainerRequest {
	return &pb.CreateContainerRequest{Username: "alice", Stack: "nodejs"}
}

// fakeCreateClient answers CreateContainer only; any other method on the
// embedded nil interface would panic, which is the point: a validation must
// not call anything else.
type fakeCreateClient struct {
	pb.ContainerServiceClient
	got  *pb.CreateContainerRequest
	resp *pb.CreateContainerResponse
	err  error
}

func (f *fakeCreateClient) CreateContainer(_ context.Context, in *pb.CreateContainerRequest, _ ...grpc.CallOption) (*pb.CreateContainerResponse, error) {
	f.got = in
	return f.resp, f.err
}

// #2925: the request carries dry_run, the caller's request is not mutated, and
// only an answer that echoes dry_run counts as "accepted, nothing created".
func TestGRPCValidateCreate_SendsDryRunAndRequiresTheEcho(t *testing.T) {
	f := &fakeCreateClient{resp: &pb.CreateContainerResponse{DryRun: true}}
	c := &GRPCClient{client: f}
	req := validateTestRequest()

	if err := c.ValidateCreate(req); err != nil {
		t.Fatalf("ValidateCreate on an accepting daemon: %v", err)
	}
	if !f.got.GetDryRun() {
		t.Error("the daemon was not sent dry_run=true: this would have been a real create")
	}
	if req.GetDryRun() {
		t.Error("the caller's request was mutated")
	}
}

func TestGRPCValidateCreate_RejectionIsAnError(t *testing.T) {
	c := &GRPCClient{client: &fakeCreateClient{err: errors.New(`unknown stack "typo"`)}}
	err := c.ValidateCreate(validateTestRequest())
	if err == nil || !strings.Contains(err.Error(), `unknown stack "typo"`) {
		t.Fatalf("got %v, want the daemon's rejection", err)
	}
}

// A daemon that predates dry_run ignores it and really creates the box; that
// success must not be read as "validated".
func TestGRPCValidateCreate_NoEchoMeansTheDaemonDidNotValidate(t *testing.T) {
	c := &GRPCClient{client: &fakeCreateClient{resp: &pb.CreateContainerResponse{Container: &pb.Container{Name: "alice-container"}}}}
	err := c.ValidateCreate(validateTestRequest())
	if err == nil || !strings.Contains(err.Error(), "dry") {
		t.Fatalf("got %v, want an error saying the daemon did not honour the dry run", err)
	}
}

func TestHTTPValidateCreate_SendsDryRunAndRequiresTheEcho(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/containers" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		_, _ = w.Write([]byte(`{"dryRun":true,"message":"ok"}`))
	}))
	defer srv.Close()
	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.ValidateCreate(validateTestRequest()); err != nil {
		t.Fatalf("ValidateCreate: %v", err)
	}
	if body["dryRun"] != true || body["username"] != "alice" || body["stack"] != "nodejs" {
		t.Errorf("request body = %v, want dryRun=true plus the original fields", body)
	}
}

func TestHTTPValidateCreate_RejectionAndNoEcho(t *testing.T) {
	status, reply := http.StatusBadRequest, `{"error":"unknown stack \"typo\""}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(reply))
	}))
	defer srv.Close()
	c, _ := NewHTTPClient(srv.URL, "tok")

	if err := c.ValidateCreate(validateTestRequest()); err == nil || !strings.Contains(err.Error(), "unknown stack") {
		t.Fatalf("rejection: got %v", err)
	}
	status, reply = http.StatusOK, `{"container":{"name":"alice-container"}}`
	if err := c.ValidateCreate(validateTestRequest()); err == nil || !strings.Contains(err.Error(), "dry") {
		t.Fatalf("no echo: got %v, want an error saying the daemon did not honour the dry run", err)
	}
}
