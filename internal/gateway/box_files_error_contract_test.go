package gateway

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/client"
)

// #3548: the REST client's reading of a WriteBoxFile error must match what this
// gateway really sends. The daemon's ErrorHandler puts the HTTP status in
// "code" and the gRPC status in "error", so a client that read "code" as a gRPC
// code would lose every typed refusal, and a client that took any JSON 404 for
// a refusal would never see an old daemon.

func TestBoxFilesClient_ReadsTheDaemonsErrorBody(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want codes.Code
	}{
		{"checksum mismatch", status.Error(codes.DataLoss, "the bytes on the box do not match sha256 x; no file was written"), codes.DataLoss},
		{"escape path", status.Error(codes.InvalidArgument, "path must stay inside the home directory"), codes.InvalidArgument},
		{"directory at the path", status.Error(codes.FailedPrecondition, "a is a directory"), codes.FailedPrecondition},
		{"not the owner", status.Error(codes.PermissionDenied, "not the box's owner or a collaborator on it"), codes.PermissionDenied},
		{"no such box", status.Error(codes.NotFound, "container alice-container not found"), codes.NotFound},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ErrorHandler(r.Context(), NewRESTMux(), &runtime.JSONPb{}, w, r, c.err)
			}))
			defer srv.Close()
			hc, err := client.NewHTTPClient(srv.URL, "tok")
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.PutBoxFile(hc, client.BoxFileParams{Box: "alice", Path: "a", Content: []byte("x")})
			var refused *client.BoxFileRefusedError
			if !errors.As(err, &refused) || refused.Code != c.want || refused.Message != status.Convert(c.err).Message() {
				t.Fatalf("err = %v (%#v), want a %v refusal with the daemon's message", err, refused, c.want)
			}
		})
	}
}

// A daemon that predates the route answers from the mux's routing error: a 404
// the client must report as Unimplemented, not as a NOT_FOUND refusal.
func TestBoxFilesClient_AnOldDaemonIsUnimplemented(t *testing.T) {
	srv := httptest.NewServer(NewRESTMux()) // no routes registered
	defer srv.Close()
	hc, err := client.NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.PutBoxFile(hc, client.BoxFileParams{Box: "alice", Path: "a", Content: []byte("x")})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("err = %v, want Unimplemented", err)
	}
}
