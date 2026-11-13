package client

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestHTTPApplyBoxBootstrap(t *testing.T) {
	var gotPath, gotMethod, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		_, _ = w.Write([]byte(`{"bundleRevision":11,"manifestFound":true,"futureField":1}`))
	}))
	defer srv.Close()
	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.ApplyBoxBootstrap(&pb.ApplyBoxBootstrapRequest{Name: "alice", BootstrapUrl: "https://bundles.example.com/b/x", BoxUser: "dev"})
	if err != nil {
		t.Fatalf("ApplyBoxBootstrap: %v", err)
	}
	var sent pb.ApplyBoxBootstrapRequest
	if err := protojson.Unmarshal([]byte(gotBody), &sent); err != nil {
		t.Fatalf("request body %q: %v", gotBody, err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/containers/alice/bootstrap:apply" ||
		sent.GetBootstrapUrl() != "https://bundles.example.com/b/x" || sent.GetBoxUser() != "dev" {
		t.Errorf("request = %s %s %s", gotMethod, gotPath, gotBody)
	}
	if got.GetBundleRevision() != 11 || !got.GetManifestFound() {
		t.Errorf("decoded = %v", got)
	}
}

func TestHTTPApplyBoxBootstrap_Errors(t *testing.T) {
	serve := func(code int, body string) *HTTPClient {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(srv.Close)
		c, err := NewHTTPClient(srv.URL, "tok")
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	req := &pb.ApplyBoxBootstrapRequest{Name: "alice", BootstrapUrl: "https://bundles.example.com/b/secret-token"}

	t.Run("old daemon without the route is Unimplemented", func(t *testing.T) {
		_, err := serve(http.StatusNotFound, "404 page not found\n").ApplyBoxBootstrap(req)
		if status.Code(err) != codes.Unimplemented {
			t.Fatalf("err = %v, want Unimplemented", err)
		}
	})
	t.Run("no such box keeps NotFound", func(t *testing.T) {
		_, err := serve(http.StatusNotFound, `{"code":5,"message":"no box for \"alice\""}`).ApplyBoxBootstrap(req)
		if status.Code(err) != codes.NotFound {
			t.Fatalf("err = %v, want NotFound", err)
		}
	})
	t.Run("typed failure keeps reason and exit code", func(t *testing.T) {
		st, _ := status.New(codes.FailedPrecondition, "not a .tar.gz with an apply.sh").WithDetails(&errdetails.ErrorInfo{
			Reason: pb.BoxBootstrapFailure_BOX_BOOTSTRAP_FAILURE_BUNDLE_INVALID.String(), Domain: "containarium.v1",
			Metadata: map[string]string{"exit_code": "4"},
		})
		body, err := protojson.Marshal(st.Proto())
		if err != nil {
			t.Fatal(err)
		}
		_, err = serve(http.StatusBadRequest, string(body)).ApplyBoxBootstrap(req)
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("err = %v, want FailedPrecondition", err)
		}
		reason, exit := BootstrapFailureOf(err)
		if reason != pb.BoxBootstrapFailure_BOX_BOOTSTRAP_FAILURE_BUNDLE_INVALID || exit != 4 {
			t.Errorf("BootstrapFailureOf = %v, %d; want BUNDLE_INVALID, 4", reason, exit)
		}
		if strings.Contains(err.Error(), "secret-token") {
			t.Errorf("the client's error carries the URL: %v", err)
		}
	})
	t.Run("transport error never carries the URL", func(t *testing.T) {
		c, _ := NewHTTPClient("http://127.0.0.1:1", "tok")
		_, err := c.ApplyBoxBootstrap(req)
		if err == nil || strings.Contains(err.Error(), "secret-token") {
			t.Errorf("err = %v", err)
		}
	})
}

func TestBootstrapFailureOf_Untyped(t *testing.T) {
	if r, code := BootstrapFailureOf(errors.New("x")); r != pb.BoxBootstrapFailure_BOX_BOOTSTRAP_FAILURE_UNSPECIFIED || code != 0 {
		t.Errorf("untyped error = %v, %d", r, code)
	}
}
