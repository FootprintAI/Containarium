package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/footprintai/containarium/internal/gateway"
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

// fakeBootstrapServer answers ApplyBoxBootstrap with err.
type fakeBootstrapServer struct {
	pb.UnimplementedContainerServiceServer
	err error
}

func (f *fakeBootstrapServer) ApplyBoxBootstrap(context.Context, *pb.ApplyBoxBootstrapRequest) (*pb.ApplyBoxBootstrapResponse, error) {
	return nil, f.err
}

// startBootstrapGateway serves the daemon's REST shape: the generated
// handlers on a runtime.ServeMux with the daemon's own gateway.ErrorHandler.
// A nil fake registers no ContainerService route at all: a daemon that
// predates ApplyBoxBootstrap, whose mux answers with its own 404.
func startBootstrapGateway(t *testing.T, fake *fakeBootstrapServer) *HTTPClient {
	t.Helper()
	mux := runtime.NewServeMux(runtime.WithErrorHandler(gateway.ErrorHandler))
	if fake != nil {
		if err := pb.RegisterContainerServiceHandlerServer(context.Background(), mux, fake); err != nil {
			t.Fatal(err)
		}
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func typedBootstrapErr(code codes.Code, reason pb.BoxBootstrapFailure, exit string, msg string) error {
	info := &errdetails.ErrorInfo{Reason: reason.String(), Domain: "containarium.v1"}
	if exit != "" {
		info.Metadata = map[string]string{"exit_code": exit}
	}
	st, _ := status.New(code, msg).WithDetails(info)
	return st.Err()
}

func TestHTTPApplyBoxBootstrap_ErrorsThroughTheDaemonGateway(t *testing.T) {
	req := &pb.ApplyBoxBootstrapRequest{Name: "alice", BootstrapUrl: "https://bundles.example.com/b/secret-token"}

	t.Run("old daemon without the route is Unimplemented", func(t *testing.T) {
		_, err := startBootstrapGateway(t, nil).ApplyBoxBootstrap(req)
		if status.Code(err) != codes.Unimplemented {
			t.Fatalf("err = %v, want Unimplemented", err)
		}
	})
	t.Run("unknown box keeps NotFound", func(t *testing.T) {
		c := startBootstrapGateway(t, &fakeBootstrapServer{err: status.Error(codes.NotFound, `no box for "alice"`)})
		_, err := c.ApplyBoxBootstrap(req)
		if status.Code(err) != codes.NotFound {
			t.Fatalf("err = %v, want NotFound", err)
		}
	})
	t.Run("stopped box keeps FailedPrecondition and its reason", func(t *testing.T) {
		c := startBootstrapGateway(t, &fakeBootstrapServer{err: typedBootstrapErr(codes.FailedPrecondition,
			pb.BoxBootstrapFailure_BOX_BOOTSTRAP_FAILURE_BOX_NOT_RUNNING, "", `"alice" is not running`)})
		_, err := c.ApplyBoxBootstrap(req)
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("err = %v, want FailedPrecondition", err)
		}
		if reason, _ := BootstrapFailureOf(err); reason != pb.BoxBootstrapFailure_BOX_BOOTSTRAP_FAILURE_BOX_NOT_RUNNING {
			t.Errorf("reason = %v, want BOX_NOT_RUNNING", reason)
		}
	})
	t.Run("bundle failure keeps reason and exit code", func(t *testing.T) {
		c := startBootstrapGateway(t, &fakeBootstrapServer{err: typedBootstrapErr(codes.FailedPrecondition,
			pb.BoxBootstrapFailure_BOX_BOOTSTRAP_FAILURE_BUNDLE_INVALID, "4", "not a .tar.gz with an apply.sh")})
		_, err := c.ApplyBoxBootstrap(req)
		reason, exit := BootstrapFailureOf(err)
		if status.Code(err) != codes.FailedPrecondition || reason != pb.BoxBootstrapFailure_BOX_BOOTSTRAP_FAILURE_BUNDLE_INVALID || exit != 4 {
			t.Errorf("err = %v: %v, %d; want FailedPrecondition BUNDLE_INVALID 4", err, reason, exit)
		}
		if strings.Contains(err.Error(), "secret-token") {
			t.Errorf("the client's error carries the URL: %v", err)
		}
	})
	t.Run("apply in progress keeps Aborted", func(t *testing.T) {
		c := startBootstrapGateway(t, &fakeBootstrapServer{err: typedBootstrapErr(codes.Aborted,
			pb.BoxBootstrapFailure_BOX_BOOTSTRAP_FAILURE_APPLY_IN_PROGRESS, "", "another apply")})
		_, err := c.ApplyBoxBootstrap(req)
		if reason, _ := BootstrapFailureOf(err); status.Code(err) != codes.Aborted || reason != pb.BoxBootstrapFailure_BOX_BOOTSTRAP_FAILURE_APPLY_IN_PROGRESS {
			t.Errorf("err = %v, want Aborted APPLY_IN_PROGRESS", err)
		}
	})
	t.Run("outcome unknown keeps Unknown and its reason", func(t *testing.T) {
		c := startBootstrapGateway(t, &fakeBootstrapServer{err: typedBootstrapErr(codes.Unknown,
			pb.BoxBootstrapFailure_BOX_BOOTSTRAP_FAILURE_OUTCOME_UNKNOWN, "", "the exec into the box failed")})
		_, err := c.ApplyBoxBootstrap(req)
		if reason, _ := BootstrapFailureOf(err); status.Code(err) != codes.Unknown || reason != pb.BoxBootstrapFailure_BOX_BOOTSTRAP_FAILURE_OUTCOME_UNKNOWN {
			t.Errorf("err = %v (reason %v), want Unknown OUTCOME_UNKNOWN", err, reason)
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
