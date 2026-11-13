package cmd

import (
	"bytes"
	"strings"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// --- `containarium code bootstrap <box> --via-daemon` (#3694) -------------

const daemonBundleURL = "https://bundles.example.com/b/one-shot-token-0123"

type fakeBootstrapApplier struct {
	reqs []*pb.ApplyBoxBootstrapRequest
	resp *pb.ApplyBoxBootstrapResponse
	err  error
}

func (f *fakeBootstrapApplier) ApplyBoxBootstrap(req *pb.ApplyBoxBootstrapRequest) (*pb.ApplyBoxBootstrapResponse, error) {
	f.reqs = append(f.reqs, req)
	return f.resp, f.err
}

func TestCodeBootstrapViaDaemon_SendsTheRequestAndReportsTheRevision(t *testing.T) {
	f := &fakeBootstrapApplier{resp: &pb.ApplyBoxBootstrapResponse{BundleRevision: 11, ManifestFound: true}}
	var out bytes.Buffer
	if err := codeBootstrapViaDaemon(f, "alice", daemonBundleURL, "dev", &out); err != nil {
		t.Fatal(err)
	}
	if len(f.reqs) != 1 || f.reqs[0].GetName() != "alice" || f.reqs[0].GetBootstrapUrl() != daemonBundleURL || f.reqs[0].GetBoxUser() != "dev" {
		t.Fatalf("requests = %v", f.reqs)
	}
	if got := out.String(); !strings.Contains(got, "alice") || !strings.Contains(got, "revision 11") || strings.Contains(got, daemonBundleURL) {
		t.Errorf("output = %q", got)
	}
}

func TestCodeBootstrapViaDaemon_OldDaemonIsDetected(t *testing.T) {
	f := &fakeBootstrapApplier{err: status.Error(codes.Unimplemented, "unknown method")}
	err := codeBootstrapViaDaemon(f, "alice", daemonBundleURL, "", &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "does not support") || !strings.Contains(err.Error(), "without --via-daemon") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), daemonBundleURL) {
		t.Errorf("error leaks the URL: %v", err)
	}
}

func TestCodeBootstrapViaDaemon_TypedFailureNamesReasonAndExitCode(t *testing.T) {
	st, _ := status.New(codes.FailedPrecondition, "the bundle was fetched but it is not a .tar.gz with an apply.sh at its root").WithDetails(&errdetails.ErrorInfo{
		Reason: pb.BoxBootstrapFailure_BOX_BOOTSTRAP_FAILURE_BUNDLE_INVALID.String(), Metadata: map[string]string{"exit_code": "4"},
	})
	f := &fakeBootstrapApplier{err: st.Err()}
	err := codeBootstrapViaDaemon(f, "alice", daemonBundleURL, "", &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "BUNDLE_INVALID") || !strings.Contains(err.Error(), "exit 4") {
		t.Fatalf("err = %v", err)
	}
}

func TestCodeBootstrap_BoxUserNeedsViaDaemon(t *testing.T) {
	origVia, origUser := codeBootstrapFlagViaDaemon, codeBootstrapFlagBoxUser
	t.Cleanup(func() { codeBootstrapFlagViaDaemon, codeBootstrapFlagBoxUser = origVia, origUser })
	codeBootstrapFlagViaDaemon, codeBootstrapFlagBoxUser = false, "dev"
	_, err := runCodeBootstrapWith(t, "alice", daemonBundleURL, "", installFakes{}, "", nil)
	if err == nil || !strings.Contains(err.Error(), "--box-user") {
		t.Fatalf("err = %v, want a --box-user needs --via-daemon error", err)
	}
}
