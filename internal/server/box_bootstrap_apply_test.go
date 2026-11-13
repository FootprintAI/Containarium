package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/coderun"
	"github.com/footprintai/containarium/pkg/core/box"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// bootstrapSecretPath is the part of the bundle URL a leak would show: a
// single-use token in the path, the shape a control plane hands out.
const bootstrapSecretPath = "/b/one-shot-token-d1f00dcafe"

// fixtureBundle is a .tar.gz with the given files (name -> content); apply.sh
// is made executable by the bundle script itself.
func fixtureBundle(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// serveBundle serves bundle at bootstrapSecretPath and 410 elsewhere; it
// returns the full URL.
func serveBundle(t *testing.T, bundle []byte) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != bootstrapSecretPath {
			w.WriteHeader(http.StatusGone)
			return
		}
		_, _ = w.Write(bundle)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + bootstrapSecretPath
}

// bootstrapExecCall is one call of the fake box exec.
type bootstrapExecCall struct{ box, user string }

// bootstrapServer is a ContainerServer whose one box ("alice", in state)
// runs bundle scripts with sh and HOME=home, recording which box and user
// each ran as. curl and tar must be on the test host.
func bootstrapServer(t *testing.T, home string, state pb.ContainerState) (*ContainerServer, *[]bootstrapExecCall) {
	t.Helper()
	for _, tool := range []string{"sh", "curl", "tar"} {
		if _, err := osexec.LookPath(tool); err != nil {
			t.Skipf("%s not on PATH", tool)
		}
	}
	var mu sync.Mutex
	var calls []bootstrapExecCall
	s := &ContainerServer{}
	s.boxBootstrapExec = func(boxName, user, script string) (string, string, int, error) {
		mu.Lock()
		calls = append(calls, bootstrapExecCall{boxName, user})
		mu.Unlock()
		cmd := osexec.Command("sh", "-c", script)
		cmd.Env = append(os.Environ(), "HOME="+home)
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		err := cmd.Run()
		var ee *osexec.ExitError
		if errors.As(err, &ee) {
			return out.String(), errb.String(), ee.ExitCode(), nil
		}
		return out.String(), errb.String(), 0, err
	}
	s.runCheckoutBoxes = func(context.Context) ([]box.BoxStatus, error) {
		return []box.BoxStatus{{Ref: box.BoxRef{Tenant: "alice", Name: "alice-container"}, State: state}}, nil
	}
	return s, &calls
}

// bootstrapFailureOf returns the typed reason and exit_code of err's ErrorInfo.
func bootstrapFailureOf(t *testing.T, err error) (pb.BoxBootstrapFailure, string) {
	t.Helper()
	st, _ := status.FromError(err)
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok {
			return pb.BoxBootstrapFailure(pb.BoxBootstrapFailure_value[info.GetReason()]), info.GetMetadata()["exit_code"]
		}
	}
	t.Fatalf("no ErrorInfo in %v", err)
	return 0, ""
}

const fixtureApply = `#!/bin/sh
set -e
mkdir -p "$HOME/.config/containarium" "$HOME/.claude"
cp manifest.json "$HOME/.config/containarium/manifest.json"
echo '{"mcpServers":{}}' > "$HOME/.claude/containarium-mcp.json"
echo applied
`

// Acceptance 1: applying a fixture bundle in a throwaway home writes the
// expected files as the box user and returns the revision.
func TestApplyBoxBootstrap_AppliesBundleAsBoxUserAndReturnsRevision(t *testing.T) {
	home := t.TempDir()
	s, calls := bootstrapServer(t, home, pb.ContainerState_CONTAINER_STATE_RUNNING)
	url := serveBundle(t, fixtureBundle(t, map[string]string{
		"apply.sh":      fixtureApply,
		"manifest.json": `{"bundle_version":1,"bundle_revision":11}`,
	}))

	resp, err := s.ApplyBoxBootstrap(tenantCtx("alice"), &pb.ApplyBoxBootstrapRequest{Name: "alice", BootstrapUrl: url})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetBundleRevision() != 11 || !resp.GetManifestFound() {
		t.Fatalf("response = %v, want bundle_revision 11 with the manifest found", resp)
	}
	for _, rel := range []string{".config/containarium/manifest.json", ".claude/containarium-mcp.json"} {
		if _, err := os.Stat(filepath.Join(home, rel)); err != nil {
			t.Errorf("bundle did not write %s: %v", rel, err)
		}
	}
	if len(*calls) == 0 {
		t.Fatal("no script ran in the box")
	}
	for _, c := range *calls {
		if c.box != "alice-container" || c.user != "alice" {
			t.Errorf("ran in %q as %q, want alice-container as the box user alice", c.box, c.user)
		}
	}
}

func TestApplyBoxBootstrap_RunsAsTheRequestedBoxUser(t *testing.T) {
	home := t.TempDir()
	s, calls := bootstrapServer(t, home, pb.ContainerState_CONTAINER_STATE_RUNNING)
	url := serveBundle(t, fixtureBundle(t, map[string]string{"apply.sh": "#!/bin/sh\ntrue\n"}))

	resp, err := s.ApplyBoxBootstrap(tenantCtx("alice"), &pb.ApplyBoxBootstrapRequest{Name: "alice", BootstrapUrl: url, BoxUser: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetManifestFound() || resp.GetBundleRevision() != 0 {
		t.Errorf("a bundle with no manifest.json reported %v", resp)
	}
	for _, c := range *calls {
		if c.user != "dev" {
			t.Errorf("ran as %q, want the requested box user dev", c.user)
		}
	}
}

// The bundle is the box user's content: never root, and never the
// unprivileged run user, which cannot write the box user's home.
func TestApplyBoxBootstrap_RefusesPrivilegedOrRunUser(t *testing.T) {
	s, calls := bootstrapServer(t, t.TempDir(), pb.ContainerState_CONTAINER_STATE_RUNNING)
	for _, user := range []string{"root", boxRunUnprivilegedUser, "bad user", "../x"} {
		_, err := s.ApplyBoxBootstrap(tenantCtx("alice"), &pb.ApplyBoxBootstrapRequest{Name: "alice", BootstrapUrl: "https://example.com/b.tgz", BoxUser: user})
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("box_user %q: err = %v, want InvalidArgument", user, err)
		}
	}
	if len(*calls) != 0 {
		t.Errorf("a refused call ran in the box: %v", *calls)
	}
}

func TestApplyBoxBootstrap_RequiresAnHTTPURL(t *testing.T) {
	s, _ := bootstrapServer(t, t.TempDir(), pb.ContainerState_CONTAINER_STATE_RUNNING)
	for _, u := range []string{"", "   ", "file:///etc/passwd", "-o/tmp/x"} {
		_, err := s.ApplyBoxBootstrap(tenantCtx("alice"), &pb.ApplyBoxBootstrapRequest{Name: "alice", BootstrapUrl: u})
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("url %q: err = %v, want InvalidArgument", u, err)
		}
		if u != "" && strings.TrimSpace(u) != "" && strings.Contains(err.Error(), u) {
			t.Errorf("url %q echoed in error %q", u, err)
		}
	}
}

// Acceptance 3: a bundle with no apply script is refused with the existing
// exit code (the one `code install --bootstrap-url` uses).
func TestApplyBoxBootstrap_BundleWithoutApplyScriptKeepsTheExitCode(t *testing.T) {
	s, _ := bootstrapServer(t, t.TempDir(), pb.ContainerState_CONTAINER_STATE_RUNNING)
	url := serveBundle(t, fixtureBundle(t, map[string]string{"README": "no apply script here\n"}))

	_, err := s.ApplyBoxBootstrap(tenantCtx("alice"), &pb.ApplyBoxBootstrapRequest{Name: "alice", BootstrapUrl: url})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want FailedPrecondition", err)
	}
	reason, code := bootstrapFailureOf(t, err)
	if reason != pb.BoxBootstrapFailure_BOX_BOOTSTRAP_FAILURE_BUNDLE_INVALID {
		t.Errorf("reason = %v, want BUNDLE_INVALID", reason)
	}
	if code != strconv.Itoa(coderun.BootstrapExitBundle) || coderun.BootstrapExitBundle != 4 {
		t.Errorf("exit_code = %q, want %d (code install's)", code, coderun.BootstrapExitBundle)
	}
}

func TestApplyBoxBootstrap_TypedFailuresOfTheBundleStep(t *testing.T) {
	cases := []struct {
		name   string
		url    func(t *testing.T) string
		code   codes.Code
		reason pb.BoxBootstrapFailure
		exit   int
	}{
		{"apply.sh fails", func(t *testing.T) string {
			return serveBundle(t, fixtureBundle(t, map[string]string{"apply.sh": "#!/bin/sh\necho boom >&2\nexit 7\n"}))
		}, codes.FailedPrecondition, pb.BoxBootstrapFailure_BOX_BOOTSTRAP_FAILURE_APPLY_FAILED, coderun.BootstrapExitApply},
		{"server answers 410", func(t *testing.T) string {
			u := serveBundle(t, nil)
			return strings.TrimSuffix(u, bootstrapSecretPath) + bootstrapSecretPath + "-spent"
		}, codes.FailedPrecondition, pb.BoxBootstrapFailure_BOX_BOOTSTRAP_FAILURE_FETCH_FAILED, coderun.BootstrapExitFetchReached},
		{"server unreachable", func(t *testing.T) string {
			srv := httptest.NewServer(http.NotFoundHandler())
			u := srv.URL
			srv.Close()
			return u + bootstrapSecretPath
		}, codes.Unavailable, pb.BoxBootstrapFailure_BOX_BOOTSTRAP_FAILURE_FETCH_UNREACHED, coderun.BootstrapExitFetch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := bootstrapServer(t, t.TempDir(), pb.ContainerState_CONTAINER_STATE_RUNNING)
			_, err := s.ApplyBoxBootstrap(tenantCtx("alice"), &pb.ApplyBoxBootstrapRequest{Name: "alice", BootstrapUrl: tc.url(t)})
			if status.Code(err) != tc.code {
				t.Fatalf("err = %v, want %v", err, tc.code)
			}
			reason, exit := bootstrapFailureOf(t, err)
			if reason != tc.reason || exit != strconv.Itoa(tc.exit) {
				t.Errorf("reason = %v exit_code = %q, want %v %d", reason, exit, tc.reason, tc.exit)
			}
		})
	}
}

// Acceptance 2: the URL appears in no log line or error, whatever the
// outcome — including a transport error that echoes the command it ran, and
// an apply.sh that prints its environment.
func TestApplyBoxBootstrap_URLNeverInLogsOrErrors(t *testing.T) {
	type outcome struct {
		name string
		run  func(t *testing.T) error
	}
	outcomes := []outcome{
		{"success", func(t *testing.T) error {
			s, _ := bootstrapServer(t, t.TempDir(), pb.ContainerState_CONTAINER_STATE_RUNNING)
			url := serveBundle(t, fixtureBundle(t, map[string]string{"apply.sh": fixtureApply, "manifest.json": `{"bundle_revision":3}`}))
			_, err := s.ApplyBoxBootstrap(tenantCtx("alice"), &pb.ApplyBoxBootstrapRequest{Name: "alice", BootstrapUrl: url})
			return err
		}},
		{"apply.sh fails loudly", func(t *testing.T) error {
			s, _ := bootstrapServer(t, t.TempDir(), pb.ContainerState_CONTAINER_STATE_RUNNING)
			url := serveBundle(t, fixtureBundle(t, map[string]string{"apply.sh": "#!/bin/sh\nps -o args= -p $PPID >&2; cat /proc/$PPID/cmdline >&2; exit 1\n"}))
			_, err := s.ApplyBoxBootstrap(tenantCtx("alice"), &pb.ApplyBoxBootstrapRequest{Name: "alice", BootstrapUrl: url})
			return err
		}},
		{"no apply script", func(t *testing.T) error {
			s, _ := bootstrapServer(t, t.TempDir(), pb.ContainerState_CONTAINER_STATE_RUNNING)
			url := serveBundle(t, fixtureBundle(t, map[string]string{"x": "y"}))
			_, err := s.ApplyBoxBootstrap(tenantCtx("alice"), &pb.ApplyBoxBootstrapRequest{Name: "alice", BootstrapUrl: url})
			return err
		}},
		{"transport error echoes the script", func(t *testing.T) error {
			s, _ := bootstrapServer(t, t.TempDir(), pb.ContainerState_CONTAINER_STATE_RUNNING)
			s.boxBootstrapExec = func(_, _, script string) (string, string, int, error) {
				return "", "stderr: " + script, -1, errors.New("exec failed running: " + script)
			}
			_, err := s.ApplyBoxBootstrap(tenantCtx("alice"), &pb.ApplyBoxBootstrapRequest{Name: "alice", BootstrapUrl: "https://bundles.example.com" + bootstrapSecretPath})
			return err
		}},
		{"unexpected exit code with the script in stderr", func(t *testing.T) error {
			s, _ := bootstrapServer(t, t.TempDir(), pb.ContainerState_CONTAINER_STATE_RUNNING)
			s.boxBootstrapExec = func(_, _, script string) (string, string, int, error) {
				return "", "su: " + script, 1, nil
			}
			_, err := s.ApplyBoxBootstrap(tenantCtx("alice"), &pb.ApplyBoxBootstrapRequest{Name: "alice", BootstrapUrl: "https://bundles.example.com" + bootstrapSecretPath})
			return err
		}},
	}
	logs := captureLog(t, func() {
		for _, o := range outcomes {
			t.Run(o.name, func(t *testing.T) {
				err := o.run(t)
				if err != nil && strings.Contains(err.Error(), bootstrapSecretPath) {
					t.Errorf("error leaks the URL: %v", err)
				}
			})
		}
	})
	if strings.Contains(logs, bootstrapSecretPath) {
		t.Errorf("a log line leaks the URL:\n%s", logs)
	}
	if !strings.Contains(logs, "[bootstrap]") {
		t.Errorf("expected the daemon to log the applies (without the URL); got:\n%s", logs)
	}
}

// Acceptance 4: an unknown box returns not found; a stopped box returns a
// typed precondition error. Neither touches the box.
func TestApplyBoxBootstrap_UnknownAndStoppedBoxes(t *testing.T) {
	s, calls := bootstrapServer(t, t.TempDir(), pb.ContainerState_CONTAINER_STATE_STOPPED)
	_, err := s.ApplyBoxBootstrap(tenantCtx("carol"), &pb.ApplyBoxBootstrapRequest{Name: "carol", BootstrapUrl: "https://example.com/b.tgz"})
	if status.Code(err) != codes.NotFound {
		t.Errorf("unknown box: err = %v, want NotFound", err)
	}
	_, err = s.ApplyBoxBootstrap(tenantCtx("alice"), &pb.ApplyBoxBootstrapRequest{Name: "alice", BootstrapUrl: "https://example.com/b.tgz"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("stopped box: err = %v, want FailedPrecondition", err)
	}
	if reason, _ := bootstrapFailureOf(t, err); reason != pb.BoxBootstrapFailure_BOX_BOOTSTRAP_FAILURE_BOX_NOT_RUNNING {
		t.Errorf("stopped box: reason = %v, want BOX_NOT_RUNNING", reason)
	}
	if len(*calls) != 0 {
		t.Errorf("an unknown or stopped box was touched: %v", *calls)
	}
}

func TestApplyBoxBootstrap_OtherTenantIsDenied(t *testing.T) {
	s, calls := bootstrapServer(t, t.TempDir(), pb.ContainerState_CONTAINER_STATE_RUNNING)
	_, err := s.ApplyBoxBootstrap(tenantCtx("mallory"), &pb.ApplyBoxBootstrapRequest{Name: "alice", BootstrapUrl: "https://example.com/b.tgz"})
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("err = %v, want PermissionDenied", err)
	}
	if len(*calls) != 0 {
		t.Errorf("a denied call touched the box: %v", *calls)
	}
}

// Callers detect support through GetSystemInfo's capabilities.
func TestApplyBoxBootstrap_IsAdvertisedAsACapability(t *testing.T) {
	for _, c := range daemonCapabilities() {
		if c == DaemonCapBoxBootstrap {
			return
		}
	}
	t.Errorf("capabilities %v do not list %q", daemonCapabilities(), DaemonCapBoxBootstrap)
}
