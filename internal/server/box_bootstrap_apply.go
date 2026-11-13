package server

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/coderun"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Applying a bootstrap bundle to an existing box from the daemon (#3694).
// `containarium code install --bootstrap-url` and `code bootstrap` run the
// bundle step over SSH from a user's machine; ApplyBoxBootstrap runs the same
// script (coderun.BootstrapScript, plus a trailer that prints the applied
// bundle's manifest) inside the box as the box's own user, so a control plane
// that manages boxes can re-bootstrap one with no user machine in the loop.
//
// The bundle URL is a single-use credential. It is never logged, and every
// error this RPC returns has it replaced (redactBootstrapURL), whatever text
// the box or the exec transport sent back.

// DaemonCapBoxBootstrap: the ApplyBoxBootstrap RPC (#3694).
const DaemonCapBoxBootstrap = "box_bootstrap"

// boxBootstrapErrorDomain is the google.rpc.ErrorInfo domain of a typed
// ApplyBoxBootstrap failure.
const boxBootstrapErrorDomain = "containarium.v1"

// boxBootstrapRedacted replaces the URL wherever it would otherwise appear.
const boxBootstrapRedacted = "<bootstrap-url>"

// boxBootstrapExecFunc runs script in boxName as user and reports its exit
// code. err is a transport failure (the script's exit status is then unknown);
// a script that ran and failed is code != 0 with err == nil.
type boxBootstrapExecFunc func(boxName, user, script string) (stdout, stderr string, code int, err error)

// boxBootstrapMaxDetail caps the bytes of the script's stderr (the tail,
// where the failing step is) carried into an error.
const boxBootstrapMaxDetail = 2048

// boxUserPattern is a plain Linux login name: nothing in it is shell syntax.
var boxUserPattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// boxBootstrapExecFn returns the exec seam: the injected fake, else `su -
// <user> -c <script>` through the container manager, which keeps the exit code
// the bundle script's contract is built on.
func (s *ContainerServer) boxBootstrapExecFn() boxBootstrapExecFunc {
	if s.boxBootstrapExec != nil {
		return s.boxBootstrapExec
	}
	if s.manager == nil {
		return nil
	}
	mgr := s.manager
	return func(boxName, user, script string) (string, string, int, error) {
		wrapped := "su - " + shellSingleQuote(user) + " -c " + shellSingleQuote(script)
		return mgr.ExecWithExitCode(boxName, []string{"sh", "-c", wrapped})
	}
}

// redactBootstrapURL removes the URL from text, in its raw and its
// shell-quoted spelling (the script carries the latter).
func redactBootstrapURL(text, rawURL string) string {
	if rawURL == "" {
		return text
	}
	text = strings.ReplaceAll(text, coderun.ShellQuoteSingle(rawURL), boxBootstrapRedacted)
	return strings.ReplaceAll(text, rawURL, boxBootstrapRedacted)
}

// boxBootstrapFailure is a typed ApplyBoxBootstrap error: msg for people,
// reason (and the bundle script's exit code, when there is one) as a
// google.rpc.ErrorInfo for callers.
func boxBootstrapFailure(code codes.Code, reason pb.BoxBootstrapFailure, exitCode int, msg string) error {
	info := &errdetails.ErrorInfo{Reason: reason.String(), Domain: boxBootstrapErrorDomain}
	if exitCode > 0 {
		info.Metadata = map[string]string{"exit_code": strconv.Itoa(exitCode)}
	}
	st := status.New(code, msg)
	if detailed, err := st.WithDetails(info); err == nil {
		st = detailed
	}
	return st.Err()
}

// validBootstrapURL accepts an absolute http(s) URL with a host. The check
// never echoes the URL.
func validBootstrapURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	return u.Scheme == "https" || u.Scheme == "http"
}

// ApplyBoxBootstrap applies a bootstrap bundle to a running box (#3694).
func (s *ContainerServer) ApplyBoxBootstrap(ctx context.Context, req *pb.ApplyBoxBootstrapRequest) (*pb.ApplyBoxBootstrapResponse, error) {
	name := req.GetName()
	if err := validateBoxRunOwner(name); err != nil {
		return nil, err
	}
	if err := s.authorizeBoxRuns(ctx, name); err != nil {
		return nil, err
	}
	rawURL := strings.TrimSpace(req.GetBootstrapUrl())
	if rawURL == "" {
		return nil, status.Error(codes.InvalidArgument, "bootstrap_url is required")
	}
	if !validBootstrapURL(rawURL) {
		return nil, status.Error(codes.InvalidArgument, "bootstrap_url must be an absolute http or https URL")
	}
	user := strings.TrimSpace(req.GetBoxUser())
	if user == "" {
		user = name
	}
	switch {
	case !boxUserPattern.MatchString(user):
		return nil, status.Errorf(codes.InvalidArgument, "box_user %q is not a plain login name", user)
	case user == "root":
		return nil, status.Error(codes.InvalidArgument, "box_user must not be root: a bootstrap bundle gets the box user's own privileges")
	case user == boxRunUnprivilegedUser:
		return nil, status.Errorf(codes.InvalidArgument, "box_user must not be the unprivileged run user %q: it cannot write the box user's home", user)
	}

	exec := s.boxBootstrapExecFn()
	if exec == nil {
		return nil, status.Error(codes.Unavailable, "no container backend to apply a bootstrap bundle on")
	}
	info, err := s.runCheckoutGetBox(ctx, name)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "look up %q: %v", name, err)
	}
	if info == nil {
		return nil, status.Errorf(codes.NotFound, "no box for %q", name)
	}
	if info.State != pb.ContainerState_CONTAINER_STATE_RUNNING {
		return nil, boxBootstrapFailure(codes.FailedPrecondition, pb.BoxBootstrapFailure_BOX_BOOTSTRAP_FAILURE_BOX_NOT_RUNNING, 0,
			fmt.Sprintf("%q is not running; a bootstrap bundle is applied to a running box (nothing was fetched)", name))
	}
	boxName := name + "-container"
	if info.Ref.Name != "" {
		boxName = info.Ref.Name
	}

	stdout, stderr, code, err := exec(boxName, user, coderun.BootstrapReportScript(rawURL))
	if err != nil {
		msg := redactBootstrapURL(fmt.Sprintf("apply bootstrap bundle on %q as %q: %v", name, user, err), rawURL)
		log.Printf("[bootstrap] %s", msg)
		return nil, status.Error(codes.Unavailable, msg)
	}
	if code != 0 {
		detail := redactBootstrapURL(strings.TrimSpace(stderr), rawURL)
		if len(detail) > boxBootstrapMaxDetail {
			detail = "..." + detail[len(detail)-boxBootstrapMaxDetail:]
		}
		err := boxBootstrapExitError(name, code, detail)
		log.Printf("[bootstrap] apply on %q as %q failed: exit %d", name, user, code)
		return nil, err
	}
	revision, found, perr := coderun.ParseBootstrapReport(stdout)
	if perr != nil {
		// The bundle was applied; only its manifest is unreadable. Report the
		// apply, with no revision, rather than a failure the caller would retry
		// with a spent URL.
		log.Printf("[bootstrap] applied on %q as %q; the bundle's manifest.json is not JSON, no revision reported", name, user)
		return &pb.ApplyBoxBootstrapResponse{}, nil
	}
	log.Printf("[bootstrap] applied on %q as %q: bundle_revision=%d manifest=%v", name, user, revision, found)
	return &pb.ApplyBoxBootstrapResponse{BundleRevision: revision, ManifestFound: found}, nil
}

// boxBootstrapExitError maps the bundle script's exit code to the typed
// failure, with the same reading of "was the URL consumed?" the CLI gives.
// detail is the script's stderr, already redacted.
func boxBootstrapExitError(name string, code int, detail string) error {
	suffix := ""
	if detail != "" {
		suffix = ": " + detail
	}
	switch code {
	case coderun.BootstrapExitFetch:
		return boxBootstrapFailure(codes.Unavailable, pb.BoxBootstrapFailure_BOX_BOOTSTRAP_FAILURE_FETCH_UNREACHED, code,
			fmt.Sprintf("fetch bootstrap bundle on %q failed: the server was not reached, so the URL was not consumed, retry is safe (exit %d)%s", name, code, suffix))
	case coderun.BootstrapExitFetchReached:
		return boxBootstrapFailure(codes.FailedPrecondition, pb.BoxBootstrapFailure_BOX_BOOTSTRAP_FAILURE_FETCH_FAILED, code,
			fmt.Sprintf("fetch bootstrap bundle on %q failed after reaching the server: the URL may already be consumed (exit %d)%s", name, code, suffix))
	case coderun.BootstrapExitBundle:
		return boxBootstrapFailure(codes.FailedPrecondition, pb.BoxBootstrapFailure_BOX_BOOTSTRAP_FAILURE_BUNDLE_INVALID, code,
			fmt.Sprintf("apply bootstrap bundle on %q: the bundle was fetched but it is not a .tar.gz with an apply.sh at its root; the URL is spent (exit %d)%s", name, code, suffix))
	case coderun.BootstrapExitApply:
		return boxBootstrapFailure(codes.FailedPrecondition, pb.BoxBootstrapFailure_BOX_BOOTSTRAP_FAILURE_APPLY_FAILED, code,
			fmt.Sprintf("apply bootstrap bundle on %q: the bundle was fetched but its apply.sh failed; the URL is spent (exit %d)%s", name, code, suffix))
	}
	return status.Errorf(codes.Internal, "apply bootstrap bundle on %q: exit %d%s", name, code, suffix)
}
