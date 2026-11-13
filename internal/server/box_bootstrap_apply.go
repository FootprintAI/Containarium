package server

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"

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

// boxUserPattern is what an explicit box_user must look like: a plain login
// name (digits may lead, as useradd allows with its default settings). An
// empty box_user defaults to the box name, which validateBoxRunOwner already
// checked and which is the login the box-run and `code install` paths use;
// either way the user only ever reaches a shell single-quoted.
var boxUserPattern = regexp.MustCompile(`^[a-z0-9_][a-z0-9_.-]{0,31}$`)

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

// redactBootstrapURL removes the URL from text. A URL with a single quote is
// refused (validBootstrapURL), so the URL's shell-quoted spelling in the
// script ('<url>') contains it verbatim, at every level of quoting the exec
// wrapper adds, and one replacement of the raw URL covers them all.
func redactBootstrapURL(text, rawURL string) string {
	if rawURL == "" {
		return text
	}
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

// validBootstrapURL accepts an absolute http(s) URL with a host and no single
// quote (one would be escaped in the script, and the escaped spelling would
// escape redaction). The check never echoes the URL.
func validBootstrapURL(raw string) bool {
	if strings.ContainsRune(raw, '\'') {
		return false
	}
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
		return nil, status.Error(codes.InvalidArgument, "bootstrap_url must be an absolute http or https URL without a single quote")
	}
	user := strings.TrimSpace(req.GetBoxUser())
	explicitUser := user != ""
	if !explicitUser {
		user = name
	}
	switch {
	case explicitUser && !boxUserPattern.MatchString(user):
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

	// One apply per box at a time: a client retrying a call whose reply it
	// lost must not run a second apply.sh in the same home concurrently.
	mu, _ := s.boxBootstrapLocks.LoadOrStore(boxName, &sync.Mutex{})
	lock := mu.(*sync.Mutex)
	if !lock.TryLock() {
		return nil, boxBootstrapFailure(codes.Aborted, pb.BoxBootstrapFailure_BOX_BOOTSTRAP_FAILURE_APPLY_IN_PROGRESS, 0,
			fmt.Sprintf("another bootstrap apply is running on %q; nothing was fetched by this call, retry once it has returned", name))
	}
	defer lock.Unlock()

	// Preflight, before the URL is used: the user exists and can run the step.
	_, pstderr, pcode, err := exec(boxName, user, coderun.BootstrapPreflightScript())
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "bootstrap preflight on %q as %q: %v; nothing was fetched", name, user, err)
	}
	if pcode != 0 {
		return nil, boxBootstrapPreflightError(name, user, pcode, strings.TrimSpace(pstderr))
	}

	stdout, stderr, code, err := exec(boxName, user, coderun.BootstrapReportScript(rawURL))
	if err != nil {
		// The step may have run to completion (e.g. output over the exec cap):
		// the outcome is unknown and the URL may be spent, so this is not the
		// retry-safe FETCH_UNREACHED.
		msg := redactBootstrapURL(fmt.Sprintf("apply bootstrap bundle on %q as %q: the exec into the box failed, so whether the bundle was applied is unknown and the URL may be spent: %v", name, user, err), rawURL)
		log.Printf("[bootstrap] %s", msg)
		return nil, boxBootstrapFailure(codes.Unknown, pb.BoxBootstrapFailure_BOX_BOOTSTRAP_FAILURE_OUTCOME_UNKNOWN, 0, msg)
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
	return boxBootstrapFailure(codes.Internal, pb.BoxBootstrapFailure_BOX_BOOTSTRAP_FAILURE_UNEXPECTED_EXIT, code,
		fmt.Sprintf("apply bootstrap bundle on %q: unexpected exit %d; the URL may be spent%s", name, code, suffix))
}

// boxBootstrapPreflightError maps a failed preflight. 10-12 are the
// preflight's own codes; anything else means the script never ran as user (su
// refused: no such user, or it cannot log in). Nothing was fetched.
func boxBootstrapPreflightError(name, user string, code int, detail string) error {
	if len(detail) > boxBootstrapMaxDetail {
		detail = "..." + detail[len(detail)-boxBootstrapMaxDetail:]
	}
	suffix := ""
	if detail != "" {
		suffix = ": " + detail
	}
	var why string
	switch code {
	case coderun.PreflightExitHome:
		why = "$HOME is not writable for the box user"
	case coderun.PreflightExitTmp:
		why = "no temporary directory can be created on the box"
	case coderun.PreflightExitTools:
		why = "curl or tar is missing on the box"
	default:
		return boxBootstrapFailure(codes.FailedPrecondition, pb.BoxBootstrapFailure_BOX_BOOTSTRAP_FAILURE_BOX_USER_UNAVAILABLE, 0,
			fmt.Sprintf("bootstrap preflight on %q could not run as %q (exit %d): the user does not exist in the box or cannot log in; nothing was fetched%s", name, user, code, suffix))
	}
	return boxBootstrapFailure(codes.FailedPrecondition, pb.BoxBootstrapFailure_BOX_BOOTSTRAP_FAILURE_PREFLIGHT_FAILED, code,
		fmt.Sprintf("bootstrap preflight on %q as %q: %s; nothing was fetched (exit %d)", name, user, why, code))
}
