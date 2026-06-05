package runner

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// MaxRunnerCount is the upper bound on how many runners a single
// provision call will create. 100 is generous for most teams (Cloud
// Run on most plans caps concurrent jobs far below this) and small
// enough that an agent typo (`count: 1000`) doesn't accidentally
// spin up a fleet that bleeds the cloud bill before the operator
// notices.
const MaxRunnerCount = 100

// DefaultBoxCreateTimeout caps how long we'll wait for a single
// box to come up and accept SSH. 5 min covers the Incus create →
// cloud-init → sshd-ready path with comfortable headroom for slow
// images; failing fast above that lets the caller move on and a
// human investigate rather than the agent blocking forever.
const DefaultBoxCreateTimeout = 5 * time.Minute

// DefaultInstallTimeout caps the runner install step. The script
// apt-installs a handful of packages plus toolchains (Go, Node,
// buf, golangci-lint) — on a cold box that can take 3-4 minutes
// over a slow link. 10 min is "generous-but-bounded".
const DefaultInstallTimeout = 10 * time.Minute

// DefaultSSHReadyTimeout bounds how long provision waits for a freshly-
// created box to become reachable via the sentinel before the first
// install-state probe. A new box isn't SSH-able the instant it reaches
// RUNNING: its sshd has to come up AND the sentinel keysync has to
// propagate the box's host-side authorized_keys into sshpiper's per-box
// gate — a periodic poll that can take a couple of minutes. Until then
// the probe is rejected publickey / dial-refused, which is transient, not
// a real failure. Comfortably over the observed keysync interval. (#475)
const DefaultSSHReadyTimeout = 5 * time.Minute

// sshProbeInitialBackoff is the first inter-probe wait in
// waitForSSHInstalled; it doubles up to sshProbeMaxBackoff. A package var
// so tests can shrink it to keep the retry loop instant.
var sshProbeInitialBackoff = 3 * time.Second

const sshProbeMaxBackoff = 15 * time.Second

// waitForSSHInstalled retries the install-state probe until the box is
// reachable via the sentinel (sshd up + keysync done) or readyTimeout /
// ctx expires. A freshly-created box's first probes fail publickey/dial;
// those are transient here, so we back off and retry rather than failing
// the whole provision on the first miss. Returns IsInstalled's result once
// SSH succeeds. (#475)
func waitForSSHInstalled(ctx context.Context, ssh RunnerInstaller, name string, readyTimeout time.Duration) (bool, error) {
	deadline := time.Now().Add(readyTimeout)
	backoff := sshProbeInitialBackoff
	var lastErr error
	for {
		installed, err := ssh.IsInstalled(ctx, name)
		if err == nil {
			return installed, nil
		}
		lastErr = err
		if time.Now().After(deadline) {
			return false, fmt.Errorf("box not reachable via sentinel within %s (sshd/keysync not ready): %w", readyTimeout, lastErr)
		}
		select {
		case <-ctx.Done():
			return false, fmt.Errorf("box not reachable via sentinel: %w", lastErr)
		case <-time.After(backoff):
		}
		if backoff < sshProbeMaxBackoff {
			if backoff *= 2; backoff > sshProbeMaxBackoff {
				backoff = sshProbeMaxBackoff
			}
		}
	}
}

// DefaultRegistrationTimeout caps the post-install poll waiting
// for the runner to appear in GitHub's runners list. systemd
// usually starts the service within a couple of seconds; we give
// 60 s so a slow `actions-runner` tarball extract on the box
// doesn't trip the wait. Use exponential backoff so we don't
// hammer the GitHub API.
const DefaultRegistrationTimeout = 60 * time.Second

// Options is the typed input to Provision. Field defaults are
// applied by Provision when the field is the zero value, so a
// caller that wants the defaults can pass `Options{Repo: "...",
// PAT: "...", Count: 1}` and not worry about timeouts.
type Options struct {
	// Repo in "owner/repo" form. Validated against repoPattern.
	Repo string

	// PAT is a GitHub Personal Access Token with `repo` scope.
	// Used both to mint registration tokens (inside the box, via
	// the install script) and to query the runners-list API to
	// confirm registration succeeded.
	PAT string

	// Count is the number of runners to provision. 1..MaxRunnerCount.
	Count int

	// NamePrefix is the prefix used when generating box names via
	// NameTemplate. Default: "ci-runner".
	NamePrefix string

	// Labels is the comma-separated label list applied to each
	// runner. Default: "containarium,ephemeral". Workflows target
	// with `runs-on: [self-hosted, <labels>...]`.
	Labels string

	// NameTemplate is the Go-style template used to build each
	// runner's box name. Two placeholders are supported and
	// substituted by simple string replace:
	//   {prefix}  → NamePrefix
	//   {i}       → 1-based runner index
	// Default: "{prefix}-{i}".
	NameTemplate string

	// SSHKey is an optional override of the SSH public key used
	// when creating boxes. Empty means the BoxManager picks a
	// default (most implementations generate an ephemeral key).
	SSHKey string

	// BoxCreateTimeout / InstallTimeout / RegistrationTimeout are
	// per-step deadlines. Zero falls back to the Default* values.
	BoxCreateTimeout    time.Duration
	InstallTimeout      time.Duration
	RegistrationTimeout time.Duration

	// MaxTotal is the system-wide ceiling on how many runner boxes
	// (names matching NamePrefix) may exist at once, across every
	// caller. Provision counts the live fleet and creates at most
	// (MaxTotal - live) net-new boxes; the remainder of a request is
	// DEFERRED (returned as "queued" rows, see Result.Deferred) rather
	// than failed — the jobs wait in GitHub's queue until an ephemeral
	// runner frees a slot. Zero falls back to MaxRunnersTotal() (env
	// MAX_RUNNERS_TOTAL or DefaultMaxRunnersTotal). Distinct from
	// MaxRunnerCount, which bounds a single call's Count.
	MaxTotal int
}

// RunnerStatus is the per-runner outcome shape returned by
// Provision / List / Remove. Kept as a small typed struct (not a
// `map[string]interface{}` — CLAUDE.md, strong typing) so both the
// CLI summary table and the MCP JSON response render uniformly.
type RunnerStatus struct {
	// Name is the box / runner name (these are 1:1 — we name the
	// GitHub runner after its containarium box).
	Name string

	// BoxID is the platform's container identifier returned by
	// the BoxManager. Empty when create failed before the box
	// got a name.
	BoxID string

	// State is one of: "provisioned" (full success — box up,
	// service installed, runner registered), "registering"
	// (install succeeded, GitHub poll timed out — usually
	// transient), "exists" (we found an already-configured
	// runner and skipped — idempotent re-run), "failed" (see
	// LastError), "removed" (Remove succeeded).
	State string

	// LastError carries the failure reason when State == "failed".
	// Empty on success.
	LastError string

	// Registered reflects the GitHub-side runners-list check.
	// True only if we saw the runner in GitHub's list. False
	// for "registering" (poll timed out) and "failed".
	Registered bool
}

// Result aggregates per-runner status plus a top-level partial-
// error indicator. Provision is partial-success-tolerant: when 2
// of 3 boxes succeed and one fails, the caller sees a non-nil
// Result with Runners populated and PartialFailure=true. We do
// NOT return a Go error in that case — the caller would otherwise
// have to inspect the error to find the partial state, which is
// the same dynamic-typing footgun CLAUDE.md warns about.
type Result struct {
	Runners        []RunnerStatus
	PartialFailure bool

	// Deferred is how many of the requested runners were NOT created
	// because doing so would exceed Options.MaxTotal. These appear in
	// Runners with State "queued". Deferral is backpressure, not
	// failure: it never sets PartialFailure and Provision returns a
	// nil error. The deferred jobs wait in GitHub's own queue until an
	// ephemeral runner finishes and a `runner reconcile` tick (or the
	// next provision call) tops the pool back up.
	Deferred int
}

// BoxManager abstracts the create/exists/delete operations on
// Containarium boxes so tests can fake the Incus / gRPC path
// without standing up a real daemon. The CLI's adapter calls
// internal/cmd/create.go's create helpers; the MCP tool's
// adapter calls the same.
type BoxManager interface {
	// Exists returns true if a box with the given name already
	// exists on the daemon. Used for the idempotent-re-provision
	// check (skip create if the box is already there).
	Exists(ctx context.Context, name string) (bool, error)

	// Create provisions a new box with the given name. The
	// implementation supplies whatever sensible defaults the
	// caller doesn't override (CPU/mem/disk, image, etc.).
	Create(ctx context.Context, name, sshKey string) (boxID string, err error)

	// Delete tears down the box. force is the same semantics as
	// `containarium delete --force`.
	Delete(ctx context.Context, name string, force bool) error

	// List returns the names of every box currently registered
	// on the daemon. Used by List to find runner boxes without
	// querying GitHub.
	List(ctx context.Context) ([]string, error)
}

// RunnerInstaller wraps "ssh into a box and run the install
// script" so tests can replace the SSH/exec path with a no-op
// fake. Real implementations live alongside the CLI / MCP
// adapters and shell out via golang.org/x/crypto/ssh.
type RunnerInstaller interface {
	// IsInstalled reports whether containarium-runner.service is
	// already present and enabled inside the box. When true,
	// Provision skips the Install step (idempotent re-run).
	IsInstalled(ctx context.Context, boxName string) (bool, error)

	// Install copies the embedded install script into the box
	// and runs it with the supplied env vars (GH_REPO, GH_PAT,
	// RUNNER_NAME, RUNNER_LABELS).
	Install(ctx context.Context, boxName string, script []byte, env map[string]string) error
}

// GitHubAPI abstracts the small slice of the GitHub REST API
// Provision uses: list runners (for the registration-confirmation
// poll) and remove a runner (for the Remove verb's deregister
// step). Tests inject a fake; the production impl talks to
// api.github.com.
type GitHubAPI interface {
	// ListRunners returns the names of every runner currently
	// registered against the given repo. We don't care about IDs
	// for the registration poll, just "is our name in there?"
	ListRunners(ctx context.Context, repo, pat string) ([]RegisteredRunner, error)

	// RemoveRunner deregisters a runner by ID. Called by Remove
	// after draining. Idempotent: 404 from the API is treated as
	// "already gone" and returned as nil.
	RemoveRunner(ctx context.Context, repo, pat string, runnerID int64) error
}

// RegisteredRunner is what ListRunners returns — the small
// subset of the GitHub API's runner record we actually need.
type RegisteredRunner struct {
	ID     int64
	Name   string
	Status string // "online" | "offline"
	Busy   bool
}

// Clock is injected so tests don't actually sleep. Defaults to a
// real-time implementation when nil; tests pass a fake that
// records sleeps for assertion.
type Clock interface {
	Now() time.Time
	Sleep(d time.Duration)
}

type realClock struct{}

func (realClock) Now() time.Time        { return time.Now() }
func (realClock) Sleep(d time.Duration) { time.Sleep(d) }

// Deps bundles the dependencies Provision needs. Keeping them in
// one struct (not as separate function params) means callers and
// tests can build a fully-wired dependency graph in one place
// and the function signature stays narrow.
type Deps struct {
	Boxes  BoxManager
	SSH    RunnerInstaller
	GitHub GitHubAPI
	Clock  Clock
}

// repoPattern matches GitHub's "owner/repo" shape. Owner and repo
// names can contain alphanumerics, hyphen, underscore, and dot;
// GitHub's full rules are slightly more permissive but this catches
// the common typos (spaces, slashes other than the single separator,
// empty owner or repo) without false negatives on real repo names.
var repoPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$`)

// ValidateOptions returns a descriptive error when Options would
// fail any precondition Provision checks. Exposed separately so
// callers (CLI flag handler, MCP tool argument parser) can
// surface input errors before doing any actual work.
func ValidateOptions(opts Options) error {
	if opts.Repo == "" {
		return fmt.Errorf("repo is required (owner/repo format)")
	}
	if !repoPattern.MatchString(opts.Repo) {
		return fmt.Errorf("repo %q is not in owner/repo format", opts.Repo)
	}
	if opts.PAT == "" {
		return fmt.Errorf("github_pat is required (PAT with `repo` scope)")
	}
	if opts.Count <= 0 {
		return fmt.Errorf("count must be > 0, got %d", opts.Count)
	}
	if opts.Count > MaxRunnerCount {
		return fmt.Errorf("count %d exceeds maximum of %d (open a manual ticket if you really need a bigger pool)", opts.Count, MaxRunnerCount)
	}
	return nil
}

// applyDefaults fills in zero-value fields with sensible defaults.
// Done as a separate step (not at field-read time) so each call
// to Provision sees a fully-populated Options without sprinkling
// `if x == "" { x = "default" }` through the orchestration body.
func applyDefaults(opts Options) Options {
	if opts.NamePrefix == "" {
		opts.NamePrefix = "ci-runner"
	}
	if opts.Labels == "" {
		opts.Labels = "containarium,ephemeral"
	}
	if opts.NameTemplate == "" {
		opts.NameTemplate = "{prefix}-{i}"
	}
	if opts.BoxCreateTimeout == 0 {
		opts.BoxCreateTimeout = DefaultBoxCreateTimeout
	}
	if opts.InstallTimeout == 0 {
		opts.InstallTimeout = DefaultInstallTimeout
	}
	if opts.RegistrationTimeout == 0 {
		opts.RegistrationTimeout = DefaultRegistrationTimeout
	}
	if opts.MaxTotal <= 0 {
		opts.MaxTotal = MaxRunnersTotal()
	}
	return opts
}

// RenderName resolves opts.NameTemplate against (prefix, i). Pure
// function so the CLI / MCP can preview names before any actual
// work (e.g. "names that would be created: ci-runner-1, ci-runner-2").
func RenderName(template, prefix string, i int) string {
	name := template
	name = strings.ReplaceAll(name, "{prefix}", prefix)
	name = strings.ReplaceAll(name, "{i}", fmt.Sprintf("%d", i))
	return name
}

// Provision is the central orchestration helper. Both the CLI's
// `containarium runner provision` handler and the MCP tool's
// provision_runners handler call this directly — there is no
// HTTP / shell boundary between them and this function.
//
// Behavior per runner (i in 1..opts.Count):
//
//  1. Compute box name via RenderName.
//  2. If the box doesn't exist, create it. If it does, skip.
//  3. If containarium-runner.service is already installed and
//     enabled, skip the install (idempotent re-run).
//  4. Else: ship the embedded InstallScript into the box and run
//     it with the right env vars.
//  5. Poll GitHub for the runner's registration. Success → State
//     "provisioned"; timeout → State "registering"; install or
//     create failure → State "failed".
//
// Per-runner failures don't abort the whole call — each runner
// gets its own RunnerStatus and the top-level Result.PartialFailure
// flag reflects whether any failed.
func Provision(ctx context.Context, deps Deps, opts Options) (*Result, error) {
	if err := ValidateOptions(opts); err != nil {
		return nil, err
	}
	opts = applyDefaults(opts)
	if deps.Clock == nil {
		deps.Clock = realClock{}
	}
	if deps.Boxes == nil || deps.SSH == nil || deps.GitHub == nil {
		return nil, fmt.Errorf("internal error: runner.Provision called with missing deps (boxes=%v ssh=%v github=%v)",
			deps.Boxes != nil, deps.SSH != nil, deps.GitHub != nil)
	}

	res := &Result{
		Runners: make([]RunnerStatus, 0, opts.Count),
	}

	// Enforce the system-wide cap. Count the live runner fleet (boxes
	// matching NamePrefix — the same signal the cap is billed against)
	// and create at most (MaxTotal - live) net-new boxes this call.
	// Anything beyond headroom is DEFERRED, not failed: it comes back
	// as a "queued" row so the caller (notably `runner reconcile`)
	// knows the job is waiting on GitHub's queue, not broken.
	live, err := CountLiveRunners(ctx, deps, opts.NamePrefix)
	if err != nil {
		return nil, err
	}
	headroom := opts.MaxTotal - live
	if headroom < 0 {
		headroom = 0
	}

	for i := 1; i <= opts.Count; i++ {
		name := RenderName(opts.NameTemplate, opts.NamePrefix, i)
		if i > headroom {
			// Past the cap — queue rather than create.
			res.Runners = append(res.Runners, RunnerStatus{Name: name, State: "queued"})
			res.Deferred++
			continue
		}
		status := provisionOne(ctx, deps, opts, name)
		if status.State == "failed" {
			res.PartialFailure = true
		}
		res.Runners = append(res.Runners, status)
	}

	return res, nil
}

// provisionOne owns the per-box flow. Factored out so the per-
// runner loop in Provision stays scannable and so future paths
// (parallel provisioning, retry) have a single entry point to
// wrap.
func provisionOne(ctx context.Context, deps Deps, opts Options, name string) RunnerStatus {
	st := RunnerStatus{Name: name}

	// Step 1+2: idempotent box create.
	createCtx, cancelCreate := context.WithTimeout(ctx, opts.BoxCreateTimeout)
	defer cancelCreate()

	exists, err := deps.Boxes.Exists(createCtx, name)
	if err != nil {
		st.State = "failed"
		st.LastError = fmt.Sprintf("check box existence: %v", err)
		return st
	}
	if exists {
		st.BoxID = name // best-effort, the daemon's canonical ID may differ but matches in practice
	} else {
		boxID, err := deps.Boxes.Create(createCtx, name, opts.SSHKey)
		if err != nil {
			st.State = "failed"
			st.LastError = fmt.Sprintf("create box: %v", err)
			return st
		}
		st.BoxID = boxID
	}

	// Step 3+4: idempotent runner install.
	installCtx, cancelInstall := context.WithTimeout(ctx, opts.InstallTimeout)
	defer cancelInstall()

	// Retry the first probe across the sshd-startup + sentinel-keysync
	// window — a fresh box is briefly unreachable (publickey/dial) before
	// its key is live in sshpiper. Bounded by installCtx (InstallTimeout)
	// and DefaultSSHReadyTimeout. (#475)
	installed, err := waitForSSHInstalled(installCtx, deps.SSH, name, DefaultSSHReadyTimeout)
	if err != nil {
		st.State = "failed"
		st.LastError = fmt.Sprintf("check install state: %v", err)
		return st
	}
	if installed {
		// Idempotent path: the box already has the runner
		// service. Skip the script. We still do the GitHub
		// poll below so a half-provisioned box (installed but
		// never managed to register) shows the right state.
		st.State = "exists"
	} else {
		env := map[string]string{
			"GH_REPO":       opts.Repo,
			"GH_PAT":        opts.PAT,
			"RUNNER_NAME":   name,
			"RUNNER_LABELS": opts.Labels,
		}
		if err := deps.SSH.Install(installCtx, name, InstallScript, env); err != nil {
			st.State = "failed"
			st.LastError = fmt.Sprintf("install runner: %v", err)
			return st
		}
		st.State = "provisioned"
	}

	// Step 5: GitHub-side registration confirmation. Poll with
	// exponential backoff so a slow runner-side startup doesn't
	// blow the GitHub API rate limit. Capped at
	// RegistrationTimeout total.
	registered := waitForRegistration(ctx, deps, opts, name)
	st.Registered = registered
	if !registered && st.State != "exists" {
		// Don't downgrade an already-failed status; only mark
		// "registering" when the install succeeded but GitHub
		// hasn't shown us the runner yet.
		st.State = "registering"
	}

	return st
}

// waitForRegistration polls GitHub for the runner name with
// exponential backoff until it appears or RegistrationTimeout
// elapses. Returns true on success, false on timeout. Network
// errors during the poll are treated as "not yet visible" — we
// retry rather than failing, since transient GitHub API blips
// are common and the box may well be registered.
func waitForRegistration(ctx context.Context, deps Deps, opts Options, name string) bool {
	deadline := deps.Clock.Now().Add(opts.RegistrationTimeout)
	// Backoff: 2 s, 4 s, 8 s, capped at 15 s. Keeps us well
	// under GitHub's 5000-req/hr authenticated rate limit even
	// when provisioning a big pool.
	backoff := 2 * time.Second
	const maxBackoff = 15 * time.Second
	for {
		runners, err := deps.GitHub.ListRunners(ctx, opts.Repo, opts.PAT)
		if err == nil {
			for _, r := range runners {
				if r.Name == name {
					return true
				}
			}
		}
		// Time check happens after the API call so we always
		// make at least one attempt even with a zero-duration
		// timeout — useful for tests.
		now := deps.Clock.Now()
		if !now.Before(deadline) {
			return false
		}
		// Sleep no longer than the remaining budget so we don't
		// undercut the caller's timeout.
		remaining := deadline.Sub(now)
		sleep := backoff
		if sleep > remaining {
			sleep = remaining
		}
		deps.Clock.Sleep(sleep)
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// List returns the runners currently registered to opts.Repo whose
// names start with opts.NamePrefix. The result merges two views:
// the GitHub-side registration (does the runner exist? is it busy?)
// and the local box view (is the box still on this daemon?).
//
// This is the implementation behind both `containarium runner list`
// and the MCP `list_runners` tool. Repo/PAT are required so we can
// query the runners-list API; NamePrefix is the filter (only boxes
// whose name starts with it are returned).
func List(ctx context.Context, deps Deps, opts Options) (*Result, error) {
	if opts.Repo == "" {
		return nil, fmt.Errorf("repo is required")
	}
	if !repoPattern.MatchString(opts.Repo) {
		return nil, fmt.Errorf("repo %q is not in owner/repo format", opts.Repo)
	}
	if opts.PAT == "" {
		return nil, fmt.Errorf("github_pat is required")
	}
	if opts.NamePrefix == "" {
		opts.NamePrefix = "ci-runner"
	}

	boxes, err := deps.Boxes.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list boxes: %w", err)
	}

	runners, err := deps.GitHub.ListRunners(ctx, opts.Repo, opts.PAT)
	if err != nil {
		// Don't fail outright — we can still return the box
		// view, which is the half of the answer the local
		// daemon owns. Mark each box as "registration unknown"
		// by leaving Registered=false.
		runners = nil
	}
	byName := make(map[string]RegisteredRunner, len(runners))
	for _, r := range runners {
		byName[r.Name] = r
	}

	res := &Result{}
	for _, name := range boxes {
		if !strings.HasPrefix(name, opts.NamePrefix) {
			continue
		}
		st := RunnerStatus{Name: name, BoxID: name}
		if reg, ok := byName[name]; ok {
			st.Registered = true
			st.State = reg.Status // "online" or "offline"
			if reg.Busy {
				st.State = "busy"
			}
		} else {
			st.State = "unregistered"
		}
		res.Runners = append(res.Runners, st)
	}
	return res, nil
}

// Remove deregisters a runner from GitHub (best effort), then
// deletes the box. The "drain" step that the install script's
// systemd unit handles natively — stopping the service waits for
// any in-flight job to exit because the runner is in --ephemeral
// mode and exits cleanly after the current job. We capture that
// guarantee by giving stopping a generous timeout; in this PR
// we keep it simple: the existing ssh-based stop happens inside
// the box-delete codepath.
//
// Opts.Repo / Opts.PAT are required so we can find the runner in
// GitHub's list and remove it. Opts.NamePrefix is ignored — name
// is taken from the explicit Name argument.
func Remove(ctx context.Context, deps Deps, opts Options, name string) (*RunnerStatus, error) {
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if opts.Repo == "" || opts.PAT == "" {
		return nil, fmt.Errorf("repo and github_pat are required so the runner can be deregistered from github")
	}
	if !repoPattern.MatchString(opts.Repo) {
		return nil, fmt.Errorf("repo %q is not in owner/repo format", opts.Repo)
	}

	st := &RunnerStatus{Name: name, BoxID: name}

	// Best-effort GitHub deregister. If the runner isn't in
	// GitHub's list we treat that as already-deregistered. If
	// the API call fails entirely we still proceed to delete
	// the box so the agent can finish the "tear it down" intent
	// — the worst case is a stale "offline" row in GitHub's UI,
	// not a leaked box.
	runners, err := deps.GitHub.ListRunners(ctx, opts.Repo, opts.PAT)
	if err == nil {
		for _, r := range runners {
			if r.Name == name {
				if rmErr := deps.GitHub.RemoveRunner(ctx, opts.Repo, opts.PAT, r.ID); rmErr != nil {
					st.LastError = fmt.Sprintf("github deregister: %v (proceeding with box delete anyway)", rmErr)
				}
				break
			}
		}
	}

	if err := deps.Boxes.Delete(ctx, name, true); err != nil {
		st.State = "failed"
		if st.LastError == "" {
			st.LastError = fmt.Sprintf("delete box: %v", err)
		} else {
			st.LastError = st.LastError + "; delete box: " + err.Error()
		}
		return st, fmt.Errorf("delete box %s: %w", name, err)
	}

	st.State = "removed"
	return st, nil
}
