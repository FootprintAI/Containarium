package proofpack

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

const (
	// SchemaVersion is the ProofPack layout this package writes.
	SchemaVersion = 1
	// LogLimitBytes bounds each step's stored log. The bound is applied in
	// the box, so the daemon never holds more than this per step; the last
	// LogLimitBytes of the output are kept.
	LogLimitBytes = 256 * 1024
	// DefaultRepoDir is where a box's repository is checked out
	// (pkg/core/container.FetchGitSource).
	DefaultRepoDir = "/workspace"
	// DefaultStepTimeout bounds each step.
	DefaultStepTimeout = 10 * time.Minute
	// timeoutKillGraceSecs is how long a timed-out step gets after SIGTERM
	// before SIGKILL.
	timeoutKillGraceSecs = 10
)

// Execer runs a command in a container and reports its exit status. A
// non-zero exit is not an error; err is for failing to run at all.
// incus.Backend satisfies it.
type Execer interface {
	ExecWithExitCode(containerName string, command []string) (stdout, stderr string, exitCode int, err error)
}

// Options configures Generate. Zero values take the defaults.
type Options struct {
	// RepoDir is the repository directory inside the box.
	RepoDir string
	// StepTimeout bounds each step; rounded up to whole seconds.
	StepTimeout time.Duration
	// Now is the clock; tests set it.
	Now func() time.Time
}

// probeScript reports, in one exec, what Generate needs before running
// anything: whether the repo dir exists, whether `timeout` is available,
// the declaration file's content (stdout, bounded) and whether a Makefile
// exists. Anything at the declaration path counts as present, including a
// dangling symlink or a directory, so an unusable declaration is refused
// (95) rather than mistaken for none. The exit status is 10 + 1
// (declaration present) + 2 (Makefile present); 95, 96 and 97 are the
// refusals.
const probeScript = `cd -- "$1" || exit 97
command -v timeout >/dev/null 2>&1 || exit 96
rc=10
if [ -e "$2" ] || [ -L "$2" ]; then head -c "$3" -- "$2" || exit 95; rc=$((rc + 1)); fi
if [ -f Makefile ] || [ -f makefile ] || [ -f GNUmakefile ]; then rc=$((rc + 2)); fi
exit "$rc"`

// stepScript runs one step with its output captured to a temp file in the
// box, then prints the output's full size on stderr and its last $4 bytes
// on stdout, and exits with the step's status. The command line arrives as
// $3 and is executed, never echoed. $2 is the timeout and $5 the SIGKILL
// grace, both in seconds.
const stepScript = `cd -- "$1" || exit 97
f=$(mktemp) || exit 98
timeout -k "$5" "$2" sh -c "$3" >"$f" 2>&1 </dev/null
rc=$?
wc -c <"$f" >&2
tail -c "$4" -- "$f"
rm -f -- "$f"
exit "$rc"`

// Generate runs the repository's test command set in box and returns the
// pack. It fails, with no pack, only when the commands could not be run
// at all (box unreachable, repo dir missing, unreadable declaration); a
// command that fails is recorded in the pack, not returned as an error.
func Generate(ctx context.Context, ex Execer, box string, opts Options) (*pb.ProofPack, error) {
	if box == "" {
		return nil, fmt.Errorf("proofpack: no box named")
	}
	if opts.RepoDir == "" {
		opts.RepoDir = DefaultRepoDir
	}
	if opts.StepTimeout <= 0 {
		opts.StepTimeout = DefaultStepTimeout
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	timeoutSecs := int64((opts.StepTimeout + time.Second - 1) / time.Second)

	pack := &pb.ProofPack{
		SchemaVersion:      SchemaVersion,
		Producer:           box,
		RepoDir:            opts.RepoDir,
		StartedAt:          timestamppb.New(opts.Now()),
		LogLimitBytes:      LogLimitBytes,
		StepTimeoutSeconds: timeoutSecs,
	}

	steps, err := resolveSteps(ex, box, opts.RepoDir, pack)
	if err != nil {
		return nil, err
	}
	pack.GitCommit = gitCommit(ex, box, opts.RepoDir)

	for _, s := range steps {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		step, err := runStep(ex, box, opts, timeoutSecs, s)
		if err != nil {
			return nil, err
		}
		pack.Steps = append(pack.Steps, step)
	}

	pack.Counts = countByKind(pack.Steps)
	pack.Status = statusOf(pack.Steps)
	pack.FinishedAt = timestamppb.New(opts.Now())
	return pack, nil
}

// resolveSteps reads the declaration (or falls back to `make test`) and
// records the source on pack.
func resolveSteps(ex Execer, box, dir string, pack *pb.ProofPack) ([]Step, error) {
	stdout, stderr, rc, err := ex.ExecWithExitCode(box, []string{
		"sh", "-c", probeScript, "proofpack-probe", dir, DeclarationPath, strconv.Itoa(MaxDeclarationBytes + 1),
	})
	if err != nil {
		return nil, fmt.Errorf("proofpack: probe %s: %w", box, err)
	}
	switch rc {
	case 97:
		return nil, fmt.Errorf("proofpack: repo dir %q does not exist in %s", dir, box)
	case 95:
		// A declaration that exists but cannot be read must not fall back
		// to `make test`: the repository declared something else.
		return nil, fmt.Errorf("proofpack: cannot read %s in %s: %s", DeclarationPath, box, strings.TrimSpace(stderr))
	case 96:
		return nil, fmt.Errorf("proofpack: %s has no `timeout` command (coreutils); steps cannot be bounded", box)
	case 10, 11, 12, 13:
	default:
		return nil, fmt.Errorf("proofpack: probe %s exited %d: %s", box, rc, strings.TrimSpace(stderr))
	}
	hasDecl := (rc-10)&1 != 0
	hasMakefile := (rc-10)&2 != 0

	if hasDecl {
		if len(stdout) > MaxDeclarationBytes {
			return nil, fmt.Errorf("proofpack: %s is larger than %d bytes", DeclarationPath, MaxDeclarationBytes)
		}
		steps, ok, err := ParseDeclaration([]byte(stdout))
		if err != nil {
			return nil, fmt.Errorf("proofpack: %w", err)
		}
		if ok {
			pack.CommandSource = pb.ProofCommandSource_PROOF_COMMAND_SOURCE_DECLARED
			pack.DeclarationSha256 = LogDigest([]byte(stdout))
			return steps, nil
		}
	}
	if hasMakefile {
		pack.CommandSource = pb.ProofCommandSource_PROOF_COMMAND_SOURCE_FALLBACK_MAKE_TEST
		return FallbackSteps(), nil
	}
	pack.CommandSource = pb.ProofCommandSource_PROOF_COMMAND_SOURCE_NONE
	return nil, nil
}

// gitCommit is HEAD of dir, or "" when dir is not a git checkout (or git
// is missing). It is informational, so failure is not an error.
func gitCommit(ex Execer, box, dir string) string {
	stdout, _, rc, err := ex.ExecWithExitCode(box, []string{
		"git", "-c", "safe.directory=*", "-C", dir, "rev-parse", "HEAD",
	})
	if err != nil || rc != 0 {
		return ""
	}
	return strings.TrimSpace(stdout)
}

func runStep(ex Execer, box string, opts Options, timeoutSecs int64, s Step) (*pb.ProofStep, error) {
	start := opts.Now()
	stdout, stderr, rc, err := ex.ExecWithExitCode(box, []string{
		"sh", "-c", stepScript, "proofpack-step",
		opts.RepoDir, strconv.FormatInt(timeoutSecs, 10), s.Run, strconv.Itoa(LogLimitBytes),
		strconv.Itoa(timeoutKillGraceSecs),
	})
	elapsed := opts.Now().Sub(start)
	if err != nil {
		return nil, fmt.Errorf("proofpack: step %q in %s: %w", s.Name, box, err)
	}
	// The wrapper prints the output size on stderr only once the step ran;
	// anything else there means the wrapper itself failed (no repo dir, no
	// temp file), which is not the step's outcome to record.
	size, perr := strconv.ParseInt(strings.TrimSpace(stderr), 10, 64)
	if perr != nil || size < 0 {
		return nil, fmt.Errorf("proofpack: step %q in %s could not run (exit %d): %s", s.Name, box, rc, strings.TrimSpace(stderr))
	}
	log := []byte(stdout)
	if len(log) > LogLimitBytes {
		log = log[len(log)-LogLimitBytes:]
	}
	return &pb.ProofStep{
		Name:     s.Name,
		Kind:     s.Kind,
		ExitCode: int32(rc), // #nosec G115 -- process exit statuses fit in int32
		// timeout(1) exits 124 on SIGTERM and 137 when it had to SIGKILL.
		// The step itself can exit with either, so the wall clock decides.
		TimedOut:         (rc == 124 || rc == 137) && elapsed >= time.Duration(timeoutSecs)*time.Second,
		DurationMs:       elapsed.Milliseconds(),
		Log:              log,
		LogSha256:        LogDigest(log),
		LogTruncated:     size > int64(len(log)),
		LogOriginalBytes: size,
	}, nil
}

func stepPassed(s *pb.ProofStep) bool {
	return s.GetExitCode() == 0 && !s.GetTimedOut()
}

func countByKind(steps []*pb.ProofStep) []*pb.ProofKindCount {
	byKind := make(map[pb.ProofPartKind]*pb.ProofKindCount)
	for _, s := range steps {
		c, ok := byKind[s.GetKind()]
		if !ok {
			c = &pb.ProofKindCount{Kind: s.GetKind()}
			byKind[s.GetKind()] = c
		}
		if stepPassed(s) {
			c.Passed++
		} else {
			c.Failed++
		}
	}
	counts := make([]*pb.ProofKindCount, 0, len(byKind))
	for _, c := range byKind {
		counts = append(counts, c)
	}
	sort.Slice(counts, func(i, j int) bool { return counts[i].GetKind() < counts[j].GetKind() })
	return counts
}

func statusOf(steps []*pb.ProofStep) pb.ProofPackStatus {
	if len(steps) == 0 {
		return pb.ProofPackStatus_PROOF_PACK_STATUS_NO_COMMANDS
	}
	for _, s := range steps {
		if !stepPassed(s) {
			return pb.ProofPackStatus_PROOF_PACK_STATUS_FAILED
		}
	}
	return pb.ProofPackStatus_PROOF_PACK_STATUS_PASSED
}
