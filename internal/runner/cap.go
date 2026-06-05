package runner

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// DefaultMaxRunnersTotal is the system-wide ceiling on how many
// runner boxes may exist at once, used when MAX_RUNNERS_TOTAL is
// unset/invalid. 20 is comfortably above a typical CI fan-out,
// well under the per-call MaxRunnerCount=100 sanity bound, and
// small enough to protect the cloud bill if an autoscaler (or an
// agent) keeps asking for more. Unlike MaxRunnerCount — which
// bounds a SINGLE provision call — this bounds the WHOLE fleet
// across every caller (CLI, MCP, the daemon reconciler).
const DefaultMaxRunnersTotal = 20

// MaxRunnersTotal resolves the system-wide runner ceiling. It
// reads MAX_RUNNERS_TOTAL from the environment and falls back to
// DefaultMaxRunnersTotal when the var is unset, unparseable, or
// non-positive. Kept as a function (not a package var) so a value
// change picks up without a process restart and so tests can flip
// it with t.Setenv.
func MaxRunnersTotal() int {
	raw := strings.TrimSpace(os.Getenv("MAX_RUNNERS_TOTAL"))
	if raw == "" {
		return DefaultMaxRunnersTotal
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		// A typo'd/garbage value should fail safe to the default
		// rather than disable the cap (n<=0) or crash.
		return DefaultMaxRunnersTotal
	}
	return n
}

// CountLiveRunners reports how many runner boxes currently exist on
// the daemon — the capacity signal the cap is enforced against. We
// count BOXES (via deps.Boxes.List) rather than GitHub-registered
// runners on purpose: a box counts against the cap the moment it
// exists (that's what's billed), even before it registers with
// GitHub and after it finishes a job but before teardown. GitHub's
// registered view lags box lifecycle in both directions, so it's
// the wrong primary gate.
//
// namePrefix defaults to "ci-runner" — the same default Provision
// uses — and only boxes whose name starts with it are counted, so
// non-runner containers never consume runner headroom.
func CountLiveRunners(ctx context.Context, deps Deps, namePrefix string) (int, error) {
	if namePrefix == "" {
		namePrefix = "ci-runner"
	}
	if deps.Boxes == nil {
		return 0, fmt.Errorf("internal error: CountLiveRunners called with nil Boxes")
	}
	names, err := deps.Boxes.List(ctx)
	if err != nil {
		return 0, fmt.Errorf("count live runners: %w", err)
	}
	n := 0
	for _, name := range names {
		if strings.HasPrefix(name, namePrefix) {
			n++
		}
	}
	return n, nil
}
