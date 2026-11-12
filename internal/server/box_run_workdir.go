package server

import (
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/coderun"
)

// StartBoxRunRequest.workdir (#3551): the run starts in a directory under the
// home it would otherwise start in. The value follows WriteBoxFile's canonical
// relative-path rule (coderun.CleanHomeRelPath), and the directory must already
// exist: it is checked as the run's own user before anything on the box
// changes, never created, and a missing one never falls back to the home.
// `containarium code run --workdir` and MCP code_run apply the same rule and
// check over SSH (#3613).

// validateBoxRunWorkdir applies the canonical path rule to a non-empty workdir.
func validateBoxRunWorkdir(workdir string) error {
	if workdir == "" {
		return nil
	}
	if _, err := coderun.CleanHomeRelPath("workdir", workdir); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	return nil
}

// resolveBoxRunWorkdir returns the directory the run starts in: home when
// workdir is empty, else home/workdir once runAs has been shown to be able to
// enter it (coderun.WorkdirCheckScript). A missing directory, a non-directory
// or one runAs cannot enter is FAILED_PRECONDITION naming workdir.
func resolveBoxRunWorkdir(exec boxRunStartFunc, box, runAs, home, workdir string) (string, error) {
	if workdir == "" {
		return home, nil
	}
	abs := coderun.WorkdirPath(home, workdir)
	out, err := exec(box, runAs, coderun.WorkdirCheckScript(abs))
	if err != nil {
		return "", status.Errorf(codes.Unavailable, "check workdir %q on %q: %v", workdir, box, err)
	}
	switch strings.TrimSpace(out) {
	case coderun.WorkdirMarkerOK:
		return abs, nil
	case coderun.WorkdirMarkerMissing:
		return "", status.Errorf(codes.FailedPrecondition, "workdir %q does not exist in the run's home (%s) on %q; it is not created", workdir, home, box)
	case coderun.WorkdirMarkerNotDir:
		return "", status.Errorf(codes.FailedPrecondition, "workdir %q in the run's home (%s) on %q is not a directory", workdir, home, box)
	case coderun.WorkdirMarkerNoEnter:
		return "", status.Errorf(codes.FailedPrecondition, "workdir %q in the run's home (%s) on %q cannot be entered by %s", workdir, home, box, runAs)
	default:
		return "", status.Errorf(codes.Unavailable, "check workdir %q on %q: unexpected output %q", workdir, box, out)
	}
}
