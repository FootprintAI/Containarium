package server

import (
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// StartBoxRunRequest.workdir (#3551): the run starts in a directory under the
// home it would otherwise start in. The value follows WriteBoxFile's canonical
// relative-path rule (cleanHomeRelPath), and the directory must already exist:
// it is checked as the run's own user before anything on the box changes, never
// created, and a missing one never falls back to the home.

// Markers boxRunWorkdirCheckScript prints, one per outcome.
const (
	boxRunWorkdirMarkerOK      = "CBR_WORKDIR_OK"
	boxRunWorkdirMarkerMissing = "CBR_WORKDIR_MISSING"
	boxRunWorkdirMarkerNotDir  = "CBR_WORKDIR_NOTDIR"
	boxRunWorkdirMarkerNoEnter = "CBR_WORKDIR_NOENTER"
)

// validateBoxRunWorkdir applies the canonical path rule to a non-empty workdir.
func validateBoxRunWorkdir(workdir string) error {
	if workdir == "" {
		return nil
	}
	if _, err := cleanHomeRelPath("workdir", workdir); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	return nil
}

// boxRunWorkdirCheckScript reports, as the user it runs as, whether abs is a
// directory that user can enter. It always exits 0 and prints one marker.
func boxRunWorkdirCheckScript(abs string) string {
	return "p=" + shellSingleQuote(abs) + "\n" +
		"if [ ! -e \"$p\" ]; then echo " + boxRunWorkdirMarkerMissing + "\n" +
		"elif [ ! -d \"$p\" ]; then echo " + boxRunWorkdirMarkerNotDir + "\n" +
		"elif ( cd \"$p\" ) 2>/dev/null; then echo " + boxRunWorkdirMarkerOK + "\n" +
		"else echo " + boxRunWorkdirMarkerNoEnter + "\n" +
		"fi\n"
}

// resolveBoxRunWorkdir returns the directory the run starts in: home when
// workdir is empty, else home/workdir once runAs has been shown to be able to
// enter it. A missing directory, a non-directory or one runAs cannot enter is
// FAILED_PRECONDITION naming workdir.
func resolveBoxRunWorkdir(exec boxRunStartFunc, box, runAs, home, workdir string) (string, error) {
	if workdir == "" {
		return home, nil
	}
	abs := strings.TrimSuffix(home, "/") + "/" + workdir
	out, err := exec(box, runAs, boxRunWorkdirCheckScript(abs))
	if err != nil {
		return "", status.Errorf(codes.Unavailable, "check workdir %q on %q: %v", workdir, box, err)
	}
	switch strings.TrimSpace(out) {
	case boxRunWorkdirMarkerOK:
		return abs, nil
	case boxRunWorkdirMarkerMissing:
		return "", status.Errorf(codes.FailedPrecondition, "workdir %q does not exist in the run's home (%s) on %q; it is not created", workdir, home, box)
	case boxRunWorkdirMarkerNotDir:
		return "", status.Errorf(codes.FailedPrecondition, "workdir %q in the run's home (%s) on %q is not a directory", workdir, home, box)
	case boxRunWorkdirMarkerNoEnter:
		return "", status.Errorf(codes.FailedPrecondition, "workdir %q in the run's home (%s) on %q cannot be entered by %s", workdir, home, box, runAs)
	default:
		return "", status.Errorf(codes.Unavailable, "check workdir %q on %q: unexpected output %q", workdir, box, out)
	}
}
