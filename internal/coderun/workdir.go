package coderun

import (
	"context"
	"fmt"
	"path"
	"strings"
)

// The directory a run starts in (#3613). The daemon's StartBoxRunRequest.workdir
// (#3551), `containarium code run --workdir` and the platform MCP code_run
// tool's workdir share one rule: a canonical path relative to the home the run
// starts in (CleanHomeRelPath), naming a directory that already exists. It is
// checked as the run's own user before anything on the box changes, never
// created, and a missing one never falls back to the home.

const (
	// MaxHomeRelPathBytes bounds a home-relative path (CleanHomeRelPath).
	MaxHomeRelPathBytes = 1024
	// MaxHomeRelPathSegmentBytes bounds each of its segments. It leaves room
	// for the ".cbf.<pid>" suffix of WriteBoxFile's temp file (NAME_MAX is 255).
	MaxHomeRelPathSegmentBytes = 200
)

// CleanHomeRelPath is the canonical home-relative path rule, shared by
// WriteBoxFile's path and a run's workdir. It demands the canonical spelling
// rather than cleaning it, so what the caller asked for is what is used. field
// names the request field or flag in the error.
func CleanHomeRelPath(field, p string) (string, error) {
	switch {
	case p == "":
		return "", fmt.Errorf("%s is required", field)
	case len(p) > MaxHomeRelPathBytes:
		return "", fmt.Errorf("%s must be at most %d bytes", field, MaxHomeRelPathBytes)
	case strings.HasPrefix(p, "/"):
		return "", fmt.Errorf("%s must be relative to the box user's home directory", field)
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("%s must not contain control characters", field)
		}
	}
	if path.Clean(p) != p || p == "." {
		return "", fmt.Errorf("%s must be a clean relative path inside the home directory (no \"..\", \".\", empty or trailing segments)", field)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." || len(seg) > MaxHomeRelPathSegmentBytes {
			return "", fmt.Errorf("%s must stay inside the home directory and keep each segment under %d bytes", field, MaxHomeRelPathSegmentBytes)
		}
	}
	if first := strings.SplitN(p, "/", 2)[0]; first == ".ssh" || first == ".containarium" {
		return "", fmt.Errorf("%s must not be under %s: the platform manages it", field, first)
	}
	return p, nil
}

// Markers WorkdirCheckScript prints, one per outcome.
const (
	WorkdirMarkerOK      = "CBR_WORKDIR_OK"
	WorkdirMarkerMissing = "CBR_WORKDIR_MISSING"
	WorkdirMarkerNotDir  = "CBR_WORKDIR_NOTDIR"
	WorkdirMarkerNoEnter = "CBR_WORKDIR_NOENTER"
)

// WorkdirPath is the absolute directory a run with workdir starts in under home.
func WorkdirPath(home, workdir string) string {
	return strings.TrimSuffix(home, "/") + "/" + workdir
}

// WorkdirCheckScript reports, as the user it runs as, whether abs is a
// directory that user can enter. It changes nothing, always exits 0 and prints
// one marker.
func WorkdirCheckScript(abs string) string {
	return "p=" + ShellQuoteSingle(abs) + "\n" +
		"if [ ! -e \"$p\" ]; then echo " + WorkdirMarkerMissing + "\n" +
		"elif [ ! -d \"$p\" ]; then echo " + WorkdirMarkerNotDir + "\n" +
		"elif ( cd \"$p\" ) 2>/dev/null; then echo " + WorkdirMarkerOK + "\n" +
		"else echo " + WorkdirMarkerNoEnter + "\n" +
		"fi\n"
}

// RunCwd is the directory a run started over SSH runs in, given the cwd its
// ProcessStart was handed, for session discovery: cwd itself, or home when cwd
// is empty (process_start's default is agent-box's own cwd, which over an SSH
// login is the home). Best-effort: if the box's login shell lands somewhere else,
// discovery finds no match and the session id stays absent, never a wrong one.
func RunCwd(home, cwd string) string {
	if cwd == "" {
		return home
	}
	return cwd
}

// ResolveWorkdir returns the directory a run started over this session (as the
// box's own user) starts in, for ProcessStart's cwd. An empty workdir is "":
// process_start's default, agent-box's own cwd, which over an SSH login is the
// home. Otherwise workdir must pass CleanHomeRelPath and name a directory under
// the box user's home that the box user can enter; the absolute path is
// returned.
//
// It changes nothing on the box, and a caller runs it before anything that
// does: process_start rotates a finished run of the same name aside and
// truncates its log before it fails on a cwd it cannot use.
func (s *Session) ResolveWorkdir(ctx context.Context, workdir string) (string, error) {
	if workdir == "" {
		return "", nil
	}
	if _, err := CleanHomeRelPath("workdir", workdir); err != nil {
		return "", err
	}
	home, err := s.HomeDir(ctx)
	if err != nil {
		return "", fmt.Errorf("check workdir %q: %w", workdir, err)
	}
	return checkWorkdir(ctx, s.ShellExec, home, workdir)
}

// checkWorkdir runs WorkdirCheckScript for home/workdir through shellExec and
// returns the absolute path when the directory can be used.
func checkWorkdir(ctx context.Context, shellExec shellExecFunc, home, workdir string) (string, error) {
	abs := WorkdirPath(home, workdir)
	out, err := shellStdout(shellExec(ctx, WorkdirCheckScript(abs)))
	if err != nil {
		return "", fmt.Errorf("check workdir %q: %w", workdir, err)
	}
	switch strings.TrimSpace(out) {
	case WorkdirMarkerOK:
		return abs, nil
	case WorkdirMarkerMissing:
		return "", fmt.Errorf("workdir %q does not exist in the box user's home (%s); it is not created", workdir, home)
	case WorkdirMarkerNotDir:
		return "", fmt.Errorf("workdir %q in the box user's home (%s) is not a directory", workdir, home)
	case WorkdirMarkerNoEnter:
		return "", fmt.Errorf("workdir %q in the box user's home (%s) cannot be entered by the box user", workdir, home)
	default:
		return "", fmt.Errorf("check workdir %q: unexpected output %q", workdir, out)
	}
}
