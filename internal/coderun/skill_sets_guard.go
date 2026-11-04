package coderun

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/footprintai/containarium/pkg/core/sdlcskills"
)

// ErrSkillSetsApplyInProgress: an ApplyBoxSkillSets is changing the box's
// skills, so a run started over SSH does not start (#3529). The daemon refuses
// its own run starts with APPLY_IN_PROGRESS (#3510); this is the same refusal
// for the SSH path, read from the marker the apply holds in the box owner's
// tree (sdlcskills.ApplyMarkerFile) rather than from the daemon.
var ErrSkillSetsApplyInProgress = errors.New("skill sets are being applied on this box")

// GuardSkillSetsApply checks the skill-set apply marker as the box user before
// a run launches. shellExec runs a command on the box and returns agent-box's
// shell_exec reply (Session.ShellExec). A held marker is
// ErrSkillSetsApplyInProgress naming the apply. A stale one (its lease lapsed,
// or it cannot be read) is removed and reported in warning, and the run goes
// ahead. A check that cannot run refuses the start: a run that did not look
// is not known to be safe.
func GuardSkillSetsApply(ctx context.Context, shellExec func(context.Context, string) (string, error)) (warning string, err error) {
	out, err := shellStdout(shellExec(ctx, sdlcskills.ApplyMarkerCheckScript()))
	if err != nil {
		return "", fmt.Errorf("check for a skill-set apply in progress: %w", err)
	}
	c, err := sdlcskills.ParseApplyMarkerCheck(out)
	if err != nil {
		return "", fmt.Errorf("check for a skill-set apply in progress: %w", err)
	}
	switch c.Status {
	case sdlcskills.ApplyMarkerHeld:
		return "", fmt.Errorf("%w (ApplyBoxSkillSets started %s ago, ~/.claude/skills/%s); a run does not start while its skills are being changed. Retry once the apply has returned",
			ErrSkillSetsApplyInProgress, time.Duration(c.Now-c.Marker.StartedAt)*time.Second, sdlcskills.ApplyMarkerFile)
	case sdlcskills.ApplyMarkerStale:
		if _, err := shellStdout(shellExec(ctx, sdlcskills.ApplyMarkerClearStaleScript(c.Raw))); err != nil {
			return "", fmt.Errorf("clear a stale skill-set apply marker: %w", err)
		}
		return fmt.Sprintf("cleared a stale skill-set apply marker (~/.claude/skills/%s): %s", sdlcskills.ApplyMarkerFile, c.Why), nil
	}
	return "", nil
}

// shellStdout reads a shell_exec reply's stdout, failing on a call error or a
// non-zero exit.
func shellStdout(reply string, err error) (string, error) {
	if err != nil {
		return "", err
	}
	head, rest, ok := strings.Cut(reply, "--- stdout ---\n")
	if !ok {
		return "", fmt.Errorf("unexpected shell_exec reply %q", reply)
	}
	stdout, stderr, _ := strings.Cut(rest, "\n--- stderr ---\n")
	kv, _ := parseKV(head, "")
	code, convErr := strconv.Atoi(kv["exit_code"])
	if convErr != nil || code != 0 {
		return "", fmt.Errorf("exit %s: %s", kv["exit_code"], strings.TrimSpace(stderr))
	}
	return stdout, nil
}
