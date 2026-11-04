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

// ErrSkillSetsApplyMarkerNotCleared (stub, #3540).
var ErrSkillSetsApplyMarkerNotCleared = errors.New("a stale skill-set apply marker could not be removed")

// shellExecFunc runs a command on the box as the box user and returns
// agent-box's shell_exec reply (Session.ShellExec).
type shellExecFunc func(context.Context, string) (string, error)

// applyMarkerAgeLimit bounds the "started ... ago" a refusal states: a start
// time ahead of the box clock or further back than this is not one the
// message can vouch for, so the age is left out.
const applyMarkerAgeLimit = 24 * time.Hour

// GuardSkillSetsApply checks the skill-set apply marker as the box user before
// a run launches. A held marker is ErrSkillSetsApplyInProgress naming the
// apply. A stale one (its lease lapsed, or it cannot be read) is removed and
// reported in warning, and the run goes ahead. When the clear finds the marker
// is no longer the stale one it read (a new apply took it in between), it
// checks again, so the new apply's marker refuses the run. A check that cannot
// run refuses the start: a run that did not look is not known to be safe.
func GuardSkillSetsApply(ctx context.Context, shellExec func(context.Context, string) (string, error)) (warning string, err error) {
	// Each pass either decides or saw its stale marker replaced; three
	// replacements in a row is not a box that will settle.
	for range 3 {
		c, err := checkApplyMarker(ctx, shellExec)
		if err != nil {
			return "", err
		}
		switch c.Status {
		case sdlcskills.ApplyMarkerAbsent:
			return "", nil
		case sdlcskills.ApplyMarkerHeld:
			return "", applyInProgressError(c, "")
		}
		script, err := sdlcskills.ApplyMarkerClearStaleScript(c.ID)
		if err != nil {
			return "", fmt.Errorf("clear a stale skill-set apply marker: %w", err)
		}
		out, err := shellStdout(shellExec(ctx, script))
		if err != nil {
			return "", fmt.Errorf("clear a stale skill-set apply marker: %w", err)
		}
		cleared, err := sdlcskills.ParseApplyMarkerCleared(out)
		if err != nil {
			return "", fmt.Errorf("clear a stale skill-set apply marker: %w", err)
		}
		if cleared == sdlcskills.ApplyMarkerClearRemoved {
			return fmt.Sprintf("cleared a stale skill-set apply marker (~/.claude/skills/%s): %s", sdlcskills.ApplyMarkerFile, c.Why), nil
		}
	}
	return "", fmt.Errorf("%w: the apply marker (~/.claude/skills/%s) kept changing while a stale one was being cleared; retry the run", ErrSkillSetsApplyInProgress, sdlcskills.ApplyMarkerFile)
}

// checkApplyMarker reads and classifies the marker.
func checkApplyMarker(ctx context.Context, shellExec shellExecFunc) (sdlcskills.ApplyMarkerCheck, error) {
	out, err := shellStdout(shellExec(ctx, sdlcskills.ApplyMarkerCheckScript()))
	if err != nil {
		return sdlcskills.ApplyMarkerCheck{}, fmt.Errorf("check for a skill-set apply in progress: %w", err)
	}
	c, err := sdlcskills.ParseApplyMarkerCheck(out)
	if err != nil {
		return sdlcskills.ApplyMarkerCheck{}, fmt.Errorf("check for a skill-set apply in progress: %w", err)
	}
	return c, nil
}

// applyInProgressError is the refusal for a held marker; note, when set, says
// what happened to a run that had already started.
func applyInProgressError(c sdlcskills.ApplyMarkerCheck, note string) error {
	what := "ApplyBoxSkillSets in progress"
	if age := c.Now - c.Marker.StartedAt; c.Marker.StartedAt > 0 && age >= 0 && age <= int64(applyMarkerAgeLimit/time.Second) {
		what = fmt.Sprintf("ApplyBoxSkillSets started %s ago", time.Duration(age)*time.Second)
	}
	return fmt.Errorf("%w (%s, ~/.claude/skills/%s)%s; a run does not start while its skills are being changed. Retry once the apply has returned",
		ErrSkillSetsApplyInProgress, what, sdlcskills.ApplyMarkerFile, note)
}

// recheckSkillSetsApplyAfterStart closes the window between GuardSkillSetsApply
// and the run's record (#3529): an apply that took the marker after the check
// but ran its run-in-progress check before agent-box recorded the run did not
// see the run. agent-box writes the record before process_start returns, so
// either that apply saw the run (and refused), or its marker was already
// written when the record was, and this re-check sees it: the run is stopped
// (forced, its log kept) and refused. A re-check that cannot run leaves the
// run going with a note in warning; the check before the start passed.
func (s *Session) recheckSkillSetsApplyAfterStart(ctx context.Context, name string) (warning string, err error) {
	c, err := checkApplyMarker(ctx, s.ShellExec)
	if err != nil {
		return fmt.Sprintf("could not re-check for a skill-set apply after the start: %v", err), nil
	}
	if c.Status != sdlcskills.ApplyMarkerHeld {
		return "", nil
	}
	if _, kerr := s.ProcessKill(ctx, name, true); kerr != nil {
		return "", applyInProgressError(c, fmt.Sprintf("; the run %q had just started and could not be stopped: %v", name, kerr))
	}
	return "", applyInProgressError(c, fmt.Sprintf("; the run %q had just started and was stopped (its log is kept)", name))
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
