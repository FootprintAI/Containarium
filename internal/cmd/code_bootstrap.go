package cmd

import (
	"context"
	"errors"
	"fmt"

	"github.com/footprintai/containarium/internal/coderun"
	"github.com/footprintai/containarium/internal/connectcore"
)

// Applying a bootstrap bundle (#2030, #3512). A bundle URL handed out by a
// control plane is typically one-shot, and fetching it may rotate the box's
// delivered credential, so the bundle step is built around one question: was
// the URL consumed? The preflight answers "no, and nothing will be" before
// the URL is used; the bundle script's exit code answers it afterwards.

// Exit codes of bootstrapScript: the shared script's (internal/coderun), so
// the CLI and the daemon's ApplyBoxBootstrap report the same codes.
const (
	bootstrapExitFetch        = coderun.BootstrapExitFetch
	bootstrapExitBundle       = coderun.BootstrapExitBundle
	bootstrapExitApply        = coderun.BootstrapExitApply
	bootstrapExitFetchReached = coderun.BootstrapExitFetchReached
)

// Exit codes of bootstrapPreflightScript, one per thing bootstrapScript is
// about to need.
const (
	preflightExitHome  = 10 // $HOME is not writable
	preflightExitTmp   = 11 // no temporary directory can be created
	preflightExitTools = 12 // curl or tar is missing
)

// bootstrapScript is the shared bundle step (coderun.BootstrapScript): the
// same script the daemon's ApplyBoxBootstrap runs.
func bootstrapScript(url string) string { return coderun.BootstrapScript(url) }

// bootstrapPreflightScript checks exactly what bootstrapScript is about to
// need, and changes nothing on the box.
func bootstrapPreflightScript() string {
	return `test -w "$HOME" || exit 10
d="$(mktemp -d)" || exit 11
rmdir "$d" || exit 11
command -v curl >/dev/null 2>&1 || exit 12
command -v tar >/dev/null 2>&1 || exit 12`
}

// bootstrapPreflight is one silent SSH round trip, under kw, that confirms
// the box is reachable, accepts the key, and can run the bundle step, BEFORE
// the bundle URL is used (or, for `code bootstrap --url-cmd`, requested). A
// failure here means nothing was requested or applied.
func bootstrapPreflight(ctx context.Context, kw connectcore.KeyWait, target connectcore.Target, privPath, box string) error {
	args := probeSSHArgsCmd(connectcore.BuildSSHArgs(target, privPath, ""), bootstrapPreflightScript())
	err := waitForKeyByProbe(ctx, kw, args)
	if err == nil {
		return nil
	}
	reason := "the box could not be reached over SSH"
	var re *remoteExitError
	if errors.As(err, &re) {
		switch re.code {
		case preflightExitHome:
			reason = "$HOME is not writable for the box user"
		case preflightExitTmp:
			reason = "no temporary directory can be created on the box"
		case preflightExitTools:
			reason = "curl or tar is missing on the box"
		default:
			reason = "the preflight check failed on the box"
		}
	}
	return fmt.Errorf("bootstrap preflight on %q: %s; nothing was requested or applied: %w", box, reason, err)
}

// applyBootstrapBundle runs bootstrapScript(url) through run and turns its
// exit code into a message that says whether the URL was consumed.
func applyBootstrapBundle(box, url string, run func(string) (string, error)) error {
	_, err := run(bootstrapScript(url))
	if err == nil {
		return nil
	}
	var re *remoteExitError
	if errors.As(err, &re) {
		switch re.code {
		case bootstrapExitFetch:
			return fmt.Errorf("fetch bootstrap bundle on %q failed: the server was not reached, so the URL was not consumed, retry is safe: %w", box, err)
		case bootstrapExitFetchReached:
			return fmt.Errorf("fetch bootstrap bundle on %q failed after reaching the server: the URL may already be consumed; "+
				"if a retry fails, request a new URL and re-run: %w", box, err)
		case bootstrapExitBundle, bootstrapExitApply:
			what := "its apply.sh failed"
			if re.code == bootstrapExitBundle {
				what = "it is not a .tar.gz with an apply.sh at its root"
			}
			return fmt.Errorf("apply bootstrap bundle on %q: the bundle was fetched but %s; the one-shot URL is spent "+
				"(a control plane may have rotated the box's credential on fetch), request a new URL and re-run: %w", box, what, err)
		}
	}
	return fmt.Errorf("apply bootstrap bundle on %q: %w", box, err)
}
