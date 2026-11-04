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

// Exit codes of bootstrapScript. Anything else (ssh failing mid-run, mktemp
// failing) is reported without a claim either way.
const (
	// bootstrapExitFetch: the download failed, so the URL was not consumed.
	bootstrapExitFetch = 3
	// bootstrapExitBundle: the bundle was fetched but is not a .tar.gz with
	// an apply.sh at its root.
	bootstrapExitBundle = 4
	// bootstrapExitApply: the bundle was fetched and its apply.sh failed.
	bootstrapExitApply = 5
)

// Exit codes of bootstrapPreflightScript, one per thing bootstrapScript is
// about to need.
const (
	preflightExitHome  = 10 // $HOME is not writable
	preflightExitTmp   = 11 // no temporary directory can be created
	preflightExitTools = 12 // curl or tar is missing
)

// bootstrapScript fetches url to a file, unpacks it into a throwaway
// directory, and runs its apply.sh from there as the box user: the seam a
// team uses to drop in skills, an MCP config, or dotfiles without this
// command growing a flag per item. No sudo anywhere: a bootstrap bundle is
// the user's own content and gets the user's own privileges.
//
// Fetch and apply are separate steps with their own exit codes, so a failed
// download (the URL was not consumed) is never confused with a failed apply
// (it was). The URL is never echoed: curl runs without -S, so its own error
// text (which names the URL's path) is suppressed. `--` keeps a URL that
// starts with "-" from being read as a curl option.
func bootstrapScript(url string) string {
	return `set -e
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
if ! curl -fsL -o "$tmp/bundle.tgz" -- ` + coderun.ShellQuoteSingle(url) + ` </dev/null; then
  echo "bootstrap bundle could not be fetched" >&2
  exit 3
fi
bundle_error() {
  echo "bootstrap bundle is not a .tar.gz with an apply.sh at its root" >&2
  exit 4
}
mkdir "$tmp/bundle" || bundle_error
if ! tar -xzf "$tmp/bundle.tgz" -C "$tmp/bundle" || [ ! -f "$tmp/bundle/apply.sh" ]; then
  bundle_error
fi
chmod +x "$tmp/bundle/apply.sh" || bundle_error
cd "$tmp/bundle" || bundle_error
if ! ./apply.sh; then
  echo "bootstrap bundle's apply.sh failed" >&2
  exit 5
fi`
}

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
			return fmt.Errorf("fetch bootstrap bundle on %q failed: the URL was not consumed, retry is safe: %w", box, err)
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
