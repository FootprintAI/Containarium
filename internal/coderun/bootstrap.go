package coderun

import (
	"encoding/json"
	"strconv"
	"strings"
)

// Applying a bootstrap bundle (#2030, #3512, #3694). A bundle URL handed out
// by a control plane is typically one-shot, and fetching it may rotate the
// box's delivered credential, so the bundle step is built around one question:
// was the URL consumed? The script's exit code answers it.
//
// The script lives here, not in internal/cmd, so `containarium code install
// --bootstrap-url` / `code bootstrap` (over SSH) and the daemon's
// ApplyBoxBootstrap RPC run the very same bytes.

// Exit codes of BootstrapScript. Anything else (the transport failing
// mid-run, mktemp failing) is reported without a claim either way.
const (
	// BootstrapExitFetch: the server was never reached (curl 5, 6, 7: proxy
	// or host not resolved, connection failed), so the URL was not consumed.
	BootstrapExitFetch = 3
	// BootstrapExitBundle: the bundle was fetched but is not a .tar.gz with
	// an apply.sh at its root.
	BootstrapExitBundle = 4
	// BootstrapExitApply: the bundle was fetched and its apply.sh failed.
	BootstrapExitApply = 5
	// BootstrapExitFetchReached: the download failed after the server was
	// reached (an HTTP error such as 404/410, a mid-transfer failure, or any
	// other curl error). A one-shot URL may already be marked used.
	BootstrapExitFetchReached = 6
)

// Stall bounds of the bundle fetch. They bound a server that stops sending,
// not the size of the bundle: a large bundle on a slow link still completes
// as long as it moves. A fetch cut off by either is curl exit 28, reported
// as BootstrapExitFetchReached (the URL may be consumed). Variables only so
// tests can shorten them.
var (
	// BootstrapConnectTimeoutSeconds bounds connecting to the bundle server.
	BootstrapConnectTimeoutSeconds = 30
	// BootstrapStallSeconds aborts a transfer slower than 1 byte/s for this
	// long (curl --speed-limit 1 --speed-time N).
	BootstrapStallSeconds = 60
)

// BootstrapScript fetches url to a file, unpacks it into a throwaway
// directory, and runs its apply.sh from there as the box user: the seam a
// team uses to drop in skills, an MCP config, or dotfiles without the CLI
// growing a flag per item. No sudo anywhere: a bootstrap bundle is the user's
// own content and gets the user's own privileges.
//
// Fetch and apply are separate steps with their own exit codes, so a download
// that never reached the server (the URL was not consumed) is told apart from
// one that did (it may have been) and from a failed apply (it was). The URL is
// never echoed: curl runs without -S, so its own error text (which names the
// URL's path) is suppressed and only its exit code is reported. `--` keeps a
// URL that starts with "-" from being read as a curl option.
func BootstrapScript(url string) string {
	return `set -e
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
rc=0
curl -fsL --connect-timeout ` + strconv.Itoa(BootstrapConnectTimeoutSeconds) + ` --speed-limit 1 --speed-time ` + strconv.Itoa(BootstrapStallSeconds) + ` -o "$tmp/bundle.tgz" -- ` + ShellQuoteSingle(url) + ` </dev/null || rc=$?
case "$rc" in
  0) ;;
  5|6|7)
    echo "bootstrap bundle server could not be reached (curl exit $rc)" >&2
    exit 3 ;;
  *)
    echo "bootstrap bundle fetch failed after reaching the server (curl exit $rc)" >&2
    exit 6 ;;
esac
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

// Exit codes of BootstrapPreflightScript, one per thing BootstrapScript is
// about to need.
const (
	PreflightExitHome  = 10 // $HOME is not writable
	PreflightExitTmp   = 11 // no temporary directory can be created
	PreflightExitTools = 12 // curl or tar is missing
)

// BootstrapPreflightScript checks exactly what BootstrapScript is about to
// need, as the user it will run as, and changes nothing on the box. It is
// run before the bundle URL is used, so a failure means nothing was
// requested or applied.
func BootstrapPreflightScript() string {
	return `test -w "$HOME" || exit 10
d="$(mktemp -d)" || exit 11
rmdir "$d" || exit 11
command -v curl >/dev/null 2>&1 || exit 12
command -v tar >/dev/null 2>&1 || exit 12`
}

// BootstrapManifestMarker separates whatever apply.sh printed from the copy
// of the bundle's manifest.json that BootstrapReportScript prints after it.
const BootstrapManifestMarker = "=== containarium bootstrap manifest ==="

// BootstrapReportScript is BootstrapScript followed, once apply.sh has
// succeeded, by the marker line and the bundle's own manifest.json (the
// manifest of the bundle just applied, read before the temp dir is removed).
// A bundle without a manifest.json prints the marker and nothing after it.
// The apply step itself is exactly BootstrapScript's.
func BootstrapReportScript(url string) string {
	return BootstrapScript(url) + `
printf '\n%s\n' '` + BootstrapManifestMarker + `'
cat "$tmp/bundle/manifest.json" 2>/dev/null || true`
}

// bootstrapManifest is the one field of a bundle's manifest.json the daemon
// reads back.
type bootstrapManifest struct {
	BundleRevision int32 `json:"bundle_revision"`
}

// ParseBootstrapReport returns the bundle_revision of the manifest that
// BootstrapReportScript printed after its marker. found is false when the
// output has no marker or the bundle carried no manifest.json; a manifest
// that is present but is not JSON is an error.
func ParseBootstrapReport(out string) (revision int32, found bool, err error) {
	i := strings.LastIndex(out, BootstrapManifestMarker+"\n")
	if i < 0 {
		return 0, false, nil
	}
	body := strings.TrimSpace(out[i+len(BootstrapManifestMarker)+1:])
	if body == "" {
		return 0, false, nil
	}
	var m bootstrapManifest
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		return 0, false, err
	}
	return m.BundleRevision, true, nil
}
