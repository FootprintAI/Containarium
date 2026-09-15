package container

import (
	"fmt"
	"strings"
)

// DefaultWorkspacePath is where git source lands in the box when the
// caller doesn't specify one. Matches the convention the CI flow
// (containarium-run) and the agent-box already assume. Exported so
// RunAgentSkill's git-source path (#1859) can report the same default in its
// response without duplicating the string.
const DefaultWorkspacePath = "/workspace"

// gitWorkspacePath returns the workspace path, defaulting to
// /workspace when the caller left it empty.
func gitWorkspacePath(p string) string {
	if strings.TrimSpace(p) == "" {
		return DefaultWorkspacePath
	}
	return p
}

// shellSingleQuote wraps s in single quotes for safe interpolation
// into a /bin/sh -c script, escaping any embedded single quotes.
// Used so a caller-supplied repo URL / ref / workspace path can't
// break out of string context in the fetch script.
func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// buildGitFetchScript returns the /bin/sh script the daemon runs
// inside the box to populate the workspace from a git remote.
//
// Design notes:
//   - The box base image may lack git; the script installs it via
//     whatever package manager is present before fetching.
//   - A shallow fetch of the exact ref keeps it fast + reproducible.
//     Empty ref fetches the remote's default branch (FETCH_HEAD).
//   - A private-repo credential is injected as an ephemeral
//     `http.extraHeader` on the single fetch invocation — it is
//     never written to the repo's .git/config, so it doesn't persist
//     in the box after provisioning. (Matches how actions/checkout
//     scopes its token, minus the on-disk config write.)
//   - All caller-supplied values are single-quoted to prevent shell
//     injection.
func buildGitFetchScript(repoURL, ref, credential, workspacePath string) string {
	ws := gitWorkspacePath(workspacePath)

	var fetch strings.Builder
	fetch.WriteString("git ")
	if credential != "" {
		// The header value carries the token; quote it as one arg.
		hdr := "AUTHORIZATION: bearer " + credential
		fetch.WriteString("-c http.extraHeader=" + shellSingleQuote(hdr) + " ")
	}
	fetch.WriteString("fetch --depth 1 -q " + shellSingleQuote(repoURL))
	if ref != "" {
		fetch.WriteString(" " + shellSingleQuote(ref))
	}

	// `set -e` so any step failing aborts with a non-zero exit the
	// daemon surfaces. git install is best-effort across apt/dnf/yum.
	return strings.Join([]string{
		"set -e",
		`if ! command -v git >/dev/null 2>&1; then`,
		`  (apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq git) \`,
		`    || (dnf install -y -q git) || (yum install -y -q git) \`,
		`    || { echo "git unavailable and auto-install failed" >&2; exit 1; }`,
		`fi`,
		"mkdir -p " + shellSingleQuote(ws),
		"cd " + shellSingleQuote(ws),
		"git init -q",
		fetch.String(),
		"git checkout -q FETCH_HEAD",
		// Last line of stdout on success: the caller (FetchGitSource) reads
		// it back as the resolved commit, so a response can cite exactly
		// what was checked out.
		"git rev-parse HEAD",
	}, "\n")
}

// GitSourceSpec is what a caller knows about the repo it wants fetched into
// an existing, running box. Mirrors CreateOptions' git-source fields so a
// second caller (a skill run, #1859) doesn't need CreateOptions' unrelated
// create-time fields.
type GitSourceSpec struct {
	Source        string // clone URL, e.g. "https://github.com/org/repo"
	Ref           string // SHA / branch / tag / "refs/pull/N/merge"; empty = default branch
	Credential    string // bearer token for private repos; used for one fetch, never persisted
	WorkspacePath string // where to place source; empty defaults to "/workspace"
}

// FetchGitSource shallow-fetches spec.Ref into spec.WorkspacePath inside an
// existing, running box (via incus exec — no caller→box SSH) and returns the
// resolved commit SHA. The credential appears only on the fetch script's
// http.extraHeader arg, sent straight to the box; it is never included in a
// returned error, which carries only the box's stderr/stdout.
func (m *Manager) FetchGitSource(containerName string, spec GitSourceSpec) (string, error) {
	script := buildGitFetchScript(spec.Source, spec.Ref, spec.Credential, spec.WorkspacePath)
	stdout, stderr, err := m.incus.ExecWithOutput(containerName, []string{"/bin/sh", "-c", script})
	if err != nil {
		// Surface the box-side stderr (credential-free: the token only
		// ever appears in the script's http.extraHeader arg, not in
		// git's diagnostic output) so the failure is actionable.
		msg := strings.TrimSpace(stderr)
		if msg == "" {
			msg = strings.TrimSpace(stdout)
		}
		return "", fmt.Errorf("git fetch in box failed: %w: %s", err, msg)
	}
	return lastNonEmptyLine(stdout), nil
}

// lastNonEmptyLine returns the trailing non-blank line of s, trimmed. Used to
// pull the `git rev-parse HEAD` result off the end of the fetch script's
// stdout without depending on how much else the box's git/package-manager
// install steps printed before it.
func lastNonEmptyLine(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if line := strings.TrimSpace(lines[i]); line != "" {
			return line
		}
	}
	return ""
}

// provisionGitSource fetches opts.GitSource into the box's workspace. Thin
// wrapper over FetchGitSource so CreateContainer's create-time path and
// RunAgentSkill's per-run path (#1859) share one fetch implementation.
func (m *Manager) provisionGitSource(containerName string, opts CreateOptions) error {
	_, err := m.FetchGitSource(containerName, GitSourceSpec{
		Source:        opts.GitSource,
		Ref:           opts.GitRef,
		Credential:    opts.GitCredential,
		WorkspacePath: opts.WorkspacePath,
	})
	return err
}
