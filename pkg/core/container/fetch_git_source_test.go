package container

import (
	"strings"
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// fakeExecBackend is a minimal incus.Backend that only implements
// ExecWithOutput, calling it directly via FetchGitSource (not through
// (*Manager).ExecWithOutput, which type-asserts to the concrete *incus.Client
// and so cannot be exercised against any fake). Every other Backend method is
// unimplemented on purpose — FetchGitSource must never call them.
type fakeExecBackend struct {
	incus.Backend
	gotContainer string
	gotCommand   []string
	stdout       string
	stderr       string
	err          error
}

func (b *fakeExecBackend) ExecWithOutput(containerName string, command []string) (string, string, error) {
	b.gotContainer = containerName
	b.gotCommand = command
	return b.stdout, b.stderr, b.err
}

func TestFetchGitSource_ReturnsResolvedCommit(t *testing.T) {
	backend := &fakeExecBackend{stdout: "some git output\nmore output\ndeadbeefcafe1234\n"}
	mgr := NewWithBackend(backend)

	commit, err := mgr.FetchGitSource("agent-code-review-container", GitSourceSpec{
		Source: "https://github.com/org/repo",
		Ref:    "main",
	})
	if err != nil {
		t.Fatalf("FetchGitSource: %v", err)
	}
	if commit != "deadbeefcafe1234" {
		t.Errorf("commit = %q, want the script's last stdout line", commit)
	}
	if backend.gotContainer != "agent-code-review-container" {
		t.Errorf("exec ran against %q, want the container name", backend.gotContainer)
	}
	if len(backend.gotCommand) != 3 || backend.gotCommand[0] != "/bin/sh" || backend.gotCommand[1] != "-c" {
		t.Errorf("command = %v, want [/bin/sh -c <script>]", backend.gotCommand)
	}
	script := backend.gotCommand[2]
	if !strings.Contains(script, "git rev-parse HEAD") {
		t.Errorf("script must print the resolved commit as its last line:\n%s", script)
	}
}

func TestFetchGitSource_ErrorSurfacesStderrNotCredential(t *testing.T) {
	backend := &fakeExecBackend{
		stderr: "fatal: could not read Username",
		err:    errTest,
	}
	mgr := NewWithBackend(backend)

	commit, err := mgr.FetchGitSource("agent-x-container", GitSourceSpec{
		Source:     "https://github.com/org/private",
		Credential: "super-secret-token",
	})
	if err == nil {
		t.Fatal("expected an error when the box exec fails")
	}
	if commit != "" {
		t.Errorf("commit = %q on error, want empty", commit)
	}
	if !strings.Contains(err.Error(), "fatal: could not read Username") {
		t.Errorf("error = %q, want the box's stderr surfaced", err.Error())
	}
	if strings.Contains(err.Error(), "super-secret-token") {
		t.Errorf("error must never contain the credential: %q", err.Error())
	}
}

func TestFetchGitSource_CredentialNeverInErrorEvenViaStdoutFallback(t *testing.T) {
	backend := &fakeExecBackend{
		stdout: "some stdout mentioning nothing sensitive",
		err:    errTest,
	}
	mgr := NewWithBackend(backend)

	_, err := mgr.FetchGitSource("agent-x-container", GitSourceSpec{
		Source:     "https://github.com/org/private",
		Credential: "super-secret-token",
	})
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "super-secret-token") {
		t.Errorf("error must never contain the credential: %q", err.Error())
	}
}

// errTest is a stand-in exec failure; its message is deliberately unrelated
// to any credential so the "must not leak" assertions above are meaningful.
var errTest = fetchTestError("exec failed")

type fetchTestError string

func (e fetchTestError) Error() string { return string(e) }

// TestProvisionGitSource_StillWorks pins that the existing CreateContainer
// call site (opts.GitSource/.GitRef/.GitCredential/.WorkspacePath) still
// fetches correctly now that it is a thin wrapper over FetchGitSource.
func TestProvisionGitSource_StillWorks(t *testing.T) {
	backend := &fakeExecBackend{stdout: "abc123\n"}
	mgr := NewWithBackend(backend)

	err := mgr.provisionGitSource("some-container", CreateOptions{
		GitSource: "https://github.com/org/repo",
		GitRef:    "v1.0.0",
	})
	if err != nil {
		t.Fatalf("provisionGitSource: %v", err)
	}
	if backend.gotContainer != "some-container" {
		t.Errorf("exec ran against %q, want %q", backend.gotContainer, "some-container")
	}
}
