package cmd

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/connectcore"
	"github.com/footprintai/containarium/internal/credentials"
)

// --- bootstrap bundle: fetch and apply are told apart (#3512) --------------

// writeBundle writes a .tar.gz holding files (name -> content, mode 0755 for
// names ending in .sh) to dir/name and returns its path.
func writeBundle(t *testing.T, dir, name string, files map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for n, content := range files {
		mode := int64(0o644)
		if strings.HasSuffix(n, ".sh") {
			mode = 0o755
		}
		if err := tw.WriteHeader(&tar.Header{Name: n, Mode: mode, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// runBootstrapScript executes bootstrapScript(url) with the local sh against a
// throwaway HOME and returns the exit code and the HOME it ran in.
func runBootstrapScript(t *testing.T, url string) (int, string, string) {
	t.Helper()
	for _, bin := range []string{"curl", "tar"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not on PATH: the script under test needs it", bin)
		}
	}
	home := t.TempDir()
	path := filepath.Join(t.TempDir(), "bootstrap.sh")
	if err := os.WriteFile(path, []byte(bootstrapScript(url)), 0o600); err != nil {
		t.Fatal(err)
	}
	c := exec.Command("/bin/sh", path) // #nosec G204 -- fixed interpreter, package-built script
	c.Env = append(os.Environ(), "HOME="+home)
	var stderr bytes.Buffer
	c.Stderr = &stderr
	err := c.Run()
	if err == nil {
		return 0, home, stderr.String()
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("run bootstrap script: %v", err)
	}
	return ee.ExitCode(), home, stderr.String()
}

// TestBootstrapScript_ExitCodesSplitFetchFromApply runs the real script over
// file:// bundles: a fetch failure, a bundle with no apply.sh, an unreadable
// bundle, and a failing apply.sh each exit with their own code, so the CLI can
// tell "the URL was not consumed" from "the URL is spent".
func TestBootstrapScript_ExitCodesSplitFetchFromApply(t *testing.T) {
	dir := t.TempDir()
	good := writeBundle(t, dir, "good.tgz", map[string]string{
		"apply.sh": "#!/bin/sh\nset -e\ncat ./payload > \"$HOME/applied\"\n",
		"payload":  "hello from the bundle\n",
	})
	noApply := writeBundle(t, dir, "noapply.tgz", map[string]string{"README": "no apply here\n"})
	failing := writeBundle(t, dir, "failing.tgz", map[string]string{"apply.sh": "#!/bin/sh\nexit 7\n"})
	garbage := filepath.Join(dir, "garbage.tgz")
	if err := os.WriteFile(garbage, []byte("not a tarball"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		url  string
		want int
	}{
		{name: "fetch fails", url: "file://" + filepath.Join(dir, "missing-s3cr3t.tgz"), want: bootstrapExitFetch},
		// Without `--` before the URL, curl reads this as its --version option,
		// exits 0, and the script goes on to unpack nothing.
		{name: "URL that looks like an option", url: "--version", want: bootstrapExitFetch},
		{name: "bundle has no apply.sh", url: "file://" + noApply, want: bootstrapExitBundle},
		{name: "bundle is not a tar.gz", url: "file://" + garbage, want: bootstrapExitBundle},
		{name: "apply.sh fails", url: "file://" + failing, want: bootstrapExitApply},
		{name: "applies", url: "file://" + good, want: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, home, stderr := runBootstrapScript(t, tc.url)
			if code != tc.want {
				t.Fatalf("exit = %d, want %d\nstderr:\n%s", code, tc.want, stderr)
			}
			if tc.want == 0 {
				got, err := os.ReadFile(filepath.Join(home, "applied"))
				if err != nil || string(got) != "hello from the bundle\n" {
					t.Errorf("apply.sh did not run from the bundle root: %q, %v", got, err)
				}
			}
			// curl's own errors name the path of the URL ("Couldn't open file
			// /…/missing-s3cr3t.tgz"); the secret part of a one-shot URL lives
			// there, so check for the path, not only the full URL.
			leaks := []string{tc.url}
			if u, err := neturl.Parse(tc.url); err == nil && len(u.Path) > 1 {
				leaks = append(leaks, u.Path)
			}
			for _, leak := range leaks {
				if strings.Contains(stderr, leak) {
					t.Errorf("the script printed %q from the URL:\n%s", leak, stderr)
				}
			}
		})
	}
}

// --- preflight before the URL is used (#3512) ------------------------------

const testBundleURL = "https://bundles.example.test/one-shot/abc123.tar.gz"

func TestCodeInstall_BootstrapPreflightRunsBeforeAnyScript(t *testing.T) {
	var events []string
	var preflight []string
	_, _, _, err := runInstallWith(t, "alice", map[string]string{"bootstrap-url": testBundleURL}, installFakes{
		events: &events,
		probe: func(args []string) error {
			if preflight == nil {
				preflight = args
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if len(events) == 0 || events[0] != "probe" {
		t.Fatalf("first remote call = %v, want the preflight probe before any script", events)
	}
	joined := strings.Join(preflight, " ")
	for _, want := range []string{"BatchMode=yes", `test -w "$HOME"`, "mktemp -d", "command -v curl", "command -v tar"} {
		if !strings.Contains(joined, want) {
			t.Errorf("preflight is missing %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, testBundleURL) {
		t.Errorf("the preflight carries the URL:\n%s", joined)
	}
}

func TestCodeInstall_NoPreflightWithoutBootstrapURL(t *testing.T) {
	var events []string
	if _, _, _, err := runInstallWith(t, "alice", nil, installFakes{events: &events}); err != nil {
		t.Fatalf("install: %v", err)
	}
	for _, e := range events {
		if e == "probe" {
			t.Fatalf("an install with no --bootstrap-url ran a preflight probe: %v", events)
		}
	}
}

func TestCodeInstall_PreflightFailureRunsNothing(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		reason string
	}{
		{
			name:   "host unreachable",
			err:    &connectcore.SSHError{ExitCode: 255, Stderr: "ssh: connect to host box.example.test port 22: Connection timed out", Err: errors.New("exit status 255")},
			reason: "SSH",
		},
		{name: "home not writable", err: &remoteExitError{code: preflightExitHome}, reason: "not writable"},
		{name: "no temp dir", err: &remoteExitError{code: preflightExitTmp}, reason: "temporary directory"},
		{name: "curl or tar missing", err: &remoteExitError{code: preflightExitTools}, reason: "curl or tar"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runs, out, stderr, err := runInstallWith(t, "alice", map[string]string{"bootstrap-url": testBundleURL}, installFakes{
				probe: func([]string) error { return tc.err },
			})
			if err == nil {
				t.Fatal("install succeeded although the preflight failed")
			}
			if len(runs) != 0 {
				t.Errorf("%d scripts ran after a failed preflight", len(runs))
			}
			for _, want := range []string{"nothing was requested or applied", tc.reason, "alice"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not mention %q", err, want)
				}
			}
			if strings.Contains(err.Error()+out+stderr, testBundleURL) {
				t.Error("the URL was printed")
			}
		})
	}
}

func TestCodeInstall_BootstrapFailureSaysWhetherTheURLIsSpent(t *testing.T) {
	tests := []struct {
		name   string
		code   int
		want   []string
		absent string
	}{
		{name: "fetch failed", code: bootstrapExitFetch, want: []string{"not consumed", "retry is safe"}, absent: "spent"},
		{name: "no apply.sh", code: bootstrapExitBundle, want: []string{"spent", "request a new URL", "credential"}, absent: "retry is safe"},
		{name: "apply.sh failed", code: bootstrapExitApply, want: []string{"spent", "request a new URL", "credential"}, absent: "retry is safe"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, out, stderr, err := runInstallWith(t, "alice", map[string]string{"bootstrap-url": testBundleURL}, installFakes{
				exec: func(script string) (string, error) {
					if strings.Contains(script, "apply.sh") {
						return "", &remoteExitError{code: tc.code}
					}
					return "1.2.3 (Claude Code)\ncredential sources present:\n  (none)", nil
				},
			})
			if err == nil {
				t.Fatal("install succeeded although the bundle step failed")
			}
			for _, want := range append(tc.want, `"alice"`) {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not mention %q", err, want)
				}
			}
			if strings.Contains(err.Error(), tc.absent) {
				t.Errorf("error %q must not say %q", err, tc.absent)
			}
			if strings.Contains(err.Error()+out+stderr, testBundleURL) {
				t.Error("the URL was printed")
			}
		})
	}
}

// --- "box not found" names the scope that was searched (#3512) -------------

func TestGetContainer_NotFoundNamesServerAndOrg(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
	}))
	t.Cleanup(ts.Close)
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
	}))
	t.Cleanup(other.Close)

	home := withTempHome(t)
	_ = seedCreds(t, home, "", map[string]credentials.ServerCreds{
		ts.URL:    {Token: "eyJcloud", OrgID: "org-abc", UserEmail: "user@example.com"},
		other.URL: {Token: "eyJdaemon"},
	})

	withOrg := &connectAPI{hc: ts.Client(), server: ts.URL, token: "eyJcloud"}
	_, err := withOrg.GetContainer(context.Background(), "alice")
	if err == nil {
		t.Fatal("want a not-found error")
	}
	for _, want := range []string{`"alice"`, "not found on " + ts.URL, "org org-abc", "user@example.com", "containarium list", "containarium whoami --server " + ts.URL} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}

	noOrg := &connectAPI{hc: other.Client(), server: other.URL, token: "eyJdaemon"}
	_, err = noOrg.GetContainer(context.Background(), "alice")
	if err == nil {
		t.Fatal("want a not-found error")
	}
	for _, want := range []string{"not found on " + other.URL, "containarium list"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "org ") {
		t.Errorf("a server with no org id must not name one: %q", err)
	}

	// A --token / CONTAINARIUM_TOKEN override is not the stored login, so the
	// stored org and account are not the scope that was searched.
	override := &connectAPI{hc: ts.Client(), server: ts.URL, token: "eyJsomeone-else"}
	_, err = override.GetContainer(context.Background(), "alice")
	if err == nil {
		t.Fatal("want a not-found error")
	}
	if strings.Contains(err.Error(), "org-abc") || strings.Contains(err.Error(), "user@example.com") {
		t.Errorf("an override token must not report the stored login's identity: %q", err)
	}
	if !strings.Contains(err.Error(), "not found on "+ts.URL) {
		t.Errorf("error %q does not name the server", err)
	}
}
