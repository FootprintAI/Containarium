package submit

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The tests in this file close the gap #2271 describes: the other
// integration tests push to a local file:// bare repository, which has no
// notion of authentication at all, so nothing there can tell whether the
// credential header PushBundle sends would be accepted by GitHub. Here
// the remote is a smart-HTTP git server (git-http-backend behind
// httptest) fronted by a gate that enforces GitHub's documented
// git-over-HTTPS auth rules for the credential shape under test, and
// rejects everything else with a 401 — the same response GitHub's git
// servers give an unaccepted credential.

// githubAuthRule reports whether a request's Authorization header is a
// form GitHub accepts for one specific credential.
type githubAuthRule func(r *http.Request) bool

// installationTokenRule is GitHub's documented form for a GitHub App
// installation token (ghs_…) over git HTTPS: Basic auth with the literal
// username "x-access-token" and the token as the password. A bearer
// header carrying the token is NOT accepted.
func installationTokenRule(token string) githubAuthRule {
	return func(r *http.Request) bool {
		user, pass, ok := r.BasicAuth()
		return ok && user == "x-access-token" && pass == token
	}
}

// patRule is what GitHub accepts for a personal access token: Basic auth
// with the token as the password, or the token as a bearer header —
// the form PushBundle has always sent for PATs.
func patRule(token string) githubAuthRule {
	return func(r *http.Request) bool {
		if _, pass, ok := r.BasicAuth(); ok {
			return pass == token
		}
		scheme, value, ok := strings.Cut(r.Header.Get("Authorization"), " ")
		return ok && strings.EqualFold(scheme, "bearer") && value == token
	}
}

// authGitServer is a smart-HTTP git server serving every repository
// under root, behind a githubAuthRule gate.
type authGitServer struct {
	*httptest.Server

	mu       sync.Mutex
	rejected int
	accepted int
}

func newAuthGitServer(t *testing.T, root string, allow githubAuthRule) *authGitServer {
	t.Helper()
	execPath := testGit(t, root, "--exec-path")
	backend := filepath.Join(execPath, "git-http-backend")
	if _, err := os.Stat(backend); err != nil {
		t.Skipf("git-http-backend not available at %s: %v", backend, err)
	}

	s := &authGitServer{}
	cgiHandler := &cgi.Handler{
		Path: backend,
		Env: []string{
			"GIT_PROJECT_ROOT=" + root,
			"GIT_HTTP_EXPORT_ALL=1",
			"GIT_CONFIG_NOSYSTEM=1",
			"GIT_CONFIG_GLOBAL=/dev/null",
		},
		InheritEnv: []string{"PATH"},
	}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allow(r) {
			s.mu.Lock()
			s.rejected++
			s.mu.Unlock()
			w.Header().Set("WWW-Authenticate", `Basic realm="GitHub"`)
			http.Error(w, "Invalid username or token.", http.StatusUnauthorized)
			return
		}
		s.mu.Lock()
		s.accepted++
		s.mu.Unlock()
		cgiHandler.ServeHTTP(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *authGitServer) counts() (accepted, rejected int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accepted, s.rejected
}

// authPushFixture is a served bare "origin" with one base commit on
// main, plus a bundle of one new commit on top of it — the same shape
// TestGitPusher_RealGit_PushesToLocalBareRemote builds, but under a
// served project root.
type authPushFixture struct {
	root       string // GIT_PROJECT_ROOT
	originDir  string
	baseSHA    string
	headSHA    string
	bundlePath string
}

func newAuthPushFixture(t *testing.T) authPushFixture {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	root := t.TempDir()
	served := filepath.Join(root, "served")
	originDir := filepath.Join(served, "acme", "widgets.git")
	workDir := filepath.Join(root, "work")
	for _, d := range []string{filepath.Dir(originDir), workDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	testGit(t, root, "init", "--bare", "-q", originDir)
	// git-http-backend refuses receive-pack unless it is enabled
	// explicitly (or REMOTE_USER is set); the auth gate in front of it
	// is what decides who may push.
	testGit(t, originDir, "config", "http.receivepack", "true")

	testGit(t, workDir, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(workDir, "README.md"), []byte("base\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	testGit(t, workDir, "add", "README.md")
	testGit(t, workDir, "commit", "-q", "-m", "base commit")
	baseSHA := testGit(t, workDir, "rev-parse", "HEAD")
	testGit(t, workDir, "push", "-q", originDir, "main")

	if err := os.WriteFile(filepath.Join(workDir, "feature.txt"), []byte("new work\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	testGit(t, workDir, "add", "feature.txt")
	testGit(t, workDir, "commit", "-q", "-m", "agent's change")
	headSHA := testGit(t, workDir, "rev-parse", "HEAD")

	bundlePath := filepath.Join(root, "out.bundle")
	testGit(t, workDir, "bundle", "create", bundlePath, baseSHA+"..HEAD")

	return authPushFixture{
		root:       served,
		originDir:  originDir,
		baseSHA:    baseSHA,
		headSHA:    headSHA,
		bundlePath: bundlePath,
	}
}

func (f authPushFixture) spec(remoteURL, credential string) PushSpec {
	return PushSpec{
		BundlePath:  f.bundlePath,
		BaseSHA:     f.baseSHA,
		HeadSHA:     f.headSHA,
		RemoteURL:   remoteURL,
		Credential:  credential,
		RunID:       "run-auth-integration-0001",
		IssueNumber: 2271,
		Title:       "Auth form integration test",
	}
}

// assertBranchLanded confirms the pushed branch is on the origin at the
// bundle's head, and main is untouched.
func (f authPushFixture) assertBranchLanded(t *testing.T, result PushResult) {
	t.Helper()
	got := testGit(t, f.root, "ls-remote", f.originDir, "refs/heads/"+result.Branch)
	if !strings.HasPrefix(got, f.headSHA) {
		t.Errorf("remote ref for %s = %q, want it to start with %s", result.Branch, got, f.headSHA)
	}
	gotMain := testGit(t, f.root, "ls-remote", f.originDir, "refs/heads/main")
	if !strings.HasPrefix(gotMain, f.baseSHA) {
		t.Errorf("remote main moved: %q, want it to still start with %s", gotMain, f.baseSHA)
	}
}

const (
	// Credential-shaped test values (not real tokens): the prefixes are
	// GitHub's documented ones — ghs_ for an App installation token,
	// ghp_ for a classic PAT.
	testInstallationToken = "ghs_16C7e42F292c6912E7710c838347Ae178B4a"
	testPAT               = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"
)

// TestAuthGitServer_EnforcesInstallationTokenForm proves the test server
// is a real gate, not a pass-through: for an installation token it
// rejects the bearer header form (what PushBundle sent before #2271),
// rejects no credential at all, and rejects Basic auth with the wrong
// username — and accepts only x-access-token:<token>. Without this, a
// green TestGitPusher_InstallationToken_PushesWithDocumentedAuthForm
// would prove nothing.
func TestAuthGitServer_EnforcesInstallationTokenForm(t *testing.T) {
	f := newAuthPushFixture(t)
	srv := newAuthGitServer(t, f.root, installationTokenRule(testInstallationToken))
	remote := srv.URL + "/acme/widgets.git"

	lsRemote := func(extraHeader string) error {
		args := []string{}
		if extraHeader != "" {
			args = append(args, "-c", "http.extraHeader="+extraHeader)
		}
		args = append(args, "ls-remote", remote)
		cmd := exec.Command("git", args...) // #nosec G204 -- test-only, test-built argv.
		cmd.Env = []string{
			"HOME=" + t.TempDir(),
			"GIT_CONFIG_NOSYSTEM=1",
			"GIT_CONFIG_GLOBAL=/dev/null",
			"GIT_TERMINAL_PROMPT=0",
			"PATH=" + os.Getenv("PATH"),
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("ls-remote with header %q: %v\n%s", extraHeader, err, out)
		}
		return err
	}

	for _, tc := range []struct {
		name   string
		header string
	}{
		{"no credential", ""},
		{"bearer header (pre-#2271 form)", "AUTHORIZATION: bearer " + testInstallationToken},
		{"basic with wrong username", basicHeader("oauth2", testInstallationToken)},
		{"basic with wrong token", basicHeader("x-access-token", "ghs_wrong")},
	} {
		t.Run("rejects "+tc.name, func(t *testing.T) {
			_, rejectedBefore := srv.counts()
			if err := lsRemote(tc.header); err == nil {
				t.Fatalf("ls-remote with %s succeeded; the server must reject it", tc.name)
			}
			if _, rejectedAfter := srv.counts(); rejectedAfter <= rejectedBefore {
				t.Errorf("server did not record a rejection for %s", tc.name)
			}
		})
	}

	t.Run("accepts x-access-token basic auth", func(t *testing.T) {
		if err := lsRemote(basicHeader("x-access-token", testInstallationToken)); err != nil {
			t.Fatalf("ls-remote with the documented form failed: %v", err)
		}
	})
}

// TestGitPusher_InstallationToken_PushesWithDocumentedAuthForm is #2271's
// "Done means": PushBundle, given a ghs_ installation token, pushes
// successfully through a server enforcing GitHub's documented
// installation-token auth form.
func TestGitPusher_InstallationToken_PushesWithDocumentedAuthForm(t *testing.T) {
	f := newAuthPushFixture(t)
	srv := newAuthGitServer(t, f.root, installationTokenRule(testInstallationToken))

	result, err := NewGitPusher().PushBundle(context.Background(),
		f.spec(srv.URL+"/acme/widgets.git", testInstallationToken))
	if err != nil {
		t.Fatalf("PushBundle with an installation token: %v", err)
	}
	if accepted, rejected := srv.counts(); accepted == 0 || rejected != 0 {
		t.Errorf("server accepted=%d rejected=%d; want every request accepted on the first try", accepted, rejected)
	}
	f.assertBranchLanded(t, result)
}

// TestGitPusher_PAT_PushUnchanged pins that PAT pushes still succeed
// against a server enforcing what GitHub accepts for a PAT — #2271 must
// not change PAT behaviour.
func TestGitPusher_PAT_PushUnchanged(t *testing.T) {
	f := newAuthPushFixture(t)
	srv := newAuthGitServer(t, f.root, patRule(testPAT))

	result, err := NewGitPusher().PushBundle(context.Background(),
		f.spec(srv.URL+"/acme/widgets.git", testPAT))
	if err != nil {
		t.Fatalf("PushBundle with a PAT: %v", err)
	}
	if accepted, rejected := srv.counts(); accepted == 0 || rejected != 0 {
		t.Errorf("server accepted=%d rejected=%d; want every request accepted on the first try", accepted, rejected)
	}
	f.assertBranchLanded(t, result)
}

// basicHeader builds an http.extraHeader value carrying Basic auth —
// built independently of the package's own header code so the gate test
// does not merely agree with itself.
func basicHeader(user, pass string) string {
	return "AUTHORIZATION: Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}
