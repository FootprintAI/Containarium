package recipes

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Tests for agent-runtime/helpers/agent-python (#3491), the Python toolchain
// helper the agent-runtime box gets with toolchains=python. Real pip runs
// offline against a wheel built here (PIP_NO_INDEX + PIP_FIND_LINKS); manifest
// selection runs against a stub venv python that records its arguments.

const agentPythonScript = "../../../agent-runtime/helpers/agent-python"

// requireVenv skips when the host python cannot create a venv with pip.
func requireVenv(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	dir := t.TempDir()
	if out, err := exec.Command("python3", "-m", "venv", filepath.Join(dir, "v")).CombinedOutput(); err != nil {
		t.Skipf("python3 -m venv unavailable: %v\n%s", err, out)
	}
}

// writeWheel builds a minimal pure-Python wheel name-version-py3-none-any.whl
// in dir: one package whose VALUE is 42.
func writeWheel(t *testing.T, dir, name, version string) {
	t.Helper()
	path := filepath.Join(dir, fmt.Sprintf("%s-%s-py3-none-any.whl", name, version))
	f, err := os.Create(path) //nolint:gosec // test temp dir
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	info := fmt.Sprintf("%s-%s.dist-info", name, version)
	files := []struct{ name, body string }{
		{name + "/__init__.py", "VALUE = 42\n"},
		{info + "/METADATA", fmt.Sprintf("Metadata-Version: 2.1\nName: %s\nVersion: %s\n", name, version)},
		{info + "/WHEEL", "Wheel-Version: 1.0\nGenerator: agent-python-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n"},
	}
	var record strings.Builder
	for _, fl := range files {
		w, err := zw.Create(fl.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(fl.body)); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(fl.body))
		fmt.Fprintf(&record, "%s,sha256=%s,%d\n", fl.name, base64.RawURLEncoding.EncodeToString(sum[:]), len(fl.body))
	}
	fmt.Fprintf(&record, "%s/RECORD,,\n", info)
	w, err := zw.Create(info + "/RECORD")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(record.String())); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// closedAddr is a loopback address nothing listens on: connection refused.
func closedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

type helperResult struct {
	stdout, stderr string
	code           int
}

// lastLine is the final non-empty line of s.
func lastLine(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return lines[len(lines)-1]
}

func runAgentPython(t *testing.T, env []string, args ...string) helperResult {
	t.Helper()
	cmd := exec.Command("bash", append([]string{agentPythonScript}, args...)...) //nolint:gosec // test-only, fixed path
	// A clean pip environment: no user config, no ambient index settings.
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "PIP_") && !strings.HasPrefix(kv, "AGENT_PYTHON_") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(cmd.Env, "PIP_CONFIG_FILE=/dev/null", "HOME="+t.TempDir())
	cmd.Env = append(cmd.Env, env...)
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("run agent-python: %v", err)
		}
		code = ee.ExitCode()
	}
	return helperResult{stdout.String(), stderr.String(), code}
}

// The acceptance path, offline: a repo declaring a dependency in
// requirements.txt gets it installed into its venv, and the test command runs
// inside that venv and reports that it executed, with its exit status.
func TestAgentPython_InstallsRequirementsAndRunsTests(t *testing.T) {
	requireVenv(t)
	repo, wheels := t.TempDir(), t.TempDir()
	writeWheel(t, wheels, "tinydep", "1.0")
	writeFiles(t, repo, map[string]string{"requirements.txt": "tinydep==1.0\n"})
	// PIP_NO_INDEX means no index is used, so none is probed: the index URL
	// below is unreachable and must not matter.
	env := []string{"PIP_NO_INDEX=1", "PIP_FIND_LINKS=" + wheels, "PIP_INDEX_URL=http://" + closedAddr(t) + "/simple/",
		"AGENT_PYTHON_VENV=" + filepath.Join(t.TempDir(), "venv")}

	if r := runAgentPython(t, env, "setup", repo); r.code != 0 {
		t.Fatalf("setup failed (exit %d)\nstdout:\n%s\nstderr:\n%s", r.code, r.stdout, r.stderr)
	}
	// Re-running setup reuses the venv and is still green.
	if r := runAgentPython(t, env, "setup", repo); r.code != 0 {
		t.Fatalf("second setup failed (exit %d)\n%s%s", r.code, r.stdout, r.stderr)
	}

	r := runAgentPython(t, env, "test", repo, "--", "python", "-c", "import tinydep, sys; sys.exit(0 if tinydep.VALUE == 42 else 9)")
	if r.code != 0 {
		t.Fatalf("test command failed (exit %d)\n%s%s", r.code, r.stdout, r.stderr)
	}
	if !strings.Contains(r.stderr, "agent-python: test command executed: exit=0") {
		t.Errorf("no execution report on stderr:\n%s", r.stderr)
	}

	// A failing test command is not a helper error: its exit status is
	// passed through and still reported as executed.
	r = runAgentPython(t, env, "test", repo, "--", "python", "-c", "raise SystemExit(3)")
	if r.code != 3 {
		t.Errorf("exit = %d, want the test command's own 3\n%s", r.code, r.stderr)
	}
	if !strings.Contains(r.stderr, "agent-python: test command executed: exit=3") {
		t.Errorf("no execution report for the failing run:\n%s", r.stderr)
	}
}

// The default test command is pytest, run from the venv. Skipped where the
// host has no pytest to see through the venv's system site-packages (the box
// gets python3-pytest from the toolchain step).
func TestAgentPython_DefaultTestCommandIsPytest(t *testing.T) {
	requireVenv(t)
	if err := exec.Command("python3", "-c", "import pytest").Run(); err != nil {
		t.Skip("pytest not installed on this host")
	}
	repo := t.TempDir()
	writeFiles(t, repo, map[string]string{"test_ok.py": "def test_ok():\n    assert 1 + 1 == 2\n"})
	env := []string{"PIP_NO_INDEX=1", "AGENT_PYTHON_VENV=" + filepath.Join(t.TempDir(), "venv")}
	if r := runAgentPython(t, env, "setup", repo); r.code != 0 {
		t.Fatalf("setup failed: %s%s", r.stdout, r.stderr)
	}
	r := runAgentPython(t, env, "test", repo)
	if r.code != 0 || !strings.Contains(r.stdout, "1 passed") {
		t.Fatalf("pytest did not run and pass (exit %d)\n%s%s", r.code, r.stdout, r.stderr)
	}
}

// Restricted egress: when the package index cannot be reached, setup fails
// fast with one line naming the index host and the hosts to allow, and never
// prints the index URL's credentials.
func TestAgentPython_UnreachableIndexFailsLoudly(t *testing.T) {
	requireVenv(t)
	addr := closedAddr(t)
	repo := t.TempDir()
	writeFiles(t, repo, map[string]string{"requirements.txt": "tinydep==1.0\n"})
	env := []string{
		"PIP_INDEX_URL=http://user:s3cr3t-token@" + addr + "/simple/",
		"AGENT_PYTHON_VENV=" + filepath.Join(t.TempDir(), "venv"),
	}
	r := runAgentPython(t, env, "setup", repo)
	if r.code == 0 {
		t.Fatalf("setup succeeded with an unreachable index\n%s%s", r.stdout, r.stderr)
	}
	line := lastLine(r.stderr)
	// "NOT installed" is the probe's wording: the failure comes before pip runs.
	for _, want := range []string{"agent-python: error:", "package index unreachable", "127.0.0.1", "NOT installed", "pypi.org", "files.pythonhosted.org"} {
		if !strings.Contains(line, want) {
			t.Errorf("error line lacks %q: %q", want, line)
		}
	}
	if strings.Contains(r.stdout+r.stderr, "s3cr3t-token") {
		t.Errorf("index credentials leaked into output:\n%s%s", r.stdout, r.stderr)
	}
}

// Restricted egress that lets the index through but blocks the file host
// (the default index serves its files from a second host): the install
// itself fails, and the error still names the unreachable host class.
func TestAgentPython_UnreachableFileHostFailsLoudly(t *testing.T) {
	requireVenv(t)
	blocked := closedAddr(t)
	index := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/simple/tinydep") {
			fmt.Fprintf(w, `<html><body><a href="http://%s/files/tinydep-1.0-py3-none-any.whl">tinydep-1.0-py3-none-any.whl</a></body></html>`, blocked)
			return
		}
		http.NotFound(w, r)
	}))
	defer index.Close()
	repo := t.TempDir()
	writeFiles(t, repo, map[string]string{"requirements.txt": "tinydep==1.0\n"})
	// Credentials in the index URL: the reachability probe must still reach it.
	indexURL := strings.Replace(index.URL, "http://", "http://user:pw@", 1) + "/simple/"
	env := []string{"PIP_INDEX_URL=" + indexURL, "PIP_RETRIES=0", "AGENT_PYTHON_VENV=" + filepath.Join(t.TempDir(), "venv")}
	r := runAgentPython(t, env, "setup", repo)
	if r.code == 0 {
		t.Fatalf("setup succeeded with an unreachable file host\n%s%s", r.stdout, r.stderr)
	}
	line := lastLine(r.stderr)
	for _, want := range []string{"agent-python: error: dependency install failed: package index unreachable", "127.0.0.1", "files.pythonhosted.org"} {
		if !strings.Contains(line, want) {
			t.Errorf("error line lacks %q: %q", want, line)
		}
	}
}

// A dependency the index does not have is a failed install, reported on one
// line, not a venv that silently lacks it.
func TestAgentPython_MissingDependencyFailsLoudly(t *testing.T) {
	requireVenv(t)
	repo := t.TempDir()
	writeFiles(t, repo, map[string]string{"requirements.txt": "nosuchpkg-agent-python==1.0\n"})
	env := []string{"PIP_NO_INDEX=1", "PIP_FIND_LINKS=" + t.TempDir(), "AGENT_PYTHON_VENV=" + filepath.Join(t.TempDir(), "venv")}
	r := runAgentPython(t, env, "setup", repo)
	if r.code == 0 {
		t.Fatalf("setup succeeded without its dependency\n%s%s", r.stdout, r.stderr)
	}
	line := lastLine(r.stderr)
	if !strings.Contains(line, "agent-python: error: dependency install failed") || !strings.Contains(line, "requirements.txt") {
		t.Errorf("unclear error line: %q", line)
	}
}

// stubVenv makes a venv directory whose python records its arguments to
// <dir>/calls and exits with code.
func stubVenv(t *testing.T, code int) (venv, calls string) {
	t.Helper()
	venv = t.TempDir()
	calls = filepath.Join(venv, "calls")
	writeFiles(t, venv, map[string]string{"bin/python": fmt.Sprintf("#!/bin/sh\necho \"$*\" >> %q\nexit %d\n", calls, code)})
	if err := os.Chmod(filepath.Join(venv, "bin/python"), 0o700); err != nil { //nolint:gosec // test stand-in
		t.Fatal(err)
	}
	return venv, calls
}

// Only manifests the repo itself declares are installed, in a fixed order;
// nothing is guessed and no setup script is run directly.
func TestAgentPython_ManifestSelection(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	pyproject := "[project]\nname = \"demo\"\nversion = \"0.1\"\n"
	for _, tc := range []struct {
		name     string
		files    map[string]string
		want     []string // substrings of the recorded pip calls, in order
		wantNone bool     // no pip call at all
		note     string   // substring of stdout
	}{
		{name: "requirements files, requirements.txt first",
			files: map[string]string{"requirements.txt": "a\n", "requirements-dev.txt": "b\n", "requirements-test.txt": "c\n"},
			want:  []string{"-m pip install", "-r requirements.txt -r requirements-dev.txt -r requirements-test.txt"}},
		{name: "pyproject with a test extra",
			files: map[string]string{"pyproject.toml": pyproject + "[project.optional-dependencies]\ntest = [\"pytest\"]\n"},
			want:  []string{"-m pip install", "-e .[test]"}},
		{name: "pyproject with a tests extra",
			files: map[string]string{"pyproject.toml": pyproject + "[project.optional-dependencies]\ntests = [\"pytest\"]\n"},
			want:  []string{"-e .[tests]"}},
		{name: "pyproject without a test extra",
			files: map[string]string{"pyproject.toml": pyproject + "[project.optional-dependencies]\ndocs = [\"x\"]\n"},
			want:  []string{"-m pip install", "-e ."}},
		{name: "requirements then project",
			files: map[string]string{"requirements.txt": "a\n", "pyproject.toml": pyproject},
			want:  []string{"-r requirements.txt", "-e ."}},
		{name: "setup.cfg metadata with a test extra",
			files: map[string]string{"setup.cfg": "[metadata]\nname = demo\n\n[options.extras_require]\ntest =\n    pytest\n"},
			want:  []string{"-e .[test]"}},
		{name: "pyproject with tool config only",
			files:    map[string]string{"pyproject.toml": "[tool.pytest.ini_options]\naddopts = \"-q\"\n"},
			wantNone: true, note: "no [project] table"},
		{name: "setup.py only is not run",
			files:    map[string]string{"setup.py": "raise SystemExit('must not run')\n"},
			wantNone: true, note: "setup.py"},
		{name: "no manifest at all",
			files:    map[string]string{"test_x.py": "def test_x(): pass\n"},
			wantNone: true, note: "no dependency manifest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := t.TempDir()
			writeFiles(t, repo, tc.files)
			venv, calls := stubVenv(t, 0)
			r := runAgentPython(t, []string{"PIP_NO_INDEX=1", "AGENT_PYTHON_VENV=" + venv}, "setup", repo)
			if r.code != 0 {
				t.Fatalf("setup failed (exit %d)\n%s%s", r.code, r.stdout, r.stderr)
			}
			got, _ := os.ReadFile(calls) //nolint:gosec // test temp file
			if tc.wantNone {
				if strings.Contains(string(got), "pip install") {
					t.Errorf("unexpected pip install: %s", got)
				}
			} else {
				rest := string(got)
				for _, w := range tc.want {
					i := strings.Index(rest, w)
					if i < 0 {
						t.Fatalf("pip calls lack %q (in order); calls:\n%s", w, got)
					}
					rest = rest[i+len(w):]
				}
			}
			if tc.note != "" && !strings.Contains(r.stdout, tc.note) {
				t.Errorf("stdout lacks note %q:\n%s", tc.note, r.stdout)
			}
		})
	}
}

// A pip failure that is not a network failure is still a one-line error that
// names what failed.
func TestAgentPython_PipFailureIsReported(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	repo := t.TempDir()
	writeFiles(t, repo, map[string]string{"pyproject.toml": "[project]\nname = \"demo\"\nversion = \"0.1\"\n"})
	venv, _ := stubVenv(t, 1)
	r := runAgentPython(t, []string{"PIP_NO_INDEX=1", "AGENT_PYTHON_VENV=" + venv}, "setup", repo)
	if r.code == 0 {
		t.Fatal("setup succeeded although pip failed")
	}
	if line := lastLine(r.stderr); !strings.Contains(line, "agent-python: error: dependency install failed") || !strings.Contains(line, "-e .") {
		t.Errorf("unclear error line: %q", line)
	}
}

func TestAgentPython_TestRequiresSetup(t *testing.T) {
	repo := t.TempDir()
	r := runAgentPython(t, []string{"AGENT_PYTHON_VENV=" + filepath.Join(t.TempDir(), "absent")}, "test", repo)
	if r.code == 0 {
		t.Fatal("test ran without a venv")
	}
	line := lastLine(r.stderr)
	if !strings.Contains(line, "agent-python: error:") || !strings.Contains(line, "agent-python setup") {
		t.Errorf("unclear error line: %q", line)
	}
	if strings.Contains(r.stderr, "test command executed") {
		t.Error("reported a test run that never happened")
	}
}

func TestAgentPython_TestCommandNotFound(t *testing.T) {
	repo := t.TempDir()
	venv, _ := stubVenv(t, 0)
	r := runAgentPython(t, []string{"AGENT_PYTHON_VENV=" + venv}, "test", repo, "--", "no-such-test-runner-xyz")
	if r.code == 0 {
		t.Fatal("a missing test command succeeded")
	}
	if line := lastLine(r.stderr); !strings.Contains(line, "test command not found") || !strings.Contains(line, "no-such-test-runner-xyz") {
		t.Errorf("unclear error line: %q", line)
	}
	if strings.Contains(r.stderr, "test command executed") {
		t.Error("reported a test run that never happened")
	}
}

func TestAgentPython_UsageErrors(t *testing.T) {
	for _, args := range [][]string{{}, {"bogus"}, {"setup", "/nonexistent/agent-python-dir"}} {
		r := runAgentPython(t, nil, args...)
		if r.code == 0 {
			t.Errorf("%v: succeeded", args)
		}
		if !strings.Contains(lastLine(r.stderr), "agent-python") {
			t.Errorf("%v: unclear error: %q", args, r.stderr)
		}
	}
}

// agent-test is the language-neutral sibling: it runs any test command,
// reports that it executed, and passes its exit status through.
func TestAgentTest(t *testing.T) {
	run := func(args ...string) helperResult {
		t.Helper()
		cmd := exec.Command("bash", append([]string{"../../../agent-runtime/helpers/agent-test"}, args...)...) //nolint:gosec // test-only, fixed path
		var stdout, stderr strings.Builder
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		code := 0
		if err := cmd.Run(); err != nil {
			ee, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatal(err)
			}
			code = ee.ExitCode()
		}
		return helperResult{stdout.String(), stderr.String(), code}
	}
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"marker": "x"})

	r := run("-C", dir, "--", "sh", "-c", "test -f marker && exit 4")
	if r.code != 4 || lastLine(r.stderr) != "agent-test: test command executed: exit=4" {
		t.Errorf("-C run: exit %d, stderr %q", r.code, r.stderr)
	}
	r = run("true")
	if r.code != 0 || lastLine(r.stderr) != "agent-test: test command executed: exit=0" {
		t.Errorf("plain run: exit %d, stderr %q", r.code, r.stderr)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"no-such-test-runner-xyz"}, "agent-test: error: test command not found: no-such-test-runner-xyz"},
		{[]string{"-C", filepath.Join(dir, "absent"), "true"}, "agent-test: error: no such directory"},
		{nil, "agent-test: usage"},
		{[]string{"-C"}, "agent-test: usage"},
	} {
		r := run(tc.args...)
		if r.code == 0 || !strings.Contains(lastLine(r.stderr), tc.want) {
			t.Errorf("%v: exit %d, stderr %q, want %q", tc.args, r.code, r.stderr, tc.want)
		}
		if strings.Contains(r.stderr, "test command executed") {
			t.Errorf("%v: reported a test run that never happened", tc.args)
		}
	}
}

// The probe checks the index pip will actually use: pip's configured
// index-url when PIP_INDEX_URL is unset, and none at all when a requirements
// file chooses its own index (pip's own failure is then the error).
func TestAgentPython_ProbeFollowsPipsIndex(t *testing.T) {
	requireVenv(t)
	closed := closedAddr(t)

	t.Run("pip config index-url", func(t *testing.T) {
		repo, conf := t.TempDir(), filepath.Join(t.TempDir(), "pip.conf")
		writeFiles(t, repo, map[string]string{"requirements.txt": "tinydep==1.0\n"})
		writeFiles(t, filepath.Dir(conf), map[string]string{"pip.conf": "[global]\nindex-url = http://" + closed + "/simple/\n"})
		r := runAgentPython(t, []string{"PIP_CONFIG_FILE=" + conf, "AGENT_PYTHON_VENV=" + filepath.Join(t.TempDir(), "venv")}, "setup", repo)
		line := lastLine(r.stderr)
		if r.code == 0 || !strings.Contains(line, "package index unreachable: 127.0.0.1") || !strings.Contains(line, "NOT installed") {
			t.Errorf("exit %d, error line %q", r.code, line)
		}
	})

	t.Run("requirements file picks its own index", func(t *testing.T) {
		repo := t.TempDir()
		writeFiles(t, repo, map[string]string{"requirements.txt": "--index-url http://" + closed + "/simple/\ntinydep==1.0\n"})
		// The environment's index is unreachable too: probing it would fail
		// with the probe's error instead of letting pip use the file's index.
		r := runAgentPython(t, []string{"PIP_INDEX_URL=http://" + closedAddr(t) + "/simple/", "AGENT_PYTHON_VENV=" + filepath.Join(t.TempDir(), "venv")}, "setup", repo)
		line := lastLine(r.stderr)
		if r.code == 0 || !strings.Contains(line, "dependency install failed: package index unreachable") || strings.Contains(line, "NOT installed") {
			t.Errorf("want pip's own failure, not the probe's: exit %d, error line %q", r.code, line)
		}
	})

	t.Run("an unusable index URL never prints its credentials", func(t *testing.T) {
		repo := t.TempDir()
		writeFiles(t, repo, map[string]string{"requirements.txt": "tinydep==1.0\n"})
		r := runAgentPython(t, []string{"PIP_INDEX_URL=http://user:s3cr3t-token@127.0.0.1:notaport/simple/",
			"AGENT_PYTHON_VENV=" + filepath.Join(t.TempDir(), "venv")}, "setup", repo)
		if r.code == 0 || !strings.Contains(lastLine(r.stderr), "package index unreachable") {
			t.Errorf("exit %d, stderr %q", r.code, r.stderr)
		}
		if strings.Contains(r.stdout+r.stderr, "s3cr3t-token") || strings.Contains(r.stderr, "Traceback") {
			t.Errorf("credentials leaked or the probe crashed:\n%s%s", r.stdout, r.stderr)
		}
	})
}

// A relative AGENT_PYTHON_VENV means a path relative to where agent-python
// was started, for setup and test alike, whatever DIR is.
func TestAgentPython_RelativeVenvOverride(t *testing.T) {
	requireVenv(t)
	work, repo := t.TempDir(), t.TempDir()
	run := func(args ...string) helperResult {
		cmd := exec.Command("bash", append([]string{filepath.Join(mustAbs(t, "."), agentPythonScript)}, args...)...) //nolint:gosec // test-only, fixed path
		cmd.Dir = work
		cmd.Env = append(os.Environ(), "PIP_CONFIG_FILE=/dev/null", "PIP_NO_INDEX=1", "AGENT_PYTHON_VENV=rel-venv", "HOME="+t.TempDir())
		var stdout, stderr strings.Builder
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		code := 0
		if err := cmd.Run(); err != nil {
			code = err.(*exec.ExitError).ExitCode() //nolint:errorlint // test: only exit errors expected
		}
		return helperResult{stdout.String(), stderr.String(), code}
	}
	if r := run("setup", repo); r.code != 0 {
		t.Fatalf("setup: %s%s", r.stdout, r.stderr)
	}
	if _, err := os.Stat(filepath.Join(work, "rel-venv", "bin", "python")); err != nil {
		t.Fatalf("venv not created relative to the caller: %v", err)
	}
	if r := run("test", repo, "--", "python", "-c", "import sys; sys.exit(0 if sys.prefix.endswith('rel-venv') else 7)"); r.code != 0 {
		t.Errorf("test did not run in the relative venv: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
}

func mustAbs(t *testing.T, p string) string {
	t.Helper()
	a, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
