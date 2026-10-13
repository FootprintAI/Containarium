package cmd

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Tests for scripts/build-sdlc-skills-bundle.sh and scripts/install-sdlc-skills.sh
// (#2065). Hermetic: a local git repo stands in for open-sdlc-skills and the
// release assets are served from a file:// base, so nothing touches the network.

const (
	buildSDLCSkillsScript   = "../../scripts/build-sdlc-skills-bundle.sh"
	installSDLCSkillsScript = "../../scripts/install-sdlc-skills.sh"
)

func needTools(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"bash", "git", "python3", "tar", "curl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
}

// run executes a script (or command) and returns combined output and whether it succeeded.
func run(t *testing.T, dir string, env []string, name string, args ...string) (string, bool) {
	t.Helper()
	cmd := exec.Command(name, args...) //nolint:gosec // test-only, fixed scripts and git
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	return buf.String(), err == nil
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// fixtureRepo builds a git repo shaped like open-sdlc-skills and returns its
// path and HEAD sha.
func fixtureRepo(t *testing.T, files map[string]string) (string, string) {
	t.Helper()
	repo := t.TempDir()
	for p, c := range files {
		write(t, filepath.Join(repo, p), c)
	}
	git := func(args ...string) string {
		out, ok := run(t, repo, nil, "git", append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com"}, args...)...)
		if !ok {
			t.Fatalf("git %v: %s", args, out)
		}
		return strings.TrimSpace(out)
	}
	git("init", "-q")
	git("add", "-A")
	git("commit", "-q", "-m", "fixture")
	return repo, git("rev-parse", "HEAD")
}

var defaultSkills = map[string]string{
	"README.md":           "not a skill\n",
	"architect/design.md": "# design\n",
	"qa/unit-test.md":     "# unit\n",
	"_shared/tracker.md":  "# shared tracker\n",
	".github/ci.md":       "not a skill either\n",
}

func writeLock(t *testing.T, repo, ref, sha string) string {
	t.Helper()
	lock := filepath.Join(t.TempDir(), "sdlc-skills.lock")
	write(t, lock, "# test lock\nrepo=example/skills\nref="+ref+"\nsha256="+sha+"\n")
	return lock
}

func buildEnv(repo, lock string) []string {
	return []string{"SDLC_SKILLS_REPO_URL=file://" + repo, "SDLC_SKILLS_LOCK=" + lock}
}

func members(t *testing.T, tarball string) []string {
	t.Helper()
	out, ok := run(t, "", nil, "tar", "-tzf", tarball)
	if !ok {
		t.Fatalf("tar -tzf: %s", out)
	}
	m := strings.Split(strings.TrimSpace(out), "\n")
	sort.Strings(m)
	return m
}

func TestBuildSDLCSkills_LayoutAndDeterminism(t *testing.T) {
	needTools(t)
	repo, sha := fixtureRepo(t, defaultSkills)
	lock := writeLock(t, repo, sha, "")
	out1, out2 := t.TempDir(), t.TempDir()

	if o, ok := run(t, "", buildEnv(repo, lock), "bash", buildSDLCSkillsScript, "--update-lock", out1); !ok {
		t.Fatalf("build failed: %s", o)
	}
	got := strings.Join(members(t, filepath.Join(out1, "sdlc-skills.tar.gz")), ",")
	want := "_shared/tracker.md,architect-design/SKILL.md,qa-unit-test/SKILL.md"
	if got != want {
		t.Errorf("members = %s, want %s (README, dot-dirs and top-level files are not skills; _shared is copied as-is)", got, want)
	}

	// Rebuilding from the lock the first build wrote must verify and be byte-identical.
	if o, ok := run(t, "", buildEnv(repo, lock), "bash", buildSDLCSkillsScript, out2); !ok {
		t.Fatalf("rebuild did not verify against the lock: %s", o)
	}
	a, _ := os.ReadFile(filepath.Join(out1, "sdlc-skills.tar.gz")) //nolint:gosec // test temp dir
	b, _ := os.ReadFile(filepath.Join(out2, "sdlc-skills.tar.gz")) //nolint:gosec // test temp dir
	if !bytes.Equal(a, b) {
		t.Error("two builds of the same ref differ; the tarball must be deterministic")
	}
}

func TestBuildSDLCSkills_RefusesWhatItCannotVerify(t *testing.T) {
	needTools(t)
	repo, sha := fixtureRepo(t, defaultSkills)

	cases := []struct {
		name, ref, lockSHA, wantMsg string
	}{
		{"digest mismatch", sha, strings.Repeat("0", 64), "mismatch"},
		{"no digest yet", sha, "", "no sha256"},
		{"ref is not a full sha", "main", "", "40-hex"},
		{"ref not in the repo", strings.Repeat("a", 40), "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lock := writeLock(t, repo, tc.ref, tc.lockSHA)
			out, ok := run(t, "", buildEnv(repo, lock), "bash", buildSDLCSkillsScript, t.TempDir())
			if ok {
				t.Fatalf("build succeeded, want failure:\n%s", out)
			}
			if tc.wantMsg != "" && !strings.Contains(out, tc.wantMsg) {
				t.Errorf("output %q does not mention %q", out, tc.wantMsg)
			}
		})
	}
}

// publish builds a bundle from a fixture and returns the file:// base serving it.
func publish(t *testing.T, files map[string]string) string {
	t.Helper()
	repo, sha := fixtureRepo(t, files)
	lock := writeLock(t, repo, sha, "")
	out := t.TempDir()
	if o, ok := run(t, "", buildEnv(repo, lock), "bash", buildSDLCSkillsScript, "--update-lock", out); !ok {
		t.Fatalf("build failed: %s", o)
	}
	return out
}

func install(t *testing.T, base, skillsDir string, extra ...string) (string, bool) {
	t.Helper()
	return run(t, "", append([]string{"ARTIFACT_BASE_URL=file://" + base, "SKILLS_DIR=" + skillsDir, "RELEASE=v9.9.9"}, extra...),
		"bash", installSDLCSkillsScript)
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func TestInstallSDLCSkills_InstallsAndLeavesTheUsersOwnSkillsAlone(t *testing.T) {
	needTools(t)
	base := publish(t, defaultSkills)
	dir := filepath.Join(t.TempDir(), "skills")
	write(t, filepath.Join(dir, "my-own-skill", "SKILL.md"), "mine\n")

	if o, ok := install(t, base, dir); !ok {
		t.Fatalf("install failed: %s", o)
	}
	for _, p := range []string{"architect-design/SKILL.md", "qa-unit-test/SKILL.md", "_shared/tracker.md", ".sdlc-skills-manifest", ".sdlc-skills-version", "my-own-skill/SKILL.md"} {
		if !exists(filepath.Join(dir, p)) {
			t.Errorf("%s missing after install", p)
		}
	}
	v, _ := os.ReadFile(filepath.Join(dir, ".sdlc-skills-version")) //nolint:gosec // test temp dir
	if !strings.Contains(string(v), "release=v9.9.9") {
		t.Errorf("version record = %q, want the release recorded", v)
	}
}

func TestInstallSDLCSkills_UpdateRemovesOnlyWhatItOwned(t *testing.T) {
	needTools(t)
	dir := filepath.Join(t.TempDir(), "skills")
	write(t, filepath.Join(dir, "my-own-skill", "SKILL.md"), "mine\n")

	if o, ok := install(t, publish(t, defaultSkills), dir); !ok {
		t.Fatalf("first install: %s", o)
	}
	// Second release drops qa/unit-test.
	next := map[string]string{"architect/design.md": "# design v2\n", "_shared/tracker.md": "# shared\n"}
	if o, ok := install(t, publish(t, next), dir); !ok {
		t.Fatalf("second install: %s", o)
	}
	if exists(filepath.Join(dir, "qa-unit-test")) {
		t.Error("a skill removed from the pinned set was left behind")
	}
	if !exists(filepath.Join(dir, "my-own-skill", "SKILL.md")) {
		t.Error("the user's own skill was removed by an update")
	}
	b, _ := os.ReadFile(filepath.Join(dir, "architect-design", "SKILL.md")) //nolint:gosec // test temp dir
	if !strings.Contains(string(b), "v2") {
		t.Errorf("architect-design not updated: %q", b)
	}
}

func TestInstallSDLCSkills_HashMismatchInstallsNothing(t *testing.T) {
	needTools(t)
	base := publish(t, defaultSkills)
	write(t, filepath.Join(base, "sdlc-skills.tar.gz.sha256"), strings.Repeat("0", 64)+"  sdlc-skills.tar.gz\n")
	dir := filepath.Join(t.TempDir(), "skills")

	out, ok := install(t, base, dir)
	if ok {
		t.Fatalf("install succeeded on a hash mismatch:\n%s", out)
	}
	if !strings.Contains(out, "sha256 mismatch") {
		t.Errorf("output %q does not say why", out)
	}
	if exists(filepath.Join(dir, "architect-design")) {
		t.Error("skills were installed despite the mismatch")
	}
}

// A hostile archive (path traversal) with a MATCHING hash is still refused.
func TestInstallSDLCSkills_RejectsPathTraversal(t *testing.T) {
	needTools(t)
	base := t.TempDir()
	evil := filepath.Join(base, "sdlc-skills.tar.gz")
	// A valid skill alongside the traversal entry: without the installer's own
	// path check, a lenient tar would strip the "../" and the install would
	// succeed, so this must fail on the guard's message, not on tar's behaviour.
	py := "import tarfile,io,sys\nt=tarfile.open(sys.argv[1],'w:gz')\nfor n in ('good-skill/SKILL.md','../escaped.txt'):\n i=tarfile.TarInfo(n);d=b'x';i.size=len(d);t.addfile(i,io.BytesIO(d))\nt.close()\n"
	if o, ok := run(t, "", nil, "python3", "-I", "-c", py, evil); !ok {
		t.Fatalf("craft archive: %s", o)
	}
	sum, ok := run(t, "", nil, "bash", "-c", "(sha256sum '"+evil+"' 2>/dev/null || shasum -a 256 '"+evil+"') | cut -d' ' -f1")
	if !ok {
		t.Fatalf("sha256: %s", sum)
	}
	write(t, evil+".sha256", strings.TrimSpace(sum)+"  sdlc-skills.tar.gz\n")
	parent := t.TempDir()
	dir := filepath.Join(parent, "skills")

	out, ok := install(t, base, dir)
	if ok {
		t.Fatalf("install accepted a traversal archive:\n%s", out)
	}
	if !strings.Contains(out, "unsafe path in archive") {
		t.Errorf("rejected, but not by the installer's path check: %q", out)
	}
	if exists(filepath.Join(parent, "escaped.txt")) {
		t.Error("a file escaped the skills directory")
	}
	if exists(filepath.Join(dir, "good-skill")) {
		t.Error("part of a rejected archive was installed")
	}
}

func TestInstallSDLCSkills_OverlayWins(t *testing.T) {
	needTools(t)
	base := publish(t, defaultSkills)
	dir := filepath.Join(t.TempDir(), "skills")
	overlay := t.TempDir()
	write(t, filepath.Join(overlay, "architect-design", "SKILL.md"), "# team override\n")

	if o, ok := install(t, base, dir, "SDLC_SKILLS_OVERLAY_DIR="+overlay); !ok {
		t.Fatalf("install: %s", o)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "architect-design", "SKILL.md")) //nolint:gosec // test temp dir
	if string(b) != "# team override\n" {
		t.Errorf("architect-design = %q, want the overlay's copy", b)
	}
	if !exists(filepath.Join(dir, "qa-unit-test", "SKILL.md")) {
		t.Error("public skills not overridden by the overlay were lost")
	}
}
