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

// --- skill sets (#3048) -----------------------------------------------------

var setSkills = map[string]string{
	"architect/design.md": "# design\n",
	"engineer/build.md":   "# build\n",
	"qa/unit-test.md":     "# unit\n",
	"qa/e2e.md":           "# e2e\n",
	"_shared/tracker.md":  "# shared tracker\n",
}

const setLines = "set.sdlc=architect,engineer\nset.qa=qa\n"

// publishSets builds a bundle whose lock defines the sets sdlc (architect,
// engineer) and qa (qa), and returns the asset base and the built lock.
func publishSets(t *testing.T, files map[string]string, sets string) (base, lock string) {
	t.Helper()
	repo, sha := fixtureRepo(t, files)
	lock = filepath.Join(t.TempDir(), "sdlc-skills.lock")
	write(t, lock, "repo=example/skills\nref="+sha+"\nsha256=\n"+sets)
	base = t.TempDir()
	if o, ok := run(t, "", buildEnv(repo, lock), "bash", buildSDLCSkillsScript, "--update-lock", base); !ok {
		t.Fatalf("build failed: %s", o)
	}
	return base, lock
}

func installSets(t *testing.T, base, lock, dir, sets string) (string, bool) {
	t.Helper()
	return install(t, base, dir, "SDLC_SKILLS_LOCK_URL=file://"+lock, "SKILL_SETS="+sets)
}

func installedNames(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, ".sdlc-skills-manifest")) //nolint:gosec // test temp dir
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	m := strings.Fields(string(b))
	sort.Strings(m)
	return strings.Join(m, ",")
}

// snapshot returns every file under dir (except the timestamped version record)
// with its content, to assert a re-run is byte-identical.
func snapshot(t *testing.T, dir string) string {
	t.Helper()
	out, ok := run(t, dir, nil, "bash", "-c",
		"find . -type f ! -name .sdlc-skills-version | LC_ALL=C sort | while read -r f; do echo \"== $f\"; cat \"$f\"; done")
	if !ok {
		t.Fatalf("snapshot: %s", out)
	}
	return out
}

func TestInstallSDLCSkills_SetsDefaultInstallsEverything(t *testing.T) {
	needTools(t)
	base, lock := publishSets(t, setSkills, setLines)
	want := "_shared,architect-design,engineer-build,qa-e2e,qa-unit-test"
	for _, sets := range []string{"", "all"} {
		dir := filepath.Join(t.TempDir(), "skills")
		if o, ok := installSets(t, base, lock, dir, sets); !ok {
			t.Fatalf("SKILL_SETS=%q: %s", sets, o)
		}
		if got := installedNames(t, dir); got != want {
			t.Errorf("SKILL_SETS=%q manifest = %s, want %s", sets, got, want)
		}
	}
}

func TestInstallSDLCSkills_SetSubsetOnlyItsNamespacesPlusShared(t *testing.T) {
	needTools(t)
	base, lock := publishSets(t, setSkills, setLines)
	dir := filepath.Join(t.TempDir(), "skills")
	if o, ok := installSets(t, base, lock, dir, "qa"); !ok {
		t.Fatalf("install: %s", o)
	}
	if got := installedNames(t, dir); got != "_shared,qa-e2e,qa-unit-test" {
		t.Errorf("manifest = %s", got)
	}
	for _, p := range []string{"architect-design", "engineer-build"} {
		if exists(filepath.Join(dir, p)) {
			t.Errorf("%s installed although set qa was selected", p)
		}
	}
	// Two sets resolve to the union.
	dir2 := filepath.Join(t.TempDir(), "skills")
	if o, ok := installSets(t, base, lock, dir2, "sdlc,qa"); !ok {
		t.Fatalf("install: %s", o)
	}
	if got := installedNames(t, dir2); got != "_shared,architect-design,engineer-build,qa-e2e,qa-unit-test" {
		t.Errorf("sdlc,qa manifest = %s", got)
	}
}

func TestInstallSDLCSkills_SetNoneInstallsNothingAndPrunesOwned(t *testing.T) {
	needTools(t)
	base, lock := publishSets(t, setSkills, setLines)
	dir := filepath.Join(t.TempDir(), "skills")
	write(t, filepath.Join(dir, "my-own-skill", "SKILL.md"), "mine\n")
	if o, ok := installSets(t, base, lock, dir, "all"); !ok {
		t.Fatalf("install: %s", o)
	}
	// "none" needs neither network nor lock.
	if o, ok := install(t, t.TempDir(), dir, "SKILL_SETS=none"); !ok {
		t.Fatalf("none: %s", o)
	}
	if got := installedNames(t, dir); got != "" {
		t.Errorf("manifest = %q, want empty", got)
	}
	for _, p := range []string{"_shared", "qa-e2e", "architect-design"} {
		if exists(filepath.Join(dir, p)) {
			t.Errorf("%s survived SKILL_SETS=none", p)
		}
	}
	if !exists(filepath.Join(dir, "my-own-skill", "SKILL.md")) {
		t.Error("the user's own skill was removed")
	}
}

func TestInstallSDLCSkills_UnknownSetFailsNamingKnownIDs(t *testing.T) {
	needTools(t)
	base, lock := publishSets(t, setSkills, setLines)
	dir := filepath.Join(t.TempDir(), "skills")
	out, ok := installSets(t, base, lock, dir, "qa,nope")
	if ok {
		t.Fatalf("unknown set accepted:\n%s", out)
	}
	for _, want := range []string{"nope", "known skill sets", "qa", "sdlc"} {
		if !strings.Contains(out, want) {
			t.Errorf("output %q does not mention %q", out, want)
		}
	}
	if exists(filepath.Join(dir, "qa-e2e")) || exists(filepath.Join(dir, ".sdlc-skills-manifest")) {
		t.Error("a failed selection installed something")
	}
}

func TestInstallSDLCSkills_SetIDsAreValidatedBeforeUse(t *testing.T) {
	needTools(t)
	base, lock := publishSets(t, setSkills, setLines)
	pwned := filepath.Join(t.TempDir(), "pwned")
	for _, bad := range []string{"qa;touch " + pwned, "$(touch " + pwned + ")", "QA", "../qa", "qa,none", "all,qa", "qa,,sdlc", "qa,", ",qa"} {
		dir := filepath.Join(t.TempDir(), "skills")
		out, ok := installSets(t, base, lock, dir, bad)
		if ok {
			t.Errorf("SKILL_SETS=%q accepted:\n%s", bad, out)
		}
		if exists(filepath.Join(dir, ".sdlc-skills-manifest")) {
			t.Errorf("SKILL_SETS=%q installed something", bad)
		}
	}
	if exists(pwned) {
		t.Error("a set id was executed by the shell")
	}
}

func TestInstallSDLCSkills_SetsNarrowWidenAndUnchangedRerun(t *testing.T) {
	needTools(t)
	base, lock := publishSets(t, setSkills, setLines)
	dir := filepath.Join(t.TempDir(), "skills")
	write(t, filepath.Join(dir, "my-own-skill", "SKILL.md"), "mine\n")

	for _, step := range []struct{ sets, want string }{
		{"sdlc,qa", "_shared,architect-design,engineer-build,qa-e2e,qa-unit-test"},
		{"qa", "_shared,qa-e2e,qa-unit-test"}, // narrowing prunes the dropped namespaces
		{"sdlc", "_shared,architect-design,engineer-build"},
		{"sdlc,qa", "_shared,architect-design,engineer-build,qa-e2e,qa-unit-test"}, // widening adds
	} {
		if o, ok := installSets(t, base, lock, dir, step.sets); !ok {
			t.Fatalf("SKILL_SETS=%s: %s", step.sets, o)
		}
		if got := installedNames(t, dir); got != step.want {
			t.Errorf("SKILL_SETS=%s manifest = %s, want %s", step.sets, got, step.want)
		}
		if !exists(filepath.Join(dir, "my-own-skill", "SKILL.md")) {
			t.Errorf("SKILL_SETS=%s removed the user's own skill", step.sets)
		}
		for _, n := range []string{"architect-design", "engineer-build", "qa-e2e", "qa-unit-test"} {
			if exists(filepath.Join(dir, n)) != strings.Contains(step.want, n) {
				t.Errorf("SKILL_SETS=%s: presence of %s disagrees with the manifest", step.sets, n)
			}
		}
	}
	before := snapshot(t, dir)
	if o, ok := installSets(t, base, lock, dir, "sdlc,qa"); !ok {
		t.Fatalf("rerun: %s", o)
	}
	if after := snapshot(t, dir); after != before {
		t.Errorf("an unchanged re-run changed the tree:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

func TestInstallSDLCSkills_SetsNeedALockMatchingTheVerifiedBundle(t *testing.T) {
	needTools(t)
	base, lock := publishSets(t, setSkills, setLines)

	// A lock that pins a different bundle than the one downloaded is refused.
	other := filepath.Join(t.TempDir(), "other.lock")
	b, _ := os.ReadFile(lock) //nolint:gosec // test temp dir
	write(t, other, regexpSHA(string(b)))
	dir := filepath.Join(t.TempDir(), "skills")
	if out, ok := installSets(t, base, other, dir, "qa"); ok || !strings.Contains(out, "does not pin") {
		t.Errorf("mismatched lock: ok=%v output %q", ok, out)
	}
	// A release with no reachable lock cannot honour an explicit selection.
	if out, ok := installSets(t, base, filepath.Join(t.TempDir(), "absent.lock"), dir, "qa"); ok || !strings.Contains(out, "lock") {
		t.Errorf("missing lock: ok=%v output %q", ok, out)
	}
	if exists(filepath.Join(dir, ".sdlc-skills-manifest")) {
		t.Error("something was installed on a refused selection")
	}
}

func regexpSHA(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, "sha256=") {
			lines[i] = "sha256=" + strings.Repeat("0", 64)
		}
	}
	return strings.Join(lines, "\n")
}

func TestBuildSDLCSkills_SetsMustPartitionTheNamespaces(t *testing.T) {
	needTools(t)
	cases := []struct{ name, sets, want string }{
		{"namespace in no set", "set.sdlc=architect,engineer\n", "qa"},
		{"set names a missing namespace", setLines + "set.extra=ghost\n", "ghost"},
		{"namespace in two sets", setLines + "set.dup=qa\n", "more than one set"},
		{"bad set id", "set.Bad_ID=architect,engineer,qa\n", "set id"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo, sha := fixtureRepo(t, setSkills)
			lock := filepath.Join(t.TempDir(), "sdlc-skills.lock")
			write(t, lock, "repo=example/skills\nref="+sha+"\nsha256=\n"+tc.sets)
			out, ok := run(t, "", buildEnv(repo, lock), "bash", buildSDLCSkillsScript, "--update-lock", t.TempDir())
			if ok {
				t.Fatalf("build accepted the lock:\n%s", out)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("output %q does not mention %q", out, tc.want)
			}
		})
	}
}

// A lock value is untrusted too: a namespace with shell-ish or path-ish
// characters is refused before it is used in a prefix match.
func TestInstallSDLCSkills_RefusesABadNamespaceInTheLock(t *testing.T) {
	needTools(t)
	base, lock := publishSets(t, setSkills, setLines)
	b, _ := os.ReadFile(lock) //nolint:gosec // test temp dir
	bad := filepath.Join(t.TempDir(), "bad.lock")
	write(t, bad, strings.Replace(string(b), "set.qa=qa", "set.qa=qa,q*", 1))
	dir := filepath.Join(t.TempDir(), "skills")
	out, ok := installSets(t, base, bad, dir, "qa")
	if ok || !strings.Contains(out, "bad namespace") {
		t.Errorf("ok=%v output %q, want a bad-namespace refusal", ok, out)
	}
	if exists(filepath.Join(dir, ".sdlc-skills-manifest")) {
		t.Error("something was installed from a lock with a bad namespace")
	}
}
