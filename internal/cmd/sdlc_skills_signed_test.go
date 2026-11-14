package cmd

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Tests for the signed source of scripts/install-sdlc-skills.sh
// (docs/design/sdlc-skills-option-b.md): a skills release is a directory with
// the bundle, a manifest and a detached signature over the manifest. Hermetic:
// the release is served from a file:// base and signed with a key made here.

func needSigningTools(t *testing.T) {
	t.Helper()
	needTools(t)
	for _, tool := range []string{"openssl", "base64"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
}

// signingKey is an ECDSA P-256 key pair on disk, as cosign generates.
type signingKey struct{ priv, pub string }

func newSigningKey(t *testing.T) signingKey {
	t.Helper()
	dir := t.TempDir()
	k := signingKey{priv: filepath.Join(dir, "key.pem"), pub: filepath.Join(dir, "key.pub")}
	if o, ok := run(t, "", nil, "openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", k.priv); !ok {
		t.Fatalf("generate key: %s", o)
	}
	if o, ok := run(t, "", nil, "openssl", "ec", "-in", k.priv, "-pubout", "-out", k.pub); !ok {
		t.Fatalf("public key: %s", o)
	}
	return k
}

// sign returns the .sig line for file: base64 of the DER signature over its
// SHA-256, the format `cosign sign-blob --key` writes.
func (k signingKey) sign(t *testing.T, file string) string {
	t.Helper()
	o, ok := run(t, "", nil, "bash", "-c", `openssl dgst -sha256 -sign "$1" "$2" | base64 | tr -d '\n'`, "_", k.priv, file)
	if !ok {
		t.Fatalf("sign: %s", o)
	}
	return o + "\n"
}

func skillsTarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for _, n := range names {
		if err := tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(files[n]))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(files[n])); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	if _, err := gz.Write(raw.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// The bundle layout the installer reads: <ns>-<name>/SKILL.md plus _shared/.
var signedSkills = map[string]string{
	"architect-design/SKILL.md":   "# design\n",
	"engineer-implement/SKILL.md": "# implement\n",
	"qa-unit-test/SKILL.md":       "# unit\n",
	"_shared/tracker.md":          "# shared tracker\n",
}

const signedSets = "set.sdlc=architect,engineer\nset.qa=qa\n"

// release is one published skills release under base.
type release struct {
	base, version string
	key           signingKey
}

func (r release) dir() string      { return filepath.Join(r.base, r.version) }
func (r release) manifest() string { return filepath.Join(r.dir(), "sdlc-skills.manifest") }
func (r release) sig() string      { return r.manifest() + ".sig" }
func (r release) tarball() string  { return filepath.Join(r.dir(), "sdlc-skills.tar.gz") }

// resign rewrites the manifest with edit applied and signs the result.
func (r release) resign(t *testing.T, edit func(string) string) {
	t.Helper()
	b, err := os.ReadFile(r.manifest())
	if err != nil {
		t.Fatal(err)
	}
	write(t, r.manifest(), edit(string(b)))
	write(t, r.sig(), r.key.sign(t, r.manifest()))
}

// pointLatest makes base/latest a copy of this release's manifest and signature.
func (r release) pointLatest(t *testing.T) {
	t.Helper()
	for _, name := range []string{"sdlc-skills.manifest", "sdlc-skills.manifest.sig"} {
		b, err := os.ReadFile(filepath.Join(r.dir(), name))
		if err != nil {
			t.Fatal(err)
		}
		write(t, filepath.Join(r.base, "latest", name), string(b))
	}
}

// publishSigned writes version under base (a new temp dir when empty), signed
// by key, and returns it. It does not move latest.
func publishSigned(t *testing.T, base, version string, key signingKey, files map[string]string, sets string) release {
	t.Helper()
	if base == "" {
		base = t.TempDir()
	}
	r := release{base: base, version: version, key: key}
	bundle := skillsTarGz(t, files)
	if err := os.MkdirAll(r.dir(), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.tarball(), bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(bundle)
	write(t, r.manifest(), "contract=1\nversion="+version+"\nsha256="+hex.EncodeToString(sum[:])+
		"\nsource.sdlc=example/skills@0123456789abcdef0123456789abcdef01234567\n"+sets)
	write(t, r.sig(), key.sign(t, r.manifest()))
	return r
}

// installSigned runs the installer against a signed source, trusting key.
func installSigned(t *testing.T, base string, key signingKey, dir string, extra ...string) (string, bool) {
	t.Helper()
	env := append([]string{"SDLC_SKILLS_BASE_URL=file://" + base, "SDLC_SKILLS_TRUSTED_KEYS_FILE=" + key.pub,
		"SKILLS_DIR=" + dir, "RELEASE=v9.9.9"}, extra...)
	return run(t, "", env, "bash", installSDLCSkillsScript)
}

func versionRecord(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, ".sdlc-skills-version")) //nolint:gosec // test temp dir
	if err != nil {
		t.Fatalf("version record: %v", err)
	}
	return string(b)
}

// nothingInstalled asserts a refused install left no skill and no record.
func nothingInstalled(t *testing.T, dir string) {
	t.Helper()
	for _, p := range []string{"architect-design", "qa-unit-test", "_shared", ".sdlc-skills-version"} {
		if exists(filepath.Join(dir, p)) {
			t.Errorf("%s exists after a refused install", p)
		}
	}
}

func TestInstallSigned_InstallsAndRecordsTheSkillsVersion(t *testing.T) {
	needSigningTools(t)
	key := newSigningKey(t)
	r := publishSigned(t, "", "2026.11.0", key, signedSkills, signedSets)
	dir := filepath.Join(t.TempDir(), "skills")
	write(t, filepath.Join(dir, "my-own-skill", "SKILL.md"), "mine\n")

	if o, ok := installSigned(t, r.base, key, dir, "SDLC_SKILLS_VERSION=2026.11.0"); !ok {
		t.Fatalf("install failed: %s", o)
	}
	if got, want := installedNames(t, dir), "_shared,architect-design,engineer-implement,qa-unit-test"; got != want {
		t.Errorf("installed %q, want %q", got, want)
	}
	if !exists(filepath.Join(dir, "my-own-skill", "SKILL.md")) {
		t.Error("the user's own skill was removed")
	}
	rec := versionRecord(t, dir)
	for _, want := range []string{"release=v9.9.9", "skills=2026.11.0", "contract=1", "sha256="} {
		if !strings.Contains(rec, want) {
			t.Errorf("version record %q lacks %q", rec, want)
		}
	}
	// Which set each installed directory came from, as the signed manifest says.
	sets, err := os.ReadFile(filepath.Join(dir, ".sdlc-skills-sets")) //nolint:gosec // test temp dir
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(sets), "qa\tqa-unit-test\nsdlc\tarchitect-design\nsdlc\tengineer-implement\n"; got != want {
		t.Errorf(".sdlc-skills-sets = %q, want %q", got, want)
	}
}

func TestInstallSigned_RefusesWhatTheKeyDidNotSign(t *testing.T) {
	needSigningTools(t)
	key, other := newSigningKey(t), newSigningKey(t)
	cases := map[string]struct {
		break_ func(t *testing.T, r release)
		want   string
	}{
		"signed by another key": {func(t *testing.T, r release) { write(t, r.sig(), other.sign(t, r.manifest())) }, "signature"},
		"manifest edited after signing": {func(t *testing.T, r release) {
			b, _ := os.ReadFile(r.manifest())
			write(t, r.manifest(), strings.Replace(string(b), "set.qa=qa", "set.qa=qa,engineer", 1))
		}, "signature"},
		"empty signature":   {func(t *testing.T, r release) { write(t, r.sig(), "") }, "signature"},
		"garbage signature": {func(t *testing.T, r release) { write(t, r.sig(), "not base64 !!\n") }, "signature"},
		"bundle swapped": {func(t *testing.T, r release) {
			if err := os.WriteFile(r.tarball(), skillsTarGz(t, map[string]string{"architect-design/SKILL.md": "# evil\n"}), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "sha256 mismatch"},
		// A validly signed, complete earlier release served under this
		// version's path: without the version check it would install.
		"another version's manifest": {func(t *testing.T, r release) {
			older := publishSigned(t, r.base, "2026.10.0", key, signedSkills, signedSets)
			for _, name := range []string{"sdlc-skills.manifest", "sdlc-skills.manifest.sig"} {
				b, err := os.ReadFile(filepath.Join(older.dir(), name))
				if err != nil {
					t.Fatal(err)
				}
				write(t, filepath.Join(r.dir(), name), string(b))
			}
		}, "the manifest there is for 2026.10.0"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := publishSigned(t, "", "2026.11.0", key, signedSkills, signedSets)
			tc.break_(t, r)
			dir := filepath.Join(t.TempDir(), "skills")
			out, ok := installSigned(t, r.base, key, dir, "SDLC_SKILLS_VERSION=2026.11.0")
			if ok {
				t.Fatalf("install succeeded: %s", out)
			}
			if !strings.Contains(out, tc.want) || !strings.Contains(out, "nothing installed") {
				t.Errorf("output %q does not mention %q and 'nothing installed'", out, tc.want)
			}
			nothingInstalled(t, dir)
		})
	}
}

func TestInstallSigned_NoTrustedKeyInstallsNothing(t *testing.T) {
	needSigningTools(t)
	key := newSigningKey(t)
	r := publishSigned(t, "", "2026.11.0", key, signedSkills, signedSets)
	dir := filepath.Join(t.TempDir(), "skills")
	// No SDLC_SKILLS_TRUSTED_KEYS_FILE: only the keys inside the installer count.
	out, ok := run(t, "", []string{"SDLC_SKILLS_BASE_URL=file://" + r.base, "SDLC_SKILLS_VERSION=2026.11.0", "SKILLS_DIR=" + dir, "RELEASE=v9.9.9"},
		"bash", installSDLCSkillsScript)
	if ok || !strings.Contains(out, "signature") {
		t.Errorf("ok=%v output=%q, want a signature refusal", ok, out)
	}
	nothingInstalled(t, dir)
}

// Rotation: the .sig may carry one line per signing key.
func TestInstallSigned_AnyTrustedKeyAnyLine(t *testing.T) {
	needSigningTools(t)
	old, next := newSigningKey(t), newSigningKey(t)
	r := publishSigned(t, "", "2026.11.0", old, signedSkills, signedSets)
	write(t, r.sig(), old.sign(t, r.manifest())+next.sign(t, r.manifest()))
	if o, ok := installSigned(t, r.base, next, filepath.Join(t.TempDir(), "skills"), "SDLC_SKILLS_VERSION=2026.11.0"); !ok {
		t.Errorf("the second line, by the trusted key, was not accepted: %s", o)
	}
	// A key file with both keys accepts a release signed by either.
	both := filepath.Join(t.TempDir(), "both.pem")
	a, _ := os.ReadFile(old.pub)
	b, _ := os.ReadFile(next.pub)
	write(t, both, "# old\n"+string(a)+"# new\n"+string(b))
	r2 := publishSigned(t, "", "2026.11.0", next, signedSkills, signedSets)
	out, ok := run(t, "", []string{"SDLC_SKILLS_BASE_URL=file://" + r2.base, "SDLC_SKILLS_TRUSTED_KEYS_FILE=" + both,
		"SDLC_SKILLS_VERSION=2026.11.0", "SKILLS_DIR=" + filepath.Join(t.TempDir(), "skills"), "RELEASE=v9.9.9"}, "bash", installSDLCSkillsScript)
	if !ok {
		t.Errorf("a release signed by the second key in the file was refused: %s", out)
	}
}

// A box keeps the skills release it was installed with: a fresh box takes
// latest once, and later runs stay on the recorded version until one is asked
// for by name.
func TestInstallSigned_ABoxKeepsItsVersionUntilAskedToMove(t *testing.T) {
	needSigningTools(t)
	key := newSigningKey(t)
	v1 := publishSigned(t, "", "2026.11.0", key, signedSkills, signedSets)
	v1.pointLatest(t)
	dir := filepath.Join(t.TempDir(), "skills")

	if o, ok := installSigned(t, v1.base, key, dir); !ok {
		t.Fatalf("fresh install failed: %s", o)
	}
	if rec := versionRecord(t, dir); !strings.Contains(rec, "skills=2026.11.0") {
		t.Fatalf("fresh install recorded %q, want latest resolved to 2026.11.0", rec)
	}

	newer := map[string]string{}
	for k, v := range signedSkills {
		newer[k] = v
	}
	newer["architect-design/SKILL.md"] = "# design v2\n"
	newer["architect-review/SKILL.md"] = "# review\n"
	v2 := publishSigned(t, v1.base, "2026.12.0", key, newer, signedSets)
	v2.pointLatest(t)

	// Re-run with no version (a set change, a daemon upgrade): stays on v1.
	if o, ok := installSigned(t, v1.base, key, dir, "SKILL_SETS=sdlc"); !ok {
		t.Fatalf("re-run failed: %s", o)
	}
	if rec := versionRecord(t, dir); !strings.Contains(rec, "skills=2026.11.0") {
		t.Errorf("re-run moved the box: %q", rec)
	}
	if exists(filepath.Join(dir, "architect-review")) {
		t.Error("re-run installed a skill of the newer release")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "architect-design", "SKILL.md")); string(b) != "# design\n" { //nolint:gosec // test temp dir
		t.Errorf("re-run changed a skill's content to %q", b)
	}

	// Asked by name: moves.
	out, ok := installSigned(t, v1.base, key, dir, "SDLC_SKILLS_VERSION=2026.12.0")
	if !ok {
		t.Fatalf("upgrade failed: %s", out)
	}
	if !strings.Contains(out, "2026.11.0 -> 2026.12.0") {
		t.Errorf("upgrade output %q does not say what moved", out)
	}
	if rec := versionRecord(t, dir); !strings.Contains(rec, "skills=2026.12.0") {
		t.Errorf("upgrade recorded %q", rec)
	}
	if !exists(filepath.Join(dir, "architect-review", "SKILL.md")) {
		t.Error("upgrade did not install the newer release's skill")
	}

	// Rollback is the same call with the earlier version.
	if o, ok := installSigned(t, v1.base, key, dir, "SDLC_SKILLS_VERSION=2026.11.0"); !ok {
		t.Fatalf("rollback failed: %s", o)
	}
	if exists(filepath.Join(dir, "architect-review")) {
		t.Error("rollback left the newer release's skill")
	}

	// "latest" asked for by name also moves.
	if o, ok := installSigned(t, v1.base, key, dir, "SDLC_SKILLS_VERSION=latest"); !ok {
		t.Fatalf("latest failed: %s", o)
	}
	if rec := versionRecord(t, dir); !strings.Contains(rec, "skills=2026.12.0") {
		t.Errorf("latest recorded %q", rec)
	}
}

// A box installed from a release asset has no skills version recorded. With a
// signed source configured and no version asked for, it stays on that
// release's asset rather than jumping to latest.
func TestInstallSigned_ABoxOnAReleaseAssetStaysThereUntilAskedToMove(t *testing.T) {
	needSigningTools(t)
	legacyBase, lock := publishSets(t, setSkills, setLines)
	dir := filepath.Join(t.TempDir(), "skills")
	if o, ok := installSets(t, legacyBase, lock, dir, "all"); !ok {
		t.Fatalf("release-asset install failed: %s", o)
	}
	before := snapshot(t, dir)

	key := newSigningKey(t)
	r := publishSigned(t, "", "2026.11.0", key, signedSkills, signedSets)
	r.pointLatest(t)

	out, ok := installSigned(t, r.base, key, dir, "ARTIFACT_BASE_URL=file://"+legacyBase, "SDLC_SKILLS_LOCK_URL=file://"+lock, "RELEASE=v10.0.0")
	if !ok {
		t.Fatalf("re-run failed: %s", out)
	}
	if !strings.Contains(out, "v9.9.9") {
		t.Errorf("output %q does not say which release the box stays on", out)
	}
	if after := snapshot(t, dir); after != before {
		t.Errorf("re-run changed the box:\n%s\nwas:\n%s", after, before)
	}
	if rec := versionRecord(t, dir); !strings.Contains(rec, "release=v9.9.9") || strings.Contains(rec, "skills=") {
		t.Errorf("record = %q, want the original release and no skills version", rec)
	}

	if o, ok := installSigned(t, r.base, key, dir, "SDLC_SKILLS_VERSION=2026.11.0"); !ok {
		t.Fatalf("explicit move failed: %s", o)
	}
	if rec := versionRecord(t, dir); !strings.Contains(rec, "skills=2026.11.0") {
		t.Errorf("explicit move recorded %q", rec)
	}
}

func TestInstallSigned_ContractTooNewInstallsNothing(t *testing.T) {
	needSigningTools(t)
	key := newSigningKey(t)
	r := publishSigned(t, "", "2026.11.0", key, signedSkills, signedSets)
	r.resign(t, func(s string) string { return strings.Replace(s, "contract=1", "contract=2", 1) })
	dir := filepath.Join(t.TempDir(), "skills")
	out, ok := installSigned(t, r.base, key, dir, "SDLC_SKILLS_VERSION=2026.11.0")
	if ok || !strings.Contains(out, "contract 2") || !strings.Contains(out, "supports contract 1") {
		t.Errorf("ok=%v output=%q, want a refusal naming both contracts", ok, out)
	}
	nothingInstalled(t, dir)
}

// A later release of the same contract may add manifest keys and sets.
func TestInstallSigned_ANewerManifestOfTheSameContractInstalls(t *testing.T) {
	needSigningTools(t)
	key := newSigningKey(t)
	files := map[string]string{"data-clean/SKILL.md": "# clean\n"}
	for k, v := range signedSkills {
		files[k] = v
	}
	r := publishSigned(t, "", "2027.01.0", key, files, signedSets+"set.data=data\nbuilt=2027-01-01T00:00:00Z\nfuture.key=x\n")
	dir := filepath.Join(t.TempDir(), "skills")
	if o, ok := installSigned(t, r.base, key, dir, "SDLC_SKILLS_VERSION=2027.01.0", "SKILL_SETS=qa"); !ok {
		t.Fatalf("install failed: %s", o)
	}
	if got, want := installedNames(t, dir), "_shared,qa-unit-test"; got != want {
		t.Errorf("installed %q, want %q", got, want)
	}
}

func TestInstallSigned_UnknownSetNamesTheSetsTheReleaseHas(t *testing.T) {
	needSigningTools(t)
	key := newSigningKey(t)
	r := publishSigned(t, "", "2026.11.0", key, signedSkills, signedSets)
	dir := filepath.Join(t.TempDir(), "skills")
	out, ok := installSigned(t, r.base, key, dir, "SDLC_SKILLS_VERSION=2026.11.0", "SKILL_SETS=sdlc,security")
	if ok || !strings.Contains(out, "unknown skill set 'security'") || !strings.Contains(out, "known skill sets: sdlc, qa") {
		t.Errorf("ok=%v output=%q, want the unknown id and the known ones", ok, out)
	}
	nothingInstalled(t, dir)
}

func TestInstallSigned_RefusesAMalformedManifest(t *testing.T) {
	needSigningTools(t)
	key := newSigningKey(t)
	cases := map[string]func(string) string{
		"duplicate key":  func(s string) string { return s + "version=2026.12.0\n" },
		"no digest":      func(s string) string { return strings.Replace(s, "sha256=", "sha=", 1) },
		"bad namespace":  func(s string) string { return strings.Replace(s, "set.qa=qa", "set.qa=qa;id", 1) },
		"no contract":    func(s string) string { return strings.Replace(s, "contract=1\n", "", 1) },
		"malformed line": func(s string) string { return s + "what is this\n" },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			r := publishSigned(t, "", "2026.11.0", key, signedSkills, signedSets)
			r.resign(t, edit)
			dir := filepath.Join(t.TempDir(), "skills")
			out, ok := installSigned(t, r.base, key, dir, "SDLC_SKILLS_VERSION=2026.11.0", "SKILL_SETS=qa")
			if ok || !strings.Contains(out, "nothing installed") {
				t.Errorf("ok=%v output=%q", ok, out)
			}
			nothingInstalled(t, dir)
		})
	}
}

func TestInstallSigned_VersionIsValidatedBeforeUse(t *testing.T) {
	needSigningTools(t)
	key := newSigningKey(t)
	r := publishSigned(t, "", "2026.11.0", key, signedSkills, signedSets)
	for _, v := range []string{"../2026.11.0", "1 2", "$(id)", "a/b", ".hidden"} {
		dir := filepath.Join(t.TempDir(), "skills")
		out, ok := installSigned(t, r.base, key, dir, "SDLC_SKILLS_VERSION="+v)
		if ok || !strings.Contains(out, "SDLC_SKILLS_VERSION") {
			t.Errorf("%q: ok=%v output=%q", v, ok, out)
		}
		nothingInstalled(t, dir)
	}
	// A version with no signed source to take it from is a mistake, not a no-op.
	dir := filepath.Join(t.TempDir(), "skills")
	out, ok := run(t, "", []string{"SDLC_SKILLS_VERSION=2026.11.0", "ARTIFACT_BASE_URL=file://" + r.dir(), "SKILLS_DIR=" + dir, "RELEASE=v9.9.9"},
		"bash", installSDLCSkillsScript)
	if ok || !strings.Contains(out, "SDLC_SKILLS_BASE_URL") {
		t.Errorf("ok=%v output=%q, want a refusal naming SDLC_SKILLS_BASE_URL", ok, out)
	}
}

// The keys inside the installer are the ones the daemon and CLI embed.
func TestInstallerTrustedKeysMatchTheEmbeddedFile(t *testing.T) {
	script, err := os.ReadFile(installSDLCSkillsScript)
	if err != nil {
		t.Fatal(err)
	}
	embedded, err := os.ReadFile("../../pkg/core/sdlcskills/trusted-keys.pub")
	if err != nil {
		t.Fatal(err)
	}
	_, rest, ok := strings.Cut(string(script), "# BEGIN TRUSTED KEYS\n")
	if !ok {
		t.Fatal("installer has no '# BEGIN TRUSTED KEYS' marker")
	}
	inline, _, ok := strings.Cut(rest, "# END TRUSTED KEYS\n")
	if !ok {
		t.Fatal("installer has no '# END TRUSTED KEYS' marker")
	}
	if got, want := pemBlocks(inline), pemBlocks(string(embedded)); got != want {
		t.Errorf("installer keys differ from pkg/core/sdlcskills/trusted-keys.pub:\ninstaller:\n%s\nembedded:\n%s", got, want)
	}
}

// pemBlocks returns the PEM blocks of text, without anything around them.
func pemBlocks(text string) string {
	var out []string
	in := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "-----BEGIN ") {
			in = true
		}
		if in {
			out = append(out, line)
		}
		if strings.HasPrefix(line, "-----END ") {
			in = false
		}
	}
	return strings.Join(out, "\n")
}

// fetchOnly runs the installer in --fetch-only mode: fetch and verify one
// skills release into out, installing nothing (the air-gapped bundle build).
func fetchOnly(t *testing.T, base string, key signingKey, out string, extra ...string) (string, bool) {
	t.Helper()
	home := t.TempDir()
	env := append([]string{"SDLC_SKILLS_BASE_URL=file://" + base, "SDLC_SKILLS_TRUSTED_KEYS_FILE=" + key.pub, "HOME=" + home}, extra...)
	o, ok := run(t, "", env, "bash", installSDLCSkillsScript, "--fetch-only", out)
	if exists(filepath.Join(home, ".claude")) {
		t.Errorf("--fetch-only touched the caller's skills directory")
	}
	return o, ok
}

// The air-gapped bundle build takes a pinned, verified skills release with
// it; a box then installs from that copy with no network, verifying again.
func TestFetchOnly_CopiesAVerifiedReleaseABoxCanInstallOffline(t *testing.T) {
	needSigningTools(t)
	key := newSigningKey(t)
	r := publishSigned(t, "", "2026.11.0", key, signedSkills, signedSets)
	out := filepath.Join(t.TempDir(), "sdlc-skills")

	o, ok := fetchOnly(t, r.base, key, out, "SDLC_SKILLS_VERSION=2026.11.0")
	if !ok {
		t.Fatalf("fetch failed: %s", o)
	}
	for _, f := range []string{"2026.11.0/sdlc-skills.tar.gz", "2026.11.0/sdlc-skills.manifest", "2026.11.0/sdlc-skills.manifest.sig",
		"latest/sdlc-skills.manifest", "latest/sdlc-skills.manifest.sig"} {
		if !exists(filepath.Join(out, f)) {
			t.Errorf("%s missing from the fetched copy", f)
		}
	}
	// The copy is byte-identical to what was published, so its signature holds.
	for _, f := range []string{"sdlc-skills.tar.gz", "sdlc-skills.manifest", "sdlc-skills.manifest.sig"} {
		a, _ := os.ReadFile(filepath.Join(r.dir(), f))          //nolint:gosec // test temp dir
		b, _ := os.ReadFile(filepath.Join(out, "2026.11.0", f)) //nolint:gosec // test temp dir
		if !bytes.Equal(a, b) {
			t.Errorf("%s differs from the published file", f)
		}
	}
	// A box with no network installs from the copy, by version and by default.
	for _, extra := range [][]string{{"SDLC_SKILLS_VERSION=2026.11.0"}, nil} {
		dir := filepath.Join(t.TempDir(), "skills")
		if o, ok := installSigned(t, out, key, dir, extra...); !ok {
			t.Fatalf("offline install %v failed: %s", extra, o)
		}
		if rec := versionRecord(t, dir); !strings.Contains(rec, "skills=2026.11.0") {
			t.Errorf("offline install %v recorded %q", extra, rec)
		}
	}
	// Running it again over the same directory is fine.
	if o, ok := fetchOnly(t, r.base, key, out, "SDLC_SKILLS_VERSION=2026.11.0"); !ok {
		t.Errorf("second fetch failed: %s", o)
	}
}

func TestFetchOnly_Refusals(t *testing.T) {
	needSigningTools(t)
	key, other := newSigningKey(t), newSigningKey(t)
	r := publishSigned(t, "", "2026.11.0", key, signedSkills, signedSets)
	r.pointLatest(t)

	cases := map[string]struct {
		key   signingKey
		extra []string
		want  string
	}{
		// A bundle build is pinned: it names its version.
		"no version":      {key, nil, "needs SDLC_SKILLS_VERSION"},
		"latest":          {key, []string{"SDLC_SKILLS_VERSION=latest"}, "needs SDLC_SKILLS_VERSION"},
		"untrusted key":   {other, []string{"SDLC_SKILLS_VERSION=2026.11.0"}, "signature"},
		"unknown version": {key, []string{"SDLC_SKILLS_VERSION=2099.01.0"}, "cannot fetch"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "sdlc-skills")
			o, ok := fetchOnly(t, r.base, tc.key, out, tc.extra...)
			if ok || !strings.Contains(o, tc.want) {
				t.Errorf("ok=%v output=%q, want a refusal mentioning %q", ok, o, tc.want)
			}
			if exists(out) {
				t.Errorf("a refused fetch left %s behind", out)
			}
		})
	}
	t.Run("swapped bundle", func(t *testing.T) {
		bad := publishSigned(t, "", "2026.11.0", key, signedSkills, signedSets)
		if err := os.WriteFile(bad.tarball(), skillsTarGz(t, map[string]string{"architect-design/SKILL.md": "# evil\n"}), 0o600); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(t.TempDir(), "sdlc-skills")
		o, ok := fetchOnly(t, bad.base, key, out, "SDLC_SKILLS_VERSION=2026.11.0")
		if ok || !strings.Contains(o, "sha256 mismatch") || exists(out) {
			t.Errorf("ok=%v output=%q exists=%v", ok, o, exists(out))
		}
	})
	t.Run("no signed source", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "sdlc-skills")
		o, ok := run(t, "", []string{"RELEASE=v9.9.9", "HOME=" + t.TempDir()}, "bash", installSDLCSkillsScript, "--fetch-only", out)
		if ok || !strings.Contains(o, "SDLC_SKILLS_BASE_URL") {
			t.Errorf("ok=%v output=%q", ok, o)
		}
	})
	t.Run("unknown argument", func(t *testing.T) {
		o, ok := run(t, "", []string{"RELEASE=v9.9.9", "HOME=" + t.TempDir()}, "bash", installSDLCSkillsScript, "--nope")
		if ok || !strings.Contains(o, "unknown argument") {
			t.Errorf("ok=%v output=%q", ok, o)
		}
	})
}
