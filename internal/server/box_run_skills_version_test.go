package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/pkg/core/box"
	"github.com/footprintai/containarium/pkg/core/sdlcskills"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// The per-box skills upgrade (docs/design/sdlc-skills-option-b.md): a box
// changes skills release only when ApplyBoxSkillSets is asked for one by
// name. The install step here is the real installer against signed releases
// served from a temp directory.

// signedSkillsReleases is a directory of signed skills releases and the key
// that signed them.
type signedSkillsReleases struct {
	dir, pub string
	key      *ecdsa.PrivateKey
}

func newSignedSkillsReleases(t *testing.T) *signedSkillsReleases {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	r := &signedSkillsReleases{dir: t.TempDir(), key: key}
	r.pub = filepath.Join(t.TempDir(), "key.pub")
	writeFile(t, r.pub, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})))
	return r
}

// publish writes one release holding a skill per contract set, whose content
// names the version, and optionally points latest at it.
func (r *signedSkillsReleases) publish(t *testing.T, version string, latest bool) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, name := range []string{"_shared/tracker.md", "architect-design/SKILL.md", "qa-unit-test/SKILL.md", "security-triage/SKILL.md"} {
		body := "# " + name + " " + version + "\n"
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(buf.Bytes())
	manifest := "contract=1\nversion=" + version + "\nsha256=" + hex.EncodeToString(sum[:]) +
		"\nsource.sdlc=example/skills@" + strings.Repeat("a", 40) + "\nset.sdlc=architect\nset.qa=qa\nset.security=security\n"
	digest := sha256.Sum256([]byte(manifest))
	sig, err := ecdsa.SignASN1(rand.Reader, r.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sigLine := base64.StdEncoding.EncodeToString(sig) + "\n"
	vdir := filepath.Join(r.dir, version)
	if err := os.MkdirAll(vdir, 0o750); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(vdir, "sdlc-skills.tar.gz"), buf.String())
	dirs := []string{vdir}
	if latest {
		ldir := filepath.Join(r.dir, "latest")
		if err := os.MkdirAll(ldir, 0o750); err != nil {
			t.Fatal(err)
		}
		dirs = append(dirs, ldir)
	}
	for _, d := range dirs {
		writeFile(t, filepath.Join(d, sdlcskills.ManifestName), manifest)
		writeFile(t, filepath.Join(d, sdlcskills.SignatureName), sigLine)
	}
}

const testSkillsBaseURL = "https://skills.example.com/sdlc"

// signedSkillSetServer is skillSetServer whose install step runs the real
// installer against releases, with the daemon configured for a skills base
// URL. asked records the source each install was handed.
func signedSkillSetServer(t *testing.T, home string, releases *signedSkillsReleases) (s *ContainerServer, asked *[]sdlcskills.SkillsSource) {
	t.Helper()
	needSkillInstallTools(t)
	if _, err := osexec.LookPath("openssl"); err != nil {
		t.Skip("openssl not available")
	}
	s, _, _ = skillSetServer(t, home, pb.ContainerState_CONTAINER_STATE_RUNNING)
	base := testSkillsBaseURL
	s.sdlcSkillsBaseURL = &base
	var got []sdlcskills.SkillsSource
	asked = &got
	s.boxSkillSetsInstall = func(_, _, _ string, sets sdlcskills.SkillSets, src sdlcskills.SkillsSource) (string, error) {
		got = append(got, src)
		cmd := osexec.Command("bash", installSDLCSkillsScriptPath)
		// The daemon's URL is https; the fixture serves the same layout from disk.
		cmd.Env = append(os.Environ(), "HOME="+home, "SDLC_SKILLS_BASE_URL=file://"+releases.dir,
			"SDLC_SKILLS_TRUSTED_KEYS_FILE="+releases.pub, "SDLC_SKILLS_VERSION="+src.Version(), "SKILL_SETS="+sets.String(), "RELEASE=v9.9.9")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return string(out), fmt.Errorf("%v: %s", err, out)
		}
		return string(out), nil
	}
	s.runCheckoutBoxes = func(context.Context) ([]box.BoxStatus, error) {
		return []box.BoxStatus{{Ref: box.BoxRef{Tenant: "alice", Name: "alice-container"}, State: pb.ContainerState_CONTAINER_STATE_RUNNING}}, nil
	}
	return s, asked
}

func applyVersion(s *ContainerServer, version string, sets ...string) (*pb.ApplyBoxSkillSetsResponse, error) {
	return s.ApplyBoxSkillSets(tenantCtx("alice"), &pb.ApplyBoxSkillSetsRequest{Username: "alice", SkillSets: sets, Release: "v9.9.9", SkillsVersion: version})
}

func skillContent(t *testing.T, home string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(home, ".claude", "skills", "qa-unit-test", "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestApplyBoxSkillSets_ABoxMovesSkillsReleaseOnlyWhenAsked(t *testing.T) {
	home := t.TempDir()
	releases := newSignedSkillsReleases(t)
	releases.publish(t, "2026.11.0", true)
	s, asked := signedSkillSetServer(t, home, releases)

	// A box with nothing recorded and no version asked for takes latest once.
	resp, err := applyVersion(s, "", "qa")
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetSkillsVersion() != "2026.11.0" {
		t.Fatalf("first apply reported skills version %q, want 2026.11.0", resp.GetSkillsVersion())
	}
	if src := (*asked)[0]; src.BaseURL() != testSkillsBaseURL || src.Version() != "" {
		t.Errorf("installer was handed %q %q, want the daemon's base URL and no version", src.BaseURL(), src.Version())
	}

	// A newer release is published and latest moves. The box does not.
	releases.publish(t, "2026.12.0", true)
	resp, err = applyVersion(s, "", "qa", "security")
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetSkillsVersion() != "2026.11.0" {
		t.Errorf("a set change moved the box to %q", resp.GetSkillsVersion())
	}
	if got := skillContent(t, home); !strings.Contains(got, "2026.11.0") {
		t.Errorf("a set change replaced the skill content: %q", got)
	}

	// Asked by name: this box moves. The set list is unchanged, so no skill
	// directory is installed or removed, and the version still changes.
	resp, err = applyVersion(s, "2026.12.0", "qa", "security")
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetSkillsVersion() != "2026.12.0" || !resp.GetUnchanged() {
		t.Errorf("upgrade: skills version %q unchanged=%v, want 2026.12.0 with no directory added or removed", resp.GetSkillsVersion(), resp.GetUnchanged())
	}
	if got := skillContent(t, home); !strings.Contains(got, "2026.12.0") {
		t.Errorf("upgrade left the old skill content: %q", got)
	}

	// Back again is the same call.
	if resp, err = applyVersion(s, "2026.11.0", "qa", "security"); err != nil || resp.GetSkillsVersion() != "2026.11.0" {
		t.Errorf("rollback: %v, skills version %q", err, resp.GetSkillsVersion())
	}
	// "latest" by name resolves to a version, which is what is reported.
	if resp, err = applyVersion(s, "latest", "qa", "security"); err != nil || resp.GetSkillsVersion() != "2026.12.0" {
		t.Errorf("latest: %v, skills version %q", err, resp.GetSkillsVersion())
	}
	if src := (*asked)[len(*asked)-1]; src.Version() != "latest" {
		t.Errorf("installer was handed version %q, want latest", src.Version())
	}
}

func TestApplyBoxSkillSets_SkillsVersionRefusals(t *testing.T) {
	releases := newSignedSkillsReleases(t)
	releases.publish(t, "2026.11.0", true)

	t.Run("not a version name", func(t *testing.T) {
		s, asked := signedSkillSetServer(t, t.TempDir(), releases)
		for _, v := range []string{"../2026.11.0", "1;rm -rf /", "$(id)", "a b"} {
			if _, err := applyVersion(s, v, "qa"); status.Code(err) != codes.InvalidArgument {
				t.Errorf("%q: err = %v, want INVALID_ARGUMENT", v, err)
			}
		}
		if len(*asked) != 0 {
			t.Errorf("the installer ran %d times for refused versions", len(*asked))
		}
	})
	t.Run("no skills base URL on this daemon", func(t *testing.T) {
		s, asked := signedSkillSetServer(t, t.TempDir(), releases)
		none := ""
		s.sdlcSkillsBaseURL = &none
		_, err := applyVersion(s, "2026.11.0", "qa")
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), sdlcSkillsBaseURLEnv) {
			t.Errorf("err = %v, want FAILED_PRECONDITION naming %s", err, sdlcSkillsBaseURLEnv)
		}
		if len(*asked) != 0 {
			t.Error("the installer ran")
		}
	})
	t.Run("a version that is not published", func(t *testing.T) {
		home := t.TempDir()
		s, _ := signedSkillSetServer(t, home, releases)
		if _, err := applyVersion(s, "2099.01.0", "qa"); status.Code(err) != codes.Unavailable {
			t.Errorf("err = %v, want UNAVAILABLE from the failed install", err)
		}
		if dirs := skillDirs(t, home); len(dirs) != 0 {
			t.Errorf("a failed install left %v", dirs)
		}
	})
}

// Without a skills base URL the daemon behaves as before: the release's own
// bundle, and no skills version reported.
func TestApplyBoxSkillSets_NoBaseURLKeepsTheReleaseAsset(t *testing.T) {
	home := t.TempDir()
	s, _, _ := skillSetServer(t, home, pb.ContainerState_CONTAINER_STATE_RUNNING)
	none := ""
	s.sdlcSkillsBaseURL = &none
	var got sdlcskills.SkillsSource
	inner := s.boxSkillSetsInstall
	s.boxSkillSetsInstall = func(box, user, release string, sets sdlcskills.SkillSets, src sdlcskills.SkillsSource) (string, error) {
		got = src
		return inner(box, user, release, sets, src)
	}
	resp, err := apply(t, s, "qa")
	if err != nil {
		t.Fatal(err)
	}
	if got.Signed() || resp.GetSkillsVersion() != "" {
		t.Errorf("source signed=%v, reported skills version %q; want the release asset and none", got.Signed(), resp.GetSkillsVersion())
	}
}

func TestSkillsBaseURL_EnvironmentThenDefault(t *testing.T) {
	s := &ContainerServer{}
	t.Setenv(sdlcSkillsBaseURLEnv, "")
	if got := s.skillsBaseURL(); got != sdlcskills.DefaultBaseURL {
		t.Errorf("unset: %q, want the built-in default %q", got, sdlcskills.DefaultBaseURL)
	}
	t.Setenv(sdlcSkillsBaseURLEnv, " https://skills.example.com/sdlc ")
	if got := s.skillsBaseURL(); got != "https://skills.example.com/sdlc" {
		t.Errorf("env: %q", got)
	}
	bad := "ftp://skills.example.com"
	s.sdlcSkillsBaseURL = &bad
	if _, err := s.boxSkillsSource(""); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("an unusable configured URL: err = %v, want FAILED_PRECONDITION", err)
	}
}
