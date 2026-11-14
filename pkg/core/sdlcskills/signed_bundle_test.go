package sdlcskills

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func signedFixture(t *testing.T, k testKey, files map[string]string, edit func(string) string) (bundle, manifest, sig []byte) {
	t.Helper()
	bundle = tarGz(t, files)
	sum := sha256.Sum256(bundle)
	text := manifestText("contract=1", "version=2026.11.0", "sha256="+hex.EncodeToString(sum[:]),
		"source.sdlc=example/skills@"+testRef, "set.sdlc=engineer")
	if edit != nil {
		text = edit(text)
	}
	manifest = []byte(text)
	return bundle, manifest, k.sign(t, manifest)
}

func TestLoadSignedBundle(t *testing.T) {
	k := newTestKey(t)
	bundle, manifest, sig := signedFixture(t, k, map[string]string{"engineer-implement/SKILL.md": implementMD}, nil)

	b, m, err := LoadSignedBundle(bundle, manifest, sig, keyring(t, k.pem))
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != "2026.11.0" {
		t.Errorf("Version = %q", m.Version)
	}
	if got := b.Pin(); got != "example/skills@b348a8258b4c skills 2026.11.0" {
		t.Errorf("Pin() = %q", got)
	}
	if _, ok := b.Section("engineer-implement", "Engineering principles"); !ok {
		t.Error("section not found in the verified bundle")
	}
}

func TestLoadSignedBundle_RefusesBeforeReadingTheArchive(t *testing.T) {
	k, other := newTestKey(t), newTestKey(t)
	files := map[string]string{"engineer-implement/SKILL.md": implementMD}
	bundle, manifest, sig := signedFixture(t, k, files, nil)
	keys := keyring(t, k.pem)

	// The archive is not gzip at all: every refusal below must come from the
	// signature or the digest, never from trying to read it.
	notAnArchive := []byte("not a tarball")

	if _, _, err := LoadSignedBundle(bundle, manifest, other.sign(t, manifest), keys); err == nil {
		t.Error("manifest signed by an untrusted key accepted")
	}
	if _, _, err := LoadSignedBundle(notAnArchive, manifest, sig, keys); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Errorf("err = %v, want a digest mismatch", err)
	}
	tampered := []byte(strings.Replace(string(manifest), "set.sdlc=engineer", "set.sdlc=engineer,qa", 1))
	if _, _, err := LoadSignedBundle(bundle, tampered, sig, keys); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Errorf("err = %v, want a signature failure for an edited manifest", err)
	}
	if _, _, err := LoadSignedBundle(bundle, manifest, sig, Keyring{}); err == nil {
		t.Error("accepted with no trusted key")
	}
}

func TestLoadSignedBundle_ContractTooNew(t *testing.T) {
	k := newTestKey(t)
	bundle, manifest, sig := signedFixture(t, k, map[string]string{"engineer-implement/SKILL.md": implementMD},
		func(s string) string { return strings.Replace(s, "contract=1", "contract=2", 1) })
	_, _, err := LoadSignedBundle(bundle, manifest, sig, keyring(t, k.pem))
	var tooNew *ContractTooNewError
	if !errors.As(err, &tooNew) {
		t.Fatalf("err = %v, want *ContractTooNewError", err)
	}
}

func TestLoadSignedBundleFile_ReadsTheManifestAndSignatureBesideIt(t *testing.T) {
	k := newTestKey(t)
	bundle, manifest, sig := signedFixture(t, k, map[string]string{"engineer-implement/SKILL.md": implementMD}, nil)
	dir := t.TempDir()
	p := filepath.Join(dir, "sdlc-skills.tar.gz")
	for name, data := range map[string][]byte{"sdlc-skills.tar.gz": bundle, ManifestName: manifest, SignatureName: sig} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := LoadSignedBundleFile(p, keyring(t, k.pem)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, SignatureName)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadSignedBundleFile(p, keyring(t, k.pem)); err == nil {
		t.Error("accepted without a signature file")
	}
}
