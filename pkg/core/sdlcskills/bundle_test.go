package sdlcskills

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #2488: the daemon reads the same sdlc-skills.tar.gz the boxes get, verified
// against the embedded pin, and takes one section of one skill from it.

const implementMD = `---
name: "Engineer: Implement"
description: Act as a software engineer.
---

Act as a **software engineer** implementing one scoped task.

**Engineering principles**

- **Test-first** — write the failing test first
- **Small and scoped** — the issue and nothing else

**Test environment**

1. Provision a fresh box over the platform MCP.
`

func tarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for name, body := range files {
		h := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
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

func lockFor(data []byte) Lock {
	sum := sha256.Sum256(data)
	return Lock{Repo: "example/skills", Ref: strings.Repeat("a", 40), SHA256: hex.EncodeToString(sum[:])}
}

func TestLoadBundleBytes_VerifiesDigestBeforeReading(t *testing.T) {
	data := tarGz(t, map[string]string{"engineer-implement/SKILL.md": implementMD})

	b, err := LoadBundleBytes(data, lockFor(data))
	if err != nil {
		t.Fatalf("matching digest: %v", err)
	}
	if b.Pin() != "example/skills@aaaaaaaaaaaa" {
		t.Errorf("Pin = %q", b.Pin())
	}

	wrong := lockFor(data)
	wrong.SHA256 = strings.Repeat("0", 64)
	if _, err := LoadBundleBytes(data, wrong); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Errorf("wrong digest: err = %v, want a digest error", err)
	}
}

func TestLoadBundleBytes_RejectsUnsafePaths(t *testing.T) {
	data := tarGz(t, map[string]string{"../escape/SKILL.md": "x", "engineer-implement/SKILL.md": implementMD})
	if _, err := LoadBundleBytes(data, lockFor(data)); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Errorf("err = %v, want an unsafe-path error", err)
	}
}

func TestSkillBody_StripsFrontmatter(t *testing.T) {
	data := tarGz(t, map[string]string{"engineer-implement/SKILL.md": implementMD})
	b, err := LoadBundleBytes(data, lockFor(data))
	if err != nil {
		t.Fatal(err)
	}
	body, ok := b.SkillBody("engineer-implement")
	if !ok {
		t.Fatal("engineer-implement not found")
	}
	if strings.Contains(body, "name: \"Engineer: Implement\"") || strings.HasPrefix(body, "---") {
		t.Errorf("frontmatter not stripped:\n%s", body)
	}
	if !strings.HasPrefix(body, "Act as a **software engineer**") {
		t.Errorf("body does not start at the prose:\n%s", body)
	}
	if _, ok := b.SkillBody("no-such-skill"); ok {
		t.Error("a missing skill reported found")
	}
}

func TestExtractSection_TakesOneBoldSectionOnly(t *testing.T) {
	body := StripFrontmatter(implementMD)
	got, ok := ExtractSection(body, "Engineering principles")
	if !ok {
		t.Fatal("section not found")
	}
	if !strings.Contains(got, "Test-first") || !strings.Contains(got, "Small and scoped") {
		t.Errorf("section is missing its bullets:\n%s", got)
	}
	if strings.Contains(got, "Test environment") || strings.Contains(got, "platform MCP") {
		t.Errorf("section ran into the next heading (the interactive workflow must not be included):\n%s", got)
	}
	if strings.Contains(got, "**Engineering principles**") {
		t.Errorf("section includes its own heading line:\n%s", got)
	}
	if _, ok := ExtractSection(body, "No such section"); ok {
		t.Error("a missing section reported found")
	}
}

func TestLoadBundle_FileAgainstEmbeddedLock(t *testing.T) {
	// The embedded lock pins the real asset, which this test does not have, so
	// any other bytes must be refused: the daemon never trusts a bundle that is
	// not the pinned one.
	data := tarGz(t, map[string]string{"engineer-implement/SKILL.md": implementMD})
	path := filepath.Join(t.TempDir(), "sdlc-skills.tar.gz")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBundle(path); err == nil {
		t.Error("a bundle that is not the pinned asset was accepted")
	}
	if _, err := LoadBundle(filepath.Join(t.TempDir(), "missing.tar.gz")); err == nil {
		t.Error("a missing file was accepted")
	}
}
