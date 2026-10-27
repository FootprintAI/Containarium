package sshkey

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGenerateFresh_PreservesOldKeyAcrossRotations(t *testing.T) {
	opts := LocateOpts{HomeDir: t.TempDir()}
	oldPubPath, oldPub, err := Generate(opts, false)
	if err != nil {
		t.Fatal(err)
	}
	oldPath := strings.TrimSuffix(oldPubPath, ".pub")
	oldBytes, err := os.ReadFile(oldPath)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{oldPubPath: true}
	for range 2 {
		pubPath, pub, err := GenerateFresh(opts)
		if err != nil {
			t.Fatalf("generate rotation key: %v", err)
		}
		if seen[pubPath] || pub == oldPub || filepath.Dir(pubPath) != filepath.Dir(oldPubPath) {
			t.Fatalf("rotation did not create a distinct key in ~/.ssh: %s", pubPath)
		}
		seen[pubPath] = true
		info, err := os.Stat(strings.TrimSuffix(pubPath, ".pub"))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("private key permissions: info=%v, error=%v", info, err)
		}
	}
	after, err := os.ReadFile(oldPath)
	if err != nil || !bytes.Equal(oldBytes, after) {
		t.Fatalf("old private key changed: %v", err)
	}
}

func TestRemoveRetired_RequiresExplicitMatchingRetirement(t *testing.T) {
	opts := LocateOpts{HomeDir: t.TempDir()}
	now := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	past, future := now.Add(-time.Hour), now.Add(time.Hour)
	paths := make(map[string]string)
	var records []SSHKey
	for _, name := range []string{"retired", "expired", "future", "missing", "duplicate active", "personal"} {
		pubPath, pub, err := GenerateFresh(opts)
		if err != nil {
			t.Fatal(err)
		}
		if name == "personal" {
			path := filepath.Join(opts.HomeDir, ".ssh", "id_ed25519")
			if err := os.Rename(strings.TrimSuffix(pubPath, ".pub"), path); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(pubPath, path+".pub"); err != nil {
				t.Fatal(err)
			}
			pubPath = path + ".pub"
		}
		paths[name] = strings.TrimSuffix(pubPath, ".pub")
		fp, err := Fingerprint(pub)
		if err != nil {
			t.Fatal(err)
		}
		record := SSHKey{Name: name, Fingerprint: fp, PublicKey: pub}
		switch name {
		case "retired", "personal", "duplicate active":
			record.RetiredAt = &past
		case "expired":
			record.ExpiresAt = past
		case "future":
			record.RetiredAt = &future
		case "missing":
			continue
		}
		records = append(records, record)
		if name == "duplicate active" {
			records = append(records, SSHKey{Fingerprint: fp})
		}
	}
	removed, err := RemoveRetired(opts, records, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || removed[0] != paths["retired"] {
		t.Fatalf("removed=%v, want only retired", removed)
	}
	for name, path := range paths {
		for _, file := range []string{path, path + ".pub"} {
			_, err := os.Stat(file)
			if name == "retired" {
				if !os.IsNotExist(err) {
					t.Errorf("retired key remains: %s", file)
				}
			} else if err != nil {
				t.Errorf("%s key removed: %v", name, err)
			}
		}
	}
}
