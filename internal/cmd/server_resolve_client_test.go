//go:build containarium_client

package cmd

import (
	"testing"

	"github.com/footprintai/containarium/internal/credentials"
)

// writeDefaultServer writes a minimal credentials.json under a temp HOME
// (set via t.Setenv, so it's undone automatically) with the given
// default_server, so resolveServerAddr's fallback has something to read.
func writeDefaultServer(t *testing.T, defaultServer string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	path, err := credentials.DefaultPath()
	if err != nil {
		t.Fatalf("DefaultPath: %v", err)
	}
	cf := credentials.NewCredentialsFile()
	// Set (not a bare DefaultServer assignment) is required: Save
	// auto-repairs an unset-in-Servers DefaultServer back to empty, so the
	// server needs a real (if minimal) entry to survive the write.
	cf.Set(defaultServer, credentials.ServerCreds{Token: "test-token"})
	if err := credentials.Save(path, cf); err != nil {
		t.Fatalf("Save: %v", err)
	}
}

func TestResolveServerAddr_Client(t *testing.T) {
	t.Run("non-empty flag/env wins over credentials file", func(t *testing.T) {
		writeDefaultServer(t, "https://from-file.example.com")
		if got := resolveServerAddr("https://from-flag.example.com"); got != "https://from-flag.example.com" {
			t.Errorf("resolveServerAddr = %q, want the flag/env value unchanged", got)
		}
	})

	t.Run("empty falls back to credentials file default_server", func(t *testing.T) {
		writeDefaultServer(t, "https://from-file.example.com")
		if got := resolveServerAddr(""); got != "https://from-file.example.com" {
			t.Errorf("resolveServerAddr = %q, want default_server from the credentials file", got)
		}
	})

	t.Run("empty stays empty with no credentials file", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir()) // no credentials.json written here
		if got := resolveServerAddr(""); got != "" {
			t.Errorf("resolveServerAddr = %q, want empty (no file, no fallback)", got)
		}
	})
}
