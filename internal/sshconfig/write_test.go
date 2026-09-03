package sshconfig

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The regression this file exists for: a sync whose enumeration came back
// empty overwrote a 44-host config with an empty file and reported success.
func TestWriteConfig_RefusesToWipeNonEmptyConfigWithZeroHosts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ssh_config")
	existing := "Host box-a\n  HostName 10.0.0.1\n"
	if err := os.WriteFile(path, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := WriteConfig(path, Generated{Content: "", Count: 0}, false)
	if !errors.Is(err, ErrRefusedEmptyOverwrite) {
		t.Fatalf("want ErrRefusedEmptyOverwrite, got %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != existing {
		t.Fatalf("existing config was modified:\n%q", got)
	}
}

func TestWriteConfig_ForceAllowsTheWipe(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ssh_config")
	if err := os.WriteFile(path, []byte("Host box-a\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	backedUp, err := WriteConfig(path, Generated{Content: "", Count: 0}, true)
	if err != nil {
		t.Fatalf("force write: %v", err)
	}
	if !backedUp {
		t.Error("force overwrite should still leave a .bak")
	}
	got, _ := os.ReadFile(path)
	if len(got) != 0 {
		t.Fatalf("want empty after forced write, got %q", got)
	}
	bak, err := os.ReadFile(path + ".bak")
	if err != nil || string(bak) != "Host box-a\n" {
		t.Fatalf("backup missing or wrong: %q (%v)", bak, err)
	}
}

func TestWriteConfig_TableDriven(t *testing.T) {
	tests := []struct {
		name        string
		existing    string // "" = no file
		gen         Generated
		force       bool
		wantErr     bool
		wantContent string
		wantBackup  bool
	}{
		{
			name:        "zero hosts over absent file is fine",
			gen:         Generated{Content: "", Count: 0},
			wantContent: "",
		},
		{
			name:        "zero hosts over EMPTY file is fine",
			existing:    "",
			gen:         Generated{Content: "", Count: 0},
			wantContent: "",
		},
		{
			name:        "normal write over existing keeps a backup",
			existing:    "Host old\n",
			gen:         Generated{Content: "Host new\n", Count: 1},
			wantContent: "Host new\n",
			wantBackup:  true,
		},
		{
			name:        "zero hosts over non-empty is refused",
			existing:    "Host old\n",
			gen:         Generated{Content: "", Count: 0},
			wantErr:     true,
			wantContent: "Host old\n",
		},
		{
			name:        "first write, no prior file, no backup",
			gen:         Generated{Content: "Host new\n", Count: 1},
			wantContent: "Host new\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "ssh_config")
			// Distinguish "no file" from "empty file": the zero-host guard
			// only trips on a file with content.
			if tt.existing != "" || tt.name == "zero hosts over EMPTY file is fine" {
				if err := os.WriteFile(path, []byte(tt.existing), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			backedUp, err := WriteConfig(path, tt.gen, tt.force)
			if tt.wantErr != (err != nil) {
				t.Fatalf("err = %v, wantErr = %v", err, tt.wantErr)
			}
			if backedUp != tt.wantBackup {
				t.Errorf("backedUp = %v, want %v", backedUp, tt.wantBackup)
			}

			got, readErr := os.ReadFile(path)
			if tt.wantContent == "" && os.IsNotExist(readErr) {
				return // absent is an acceptable form of "empty"
			}
			if readErr != nil {
				t.Fatalf("read back: %v", readErr)
			}
			if string(got) != tt.wantContent {
				t.Errorf("content = %q, want %q", got, tt.wantContent)
			}
		})
	}
}

func TestWriteConfig_ModeIs0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ssh_config")
	if _, err := WriteConfig(path, Generated{Content: "Host a\n", Count: 1}, false); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// The file lists every host the caller can reach; it must not widen
	// just because it now goes through a temp file + rename.
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 600", perm)
	}
}

func TestWriteConfig_LeavesNoTempFileBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ssh_config")
	if _, err := WriteConfig(path, Generated{Content: "Host a\n", Count: 1}, false); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "ssh_config" {
			t.Errorf("unexpected leftover file: %s", e.Name())
		}
	}
}
