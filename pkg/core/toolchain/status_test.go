package toolchain

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeRelease(t *testing.T, root, manifest string) {
	t.Helper()
	dir := filepath.Join(root, "releases", "r1")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("releases/r1", filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
}

func TestReadStatus(t *testing.T) {
	tests := []struct {
		name          string
		setup         func(t *testing.T, root string)
		wantInstalled bool
		wantMissing   bool
		wantRelease   string
		wantArch      string
	}{
		{
			name:        "no toolchain directory at all",
			setup:       func(t *testing.T, root string) { _ = os.RemoveAll(root) },
			wantMissing: true,
		},
		{
			name:        "root exists without a current release",
			setup:       func(t *testing.T, root string) {},
			wantMissing: true,
		},
		{
			name: "active release",
			setup: func(t *testing.T, root string) {
				writeRelease(t, root, `{"schema_version":1,"release":"v0.123.0","arch":"amd64"}`)
			},
			wantInstalled: true,
			wantRelease:   "v0.123.0",
			wantArch:      "amd64",
		},
		{
			name: "manifest present but not JSON is not reported as missing",
			setup: func(t *testing.T, root string) {
				writeRelease(t, root, `not json`)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "toolchains")
			if err := os.MkdirAll(root, 0755); err != nil {
				t.Fatal(err)
			}
			tt.setup(t, root)
			st := ReadStatus(root)
			if st.Installed != tt.wantInstalled {
				t.Fatalf("Installed = %v, want %v (err %v)", st.Installed, tt.wantInstalled, st.Err)
			}
			if st.Missing() != tt.wantMissing {
				t.Fatalf("Missing() = %v, want %v (err %v)", st.Missing(), tt.wantMissing, st.Err)
			}
			if st.Release != tt.wantRelease || st.Arch != tt.wantArch {
				t.Fatalf("release/arch = %q/%q, want %q/%q", st.Release, st.Arch, tt.wantRelease, tt.wantArch)
			}
			if !st.Installed && st.Err == nil {
				t.Fatal("a status that is not installed must carry the reason")
			}
		})
	}
}

func TestMissingAdvicePointsAtTheInstallDoc(t *testing.T) {
	for _, want := range []string{HostRoot, InstallDoc, "BUILD_TOOLS"} {
		if !strings.Contains(MissingAdvice, want) {
			t.Fatalf("MissingAdvice %q does not mention %q", MissingAdvice, want)
		}
	}
}
