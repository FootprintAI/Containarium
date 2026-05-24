package credentials

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// withTempHome redirects $HOME to a freshly created tempdir for the
// duration of the test. Returns the path so callers can assert on
// it. Uses t.Setenv so the env var is reverted automatically.
func withTempHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	// macOS / windows also honor USERPROFILE in some Go stdlib
	// paths; set it too so DefaultPath is deterministic across
	// platforms.
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	}
	return home
}

func TestDefaultPath_UsesHome(t *testing.T) {
	home := withTempHome(t)
	got, err := DefaultPath()
	if err != nil {
		t.Fatalf("DefaultPath: %v", err)
	}
	want := filepath.Join(home, DefaultRelPath)
	if got != want {
		t.Fatalf("DefaultPath = %q, want %q", got, want)
	}
}

func TestLoad_MissingFile_ReturnsEmpty(t *testing.T) {
	home := withTempHome(t)
	path := filepath.Join(home, DefaultRelPath)

	cf, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cf == nil {
		t.Fatal("Load returned nil for missing file")
	}
	if len(cf.Servers) != 0 {
		t.Fatalf("Load returned %d servers for missing file, want 0", len(cf.Servers))
	}
	if cf.DefaultServer != "" {
		t.Fatalf("Load returned DefaultServer = %q for missing file", cf.DefaultServer)
	}
}

func TestLoad_EmptyFile_ReturnsEmpty(t *testing.T) {
	home := withTempHome(t)
	dir := filepath.Join(home, ".containarium")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(dir, "credentials.json")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatalf("write empty file: %v", err)
	}
	cf, err := Load(path)
	if err != nil {
		t.Fatalf("Load on empty file: %v", err)
	}
	if len(cf.Servers) != 0 {
		t.Fatalf("Load on empty file produced %d servers", len(cf.Servers))
	}
}

func TestLoad_MalformedJSON_Errors(t *testing.T) {
	home := withTempHome(t)
	dir := filepath.Join(home, ".containarium")
	_ = os.MkdirAll(dir, 0o700)
	path := filepath.Join(dir, "credentials.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load on malformed JSON expected error, got nil")
	}
}

func TestSaveLoad_RoundTrip(t *testing.T) {
	home := withTempHome(t)
	path := filepath.Join(home, DefaultRelPath)

	issued := time.Date(2026, 5, 24, 10, 15, 30, 0, time.UTC)
	cf := NewCredentialsFile()
	cf.Set("https://cloud.containarium.dev", ServerCreds{
		Token:     "ctnr_a7B3",
		UserEmail: "alice@example.com",
		OrgID:     "org_123",
		IssuedAt:  issued,
		ExpiresAt: nil,
	})

	if err := Save(path, cf); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// File mode should be 0600.
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Fatalf("file mode = %o, want 0600", st.Mode().Perm())
	}

	// Round-trip.
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	creds, ok := got.Get("https://cloud.containarium.dev")
	if !ok {
		t.Fatal("Get after Save: not found")
	}
	if creds.Token != "ctnr_a7B3" || creds.UserEmail != "alice@example.com" || creds.OrgID != "org_123" {
		t.Fatalf("creds mismatch: %+v", creds)
	}
	if !creds.IssuedAt.Equal(issued) {
		t.Fatalf("IssuedAt = %v, want %v", creds.IssuedAt, issued)
	}
	if creds.ExpiresAt != nil {
		t.Fatalf("ExpiresAt = %v, want nil", creds.ExpiresAt)
	}
	if got.DefaultServer != "https://cloud.containarium.dev" {
		t.Fatalf("DefaultServer = %q, want auto-set to the only server", got.DefaultServer)
	}
}

func TestSave_ExpiresAtSerializesAsNull(t *testing.T) {
	home := withTempHome(t)
	path := filepath.Join(home, DefaultRelPath)
	cf := NewCredentialsFile()
	cf.Set("https://x", ServerCreds{Token: "t", IssuedAt: time.Now()})
	if err := Save(path, cf); err != nil {
		t.Fatalf("Save: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// Must contain `"expires_at": null` — locked PRD field.
	if !strings.Contains(string(b), `"expires_at": null`) {
		t.Fatalf("file missing expires_at: null marker:\n%s", string(b))
	}
}

func TestMultiServer_Isolation(t *testing.T) {
	home := withTempHome(t)
	path := filepath.Join(home, DefaultRelPath)

	cf := NewCredentialsFile()
	cf.Set("https://cloud.containarium.dev", ServerCreds{Token: "cloud-tok", UserEmail: "alice@example.com"})
	cf.Set("https://self-hosted.example.com", ServerCreds{Token: "self-tok", UserEmail: "alice@example.com"})
	cf.DefaultServer = "https://cloud.containarium.dev"

	if err := Save(path, cf); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	cloudCreds, ok := got.Get("https://cloud.containarium.dev")
	if !ok || cloudCreds.Token != "cloud-tok" {
		t.Fatalf("cloud lookup failed: %+v ok=%v", cloudCreds, ok)
	}
	selfCreds, ok := got.Get("https://self-hosted.example.com")
	if !ok || selfCreds.Token != "self-tok" {
		t.Fatalf("self-hosted lookup failed: %+v ok=%v", selfCreds, ok)
	}
	// Empty server → default.
	defCreds, ok := got.Get("")
	if !ok || defCreds.Token != "cloud-tok" {
		t.Fatalf("default lookup failed: %+v ok=%v", defCreds, ok)
	}
}

func TestNormalizeServer(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"https://cloud.containarium.dev", "https://cloud.containarium.dev"},
		{"https://cloud.containarium.dev/", "https://cloud.containarium.dev"},
		{"HTTPS://Cloud.Containarium.Dev/", "https://cloud.containarium.dev"},
		{"  https://x/  ", "https://x"},
		{"cloud.containarium.dev", "cloud.containarium.dev"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := NormalizeServer(tc.in); got != tc.want {
			t.Errorf("NormalizeServer(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestGet_TolerantLookup(t *testing.T) {
	cf := NewCredentialsFile()
	// Stored with trailing slash (older / hand-edited).
	cf.Servers["https://cloud.containarium.dev/"] = ServerCreds{Token: "tok"}
	cf.DefaultServer = "https://cloud.containarium.dev/"

	got, ok := cf.Get("https://cloud.containarium.dev")
	if !ok {
		t.Fatal("tolerant Get failed")
	}
	if got.Token != "tok" {
		t.Fatalf("got %q, want tok", got.Token)
	}
}

func TestRemove_ClearsDefaultIfMatches(t *testing.T) {
	home := withTempHome(t)
	path := filepath.Join(home, DefaultRelPath)

	cf := NewCredentialsFile()
	cf.Set("https://a", ServerCreds{Token: "a"})
	cf.Set("https://b", ServerCreds{Token: "b"})
	cf.DefaultServer = "https://a"

	if removed := cf.Remove("https://a"); !removed {
		t.Fatal("Remove returned false for present server")
	}
	if cf.DefaultServer != "" {
		t.Fatalf("DefaultServer = %q after removing it, want cleared", cf.DefaultServer)
	}
	// Save → repair default to the remaining server.
	if err := Save(path, cf); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, _ := Load(path)
	if got.DefaultServer != "https://b" {
		t.Fatalf("DefaultServer after Save = %q, want auto-repaired to https://b", got.DefaultServer)
	}
}

func TestRemove_AbsentReturnsFalse(t *testing.T) {
	cf := NewCredentialsFile()
	cf.Set("https://a", ServerCreds{Token: "a"})
	if cf.Remove("https://missing") {
		t.Fatal("Remove returned true for absent server")
	}
}

func TestSave_AtomicReplaceLeavesNoTempFiles(t *testing.T) {
	home := withTempHome(t)
	path := filepath.Join(home, DefaultRelPath)
	cf := NewCredentialsFile()
	cf.Set("https://x", ServerCreds{Token: "t"})
	for i := 0; i < 3; i++ {
		if err := Save(path, cf); err != nil {
			t.Fatalf("Save #%d: %v", i, err)
		}
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

func TestSchema_MatchesPRDExample(t *testing.T) {
	// PRD-locked example from prd/cloud/cli-login-and-multi-env-ssh.md
	// §"Credentials file format". We unmarshal the exact JSON and
	// verify every field round-trips.
	const example = `{
  "default_server": "https://cloud.containarium.dev",
  "servers": {
    "https://cloud.containarium.dev": {
      "token": "ctnr_a7B3...",
      "user_email": "alice@example.com",
      "org_id": "...",
      "issued_at": "2026-05-24T10:15:30Z",
      "expires_at": null
    }
  }
}`
	var cf CredentialsFile
	if err := json.Unmarshal([]byte(example), &cf); err != nil {
		t.Fatalf("PRD example failed to parse: %v", err)
	}
	if cf.DefaultServer != "https://cloud.containarium.dev" {
		t.Fatalf("DefaultServer = %q", cf.DefaultServer)
	}
	creds, ok := cf.Servers["https://cloud.containarium.dev"]
	if !ok {
		t.Fatal("PRD example missing server entry after parse")
	}
	if creds.Token != "ctnr_a7B3..." || creds.UserEmail != "alice@example.com" || creds.OrgID != "..." {
		t.Fatalf("creds mismatch: %+v", creds)
	}
	if creds.ExpiresAt != nil {
		t.Fatalf("ExpiresAt = %v, want nil for PRD null", creds.ExpiresAt)
	}
	want := time.Date(2026, 5, 24, 10, 15, 30, 0, time.UTC)
	if !creds.IssuedAt.Equal(want) {
		t.Fatalf("IssuedAt = %v, want %v", creds.IssuedAt, want)
	}
}
