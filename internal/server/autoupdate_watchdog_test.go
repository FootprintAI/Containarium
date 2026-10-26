package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestAutoUpdaterWatchdogHealthURL verifies SetWatchdogHealthURL stores the URL.
func TestAutoUpdaterWatchdogHealthURL(t *testing.T) {
	u := NewAutoUpdater("http://sentinel:8888", "/tmp/bin", time.Minute)
	if u.watchdogHealthURL != "" {
		t.Errorf("default watchdogHealthURL should be empty, got %q", u.watchdogHealthURL)
	}
	u.SetWatchdogHealthURL("http://localhost:9999/health")
	if u.watchdogHealthURL != "http://localhost:9999/health" {
		t.Errorf("watchdogHealthURL not set: %q", u.watchdogHealthURL)
	}
}

// TestWatchdogRollback verifies that RunUpgradeWatchdog restores .old
// when the health endpoint never returns 200.
func TestWatchdogRollback(t *testing.T) {
	// Serve a health endpoint that always returns 503.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "containarium")
	oldPath := binaryPath + ".old"

	// Simulate: new binary is at binaryPath, old binary is at .old.
	if err := os.WriteFile(binaryPath, []byte("new"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oldPath, []byte("old"), 0755); err != nil {
		t.Fatal(err)
	}

	err := RunUpgradeWatchdog(binaryPath, srv.URL+"/health",
		3*time.Second, // short timeout for the test
		500*time.Millisecond,
		500*time.Millisecond,
		true, // dryRun: skip systemctl restart
	)
	if err != nil {
		t.Fatalf("watchdog returned unexpected error: %v", err)
	}

	// .old should have been renamed back to binaryPath.
	contents, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatalf("binary not found after rollback: %v", err)
	}
	if string(contents) != "old" {
		t.Errorf("binary contents after rollback: got %q, want %q", string(contents), "old")
	}
	// .old should be gone after the rename.
	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Errorf(".old should not exist after rollback")
	}
}

// TestWatchdogHealthy verifies that when the health endpoint returns 200 the
// watchdog removes .old and returns nil.
func TestWatchdogHealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "containarium")
	oldPath := binaryPath + ".old"

	if err := os.WriteFile(binaryPath, []byte("new"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oldPath, []byte("old"), 0755); err != nil {
		t.Fatal(err)
	}

	err := RunUpgradeWatchdog(binaryPath, srv.URL+"/health",
		10*time.Second,
		0, // no initial delay
		200*time.Millisecond,
		true,
	)
	if err != nil {
		t.Fatalf("watchdog returned error on healthy daemon: %v", err)
	}

	// Binary should still be the new one.
	contents, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatalf("binary not found: %v", err)
	}
	if string(contents) != "new" {
		t.Errorf("binary contents after healthy upgrade: got %q, want %q", string(contents), "new")
	}
	// .old should be removed.
	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Errorf(".old should be removed after successful upgrade")
	}
}

// TestWatchdogHealthyKeepsPrev (#3058): a passing /health must not delete the
// only rollback binary. .old is renamed to .prev, and a .prev left by an
// earlier upgrade is overwritten.
func TestWatchdogHealthyKeepsPrev(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "containarium")
	for p, c := range map[string]string{
		binaryPath:           "new",
		binaryPath + ".old":  "previous",
		binaryPath + ".prev": "two-releases-ago",
	} {
		if err := os.WriteFile(p, []byte(c), 0755); err != nil {
			t.Fatal(err)
		}
	}

	if err := RunUpgradeWatchdog(binaryPath, srv.URL+"/health", 10*time.Second, 0, 200*time.Millisecond, true); err != nil {
		t.Fatalf("watchdog error: %v", err)
	}

	got, err := os.ReadFile(binaryPath + ".prev")
	if err != nil {
		t.Fatalf(".prev missing after healthy check: %v", err)
	}
	if string(got) != "previous" {
		t.Errorf(".prev = %q, want %q (previous .prev must be overwritten)", got, "previous")
	}
	if _, err := os.Stat(binaryPath + ".old"); !os.IsNotExist(err) {
		t.Errorf(".old should have been renamed to .prev")
	}
}

// TestWatchdogHealthyNoOld: healthy check with no .old is a no-op, and an
// existing .prev is left alone.
func TestWatchdogHealthyNoOld(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "containarium")
	_ = os.WriteFile(binaryPath, []byte("new"), 0755)
	_ = os.WriteFile(binaryPath+".prev", []byte("keep"), 0755)
	if err := RunUpgradeWatchdog(binaryPath, srv.URL+"/health", 10*time.Second, 0, 200*time.Millisecond, true); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(binaryPath + ".prev"); string(got) != "keep" {
		t.Errorf(".prev = %q, want keep", got)
	}
}

// TestLaunchWatchdogWritesLog (#3058): the detached watchdog's stdout/stderr
// land in a known file beside the binary, created 0600 and appended to.
func TestLaunchWatchdogWritesLog(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "containarium")
	script := "#!/bin/sh\necho \"fake-watchdog args: $*\"\necho \"fake-watchdog stderr\" >&2\n"
	if err := os.WriteFile(bin, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	logPath := WatchdogLogPath(bin)
	if err := os.WriteFile(logPath, []byte("earlier run\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	u := &AutoUpdater{binaryPath: bin}
	u.launchWatchdog()

	deadline := time.Now().Add(5 * time.Second)
	var data []byte
	for time.Now().Before(deadline) {
		data, _ = os.ReadFile(logPath)
		if strings.Contains(string(data), "fake-watchdog stderr") {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	s := string(data)
	if !strings.Contains(s, "earlier run") {
		t.Errorf("log was truncated, not appended: %q", s)
	}
	if !strings.Contains(s, "fake-watchdog args: upgrade-watchdog") || !strings.Contains(s, "fake-watchdog stderr") {
		t.Errorf("log missing stdout/stderr output: %q", s)
	}
	fi, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("log mode %v, want no group/other access", fi.Mode().Perm())
	}
}

// TestLaunchWatchdogLogCreatedSafe: a fresh log is created with 0600.
func TestLaunchWatchdogLogCreatedSafe(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "containarium")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho hi\n"), 0755); err != nil {
		t.Fatal(err)
	}
	(&AutoUpdater{binaryPath: bin}).launchWatchdog()
	fi, err := os.Stat(WatchdogLogPath(bin))
	if err != nil {
		t.Fatalf("log not created: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", fi.Mode().Perm())
	}
}
