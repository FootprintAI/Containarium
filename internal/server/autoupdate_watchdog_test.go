package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
