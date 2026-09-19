package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/releases"
)

// fakeGitHubRelease serves SHA256SUMS.txt + the named binary asset from an
// httptest.Server, standing in for GitHub Releases. binaryContent is a shell
// script so the smoke test (`<binary> version`) can actually execute it.
func fakeGitHubRelease(t *testing.T, binaryName, binaryContent string) *httptest.Server {
	t.Helper()
	sum := sha256.Sum256([]byte(binaryContent))
	sums := fmt.Sprintf("%s  %s\n", hex.EncodeToString(sum[:]), binaryName)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/SHA256SUMS.txt"):
			_, _ = w.Write([]byte(sums))
		case strings.HasSuffix(r.URL.Path, "/"+binaryName):
			_, _ = w.Write([]byte(binaryContent))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// pointReleasesAt overrides the package-level GitHubReleaseBaseURL for the
// duration of the test, restoring it on cleanup.
func pointReleasesAt(t *testing.T, url string) {
	t.Helper()
	orig := releases.GitHubReleaseBaseURL
	releases.GitHubReleaseBaseURL = url
	t.Cleanup(func() { releases.GitHubReleaseBaseURL = orig })
}

// stubRestartAfterGitHubSwap replaces the real systemctl/watchdog side
// effects with a call counter for the duration of the test. Production code
// must never invoke systemctl during a unit test run.
func stubRestartAfterGitHubSwap(t *testing.T) *int {
	t.Helper()
	calls := 0
	orig := restartAfterGitHubSwap
	restartAfterGitHubSwap = func(string) { calls++ }
	t.Cleanup(func() { restartAfterGitHubSwap = orig })
	return &calls
}

const okScript = "#!/bin/sh\necho fake-version\nexit 0\n"

func writeExecutable(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0755); err != nil { // #nosec G306 -- test fixture binary needs +x
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestRunGitHubUpgrade_SwapsBinaryOnChecksumMismatch(t *testing.T) {
	srv := fakeGitHubRelease(t, githubUpgradeBinaryName, okScript)
	pointReleasesAt(t, srv.URL)
	calls := stubRestartAfterGitHubSwap(t)

	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "containariumd")
	writeExecutable(t, binaryPath, "#!/bin/sh\necho old-version\nexit 0\n")

	changed, err := runGitHubUpgrade(context.Background(), binaryPath, "v0.99.0", false)
	if err != nil {
		t.Fatalf("runGitHubUpgrade: %v", err)
	}
	if !changed {
		t.Fatal("expected changed=true on a checksum mismatch")
	}

	gotBinary, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatalf("read swapped binary: %v", err)
	}
	if string(gotBinary) != okScript {
		t.Errorf("binary content = %q, want the fetched release content", gotBinary)
	}

	oldBinary, err := os.ReadFile(binaryPath + ".old")
	if err != nil {
		t.Fatalf("read .old binary: %v", err)
	}
	if !strings.Contains(string(oldBinary), "old-version") {
		t.Errorf(".old content = %q, want the original binary preserved", oldBinary)
	}

	if _, err := os.Stat(binaryPath + ".new"); !os.IsNotExist(err) {
		t.Errorf(".new tmp file should be gone after a successful swap")
	}

	if *calls != 1 {
		t.Errorf("restartAfterGitHubSwap called %d times, want 1", *calls)
	}
}

func TestRunGitHubUpgrade_NoopWhenChecksumMatchesAndNotForced(t *testing.T) {
	srv := fakeGitHubRelease(t, githubUpgradeBinaryName, okScript)
	pointReleasesAt(t, srv.URL)
	calls := stubRestartAfterGitHubSwap(t)

	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "containariumd")
	writeExecutable(t, binaryPath, okScript) // already matches the release

	changed, err := runGitHubUpgrade(context.Background(), binaryPath, "v0.99.0", false)
	if err != nil {
		t.Fatalf("runGitHubUpgrade: %v", err)
	}
	if changed {
		t.Error("expected changed=false when local binary already matches the release")
	}
	if *calls != 0 {
		t.Errorf("restartAfterGitHubSwap called %d times, want 0 on a no-op", *calls)
	}
	if _, err := os.Stat(binaryPath + ".old"); !os.IsNotExist(err) {
		t.Error(".old should not be created on a no-op")
	}
}

func TestRunGitHubUpgrade_ForceSwapsEvenWhenChecksumMatches(t *testing.T) {
	srv := fakeGitHubRelease(t, githubUpgradeBinaryName, okScript)
	pointReleasesAt(t, srv.URL)
	calls := stubRestartAfterGitHubSwap(t)

	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "containariumd")
	writeExecutable(t, binaryPath, okScript) // already matches the release

	changed, err := runGitHubUpgrade(context.Background(), binaryPath, "v0.99.0", true)
	if err != nil {
		t.Fatalf("runGitHubUpgrade: %v", err)
	}
	if !changed {
		t.Error("expected changed=true when force=true, even with matching checksums")
	}
	if *calls != 1 {
		t.Errorf("restartAfterGitHubSwap called %d times, want 1", *calls)
	}
}

func TestRunGitHubUpgrade_UnpublishedTagIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	pointReleasesAt(t, srv.URL)
	calls := stubRestartAfterGitHubSwap(t)

	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "containariumd")
	writeExecutable(t, binaryPath, okScript)

	_, err := runGitHubUpgrade(context.Background(), binaryPath, "v9.9.9-nope", false)
	if err == nil {
		t.Fatal("expected an error for an unpublished tag")
	}
	if *calls != 0 {
		t.Errorf("restartAfterGitHubSwap called %d times, want 0 on error", *calls)
	}
	// The original binary must be untouched.
	got, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatalf("read binary: %v", err)
	}
	if string(got) != okScript {
		t.Error("original binary was modified despite the fetch failing")
	}
}

func TestRunGitHubUpgrade_ChecksumMismatchAfterDownloadIsError(t *testing.T) {
	// SHA256SUMS.txt lies about the asset's checksum.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/SHA256SUMS.txt"):
			_, _ = w.Write([]byte("0000000000000000000000000000000000000000000000000000000000000000  " + githubUpgradeBinaryName + "\n"))
		case strings.HasSuffix(r.URL.Path, "/"+githubUpgradeBinaryName):
			_, _ = w.Write([]byte(okScript))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	pointReleasesAt(t, srv.URL)
	calls := stubRestartAfterGitHubSwap(t)

	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "containariumd")
	writeExecutable(t, binaryPath, "#!/bin/sh\necho old-version\nexit 0\n")

	_, err := runGitHubUpgrade(context.Background(), binaryPath, "v0.99.0", false)
	if err == nil {
		t.Fatal("expected a checksum-mismatch error")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("error = %v, want a checksum mismatch error", err)
	}
	if *calls != 0 {
		t.Errorf("restartAfterGitHubSwap called %d times, want 0 on error", *calls)
	}
	if _, err := os.Stat(binaryPath + ".new"); !os.IsNotExist(err) {
		t.Error(".new tmp file should be removed after a checksum-mismatch failure")
	}
	got, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatalf("read binary: %v", err)
	}
	if !strings.Contains(string(got), "old-version") {
		t.Error("original binary must be left in place when the download fails verification")
	}
}

func TestRunGitHubUpgrade_SmokeTestFailureLeavesOriginalBinaryInPlace(t *testing.T) {
	badScript := "#!/bin/sh\nexit 1\n"
	srv := fakeGitHubRelease(t, githubUpgradeBinaryName, badScript)
	pointReleasesAt(t, srv.URL)
	calls := stubRestartAfterGitHubSwap(t)

	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "containariumd")
	writeExecutable(t, binaryPath, "#!/bin/sh\necho old-version\nexit 0\n")

	_, err := runGitHubUpgrade(context.Background(), binaryPath, "v0.99.0", false)
	if err == nil {
		t.Fatal("expected a smoke-test failure error")
	}
	if !strings.Contains(err.Error(), "smoke test failed") {
		t.Errorf("error = %v, want a smoke test error", err)
	}
	if *calls != 0 {
		t.Errorf("restartAfterGitHubSwap called %d times, want 0 on smoke-test failure", *calls)
	}
	if _, err := os.Stat(binaryPath + ".new"); !os.IsNotExist(err) {
		t.Error(".new tmp file should be removed after a smoke-test failure")
	}
	got, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatalf("read binary: %v", err)
	}
	if !strings.Contains(string(got), "old-version") {
		t.Error("original binary must be left in place when the new binary fails its smoke test")
	}
}
