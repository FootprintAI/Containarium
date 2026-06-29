package sentinel

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/releases"
)

const (
	githubReleaseBaseURL = "https://github.com/FootprintAI/Containarium/releases/download"
	releaseBinaryName    = "containarium-linux-amd64"
)

type fetchReleaseRequest struct {
	Tag string `json:"tag"`
}

// fetchReleaseHandler returns an HTTP handler for POST /sentinel/fetch-release.
// It downloads the named release from GitHub, verifies SHA256SUMS.txt,
// smoke-tests the binary, atomically swaps it, and restarts the sentinel service.
func fetchReleaseHandler(binaryPath string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		var req fetchReleaseRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid JSON body"}`, http.StatusBadRequest)
			return
		}
		tag := strings.TrimSpace(req.Tag)
		if tag == "" {
			http.Error(w, `{"error":"tag is required (e.g. \"v0.48.0\" or \"latest\")"}`, http.StatusBadRequest)
			return
		}

		ctx := r.Context()

		// Resolve "latest" → concrete tag via GitHub API.
		if tag == "latest" {
			rel, _, err := releases.NewClient().Latest(ctx)
			if err != nil {
				http.Error(w, fmt.Sprintf(`{"error":"resolve latest tag: %v"}`, err), http.StatusBadGateway)
				return
			}
			tag = rel.TagName
		}

		// Normalise: ensure the "v" prefix that GitHub release URLs require.
		if !strings.HasPrefix(tag, "v") {
			tag = "v" + tag
		}

		log.Printf("[sentinel-selfupdate] operator requested upgrade to %s", tag)

		if err := fetchAndInstallRelease(ctx, tag, binaryPath); err != nil {
			log.Printf("[sentinel-selfupdate] upgrade to %s failed: %v", tag, err)
			http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"message": "binary swapped — containarium-sentinel restarting momentarily",
			"tag":     tag,
		})

		// Give the response a moment to flush before the restart kills us.
		go func() {
			time.Sleep(500 * time.Millisecond)
			log.Printf("[sentinel-selfupdate] restarting containarium-sentinel…")
			if err := exec.Command("systemctl", "restart", "containarium-sentinel").Run(); err != nil { // #nosec G204
				// Fallback: if systemctl fails (e.g. not running under systemd),
				// hard-exit so the service manager (if any) restarts the process.
				log.Printf("[sentinel-selfupdate] systemctl restart failed (%v); exiting for service-manager restart", err)
				os.Exit(0)
			}
		}()
	})
}

// fetchAndInstallRelease downloads the containarium-linux-amd64 binary for
// the given tag from GitHub Releases, verifies it against SHA256SUMS.txt,
// smoke-tests it with `version`, and atomically swaps the sentinel binary.
// Callers restart the sentinel service after this returns nil.
func fetchAndInstallRelease(ctx context.Context, tag, binaryPath string) error {
	base := githubReleaseBaseURL + "/" + tag
	binURL := base + "/" + releaseBinaryName
	sumsURL := base + "/SHA256SUMS.txt"

	// 1. Fetch expected hash from SHA256SUMS.txt.
	expectedHash, err := fetchExpectedHash(ctx, sumsURL, releaseBinaryName)
	if err != nil {
		return fmt.Errorf("fetch SHA256SUMS.txt for %s: %w", tag, err)
	}

	// 2. Download the binary to a temp path.
	tmpPath := binaryPath + ".new"
	if err := downloadReleaseBinary(ctx, binURL, tmpPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("download %s binary: %w", tag, err)
	}

	// 3. Verify checksum. checksumFile is defined in autoupdate.go (server pkg)
	// — here we inline the same logic to keep the sentinel package self-contained.
	actualHash, err := checksumFileSentinel(tmpPath)
	if err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("checksum new binary: %w", err)
	}
	if actualHash != expectedHash {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("checksum mismatch (got %.12s, want %.12s)", actualHash, expectedHash)
	}

	// 4. Make executable and smoke-test.
	if err := os.Chmod(tmpPath, 0755); err != nil { // #nosec G302 -- executable binary requires 0755
		_ = os.Remove(tmpPath)
		return fmt.Errorf("chmod new binary: %w", err)
	}
	smokeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	out, smokeErr := exec.CommandContext(smokeCtx, tmpPath, "version").CombinedOutput() // #nosec G204 -- tmpPath derived from trusted binaryPath config
	cancel()
	if smokeErr != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("smoke test failed: %w; output: %s", smokeErr, strings.TrimSpace(string(out)))
	}

	// 5. Atomic swap: current → .old, new → current.
	oldPath := binaryPath + ".old"
	_ = os.Remove(oldPath)
	if err := os.Rename(binaryPath, oldPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("save old binary: %w", err)
	}
	if err := os.Rename(tmpPath, binaryPath); err != nil {
		_ = os.Rename(oldPath, binaryPath) // restore on failure
		return fmt.Errorf("install new binary: %w", err)
	}

	log.Printf("[sentinel-selfupdate] binary swapped to %s (sha256: %.12s…)", tag, actualHash)
	return nil
}

// fetchExpectedHash downloads SHA256SUMS.txt from url and returns the hash
// for the given filename.
func fetchExpectedHash(ctx context.Context, sumsURL, filename string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sumsURL, nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d from %s", resp.StatusCode, sumsURL)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	// SHA256SUMS.txt format: "<hash>  <filename>" (two spaces, GNU sha256sum style)
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		name := strings.TrimPrefix(fields[1], "./")
		if name == filename {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("%q not found in SHA256SUMS.txt", filename)
}

// downloadReleaseBinary downloads the binary at url to dest.
func downloadReleaseBinary(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d from %s", resp.StatusCode, url)
	}
	f, err := os.Create(dest) // #nosec G304 -- dest is binaryPath+".new", derived from trusted config
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if _, err := io.Copy(f, resp.Body); err != nil {
		return err
	}
	return f.Close()
}

// checksumFileSentinel computes the SHA-256 hex digest of path.
// Mirrors server.checksumFile; kept here so the sentinel package doesn't
// import the server package.
func checksumFileSentinel(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- path is binaryPath+".new"
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
