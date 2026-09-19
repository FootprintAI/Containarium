package server

import (
	"context"
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

// githubUpgradeBinaryName matches selfupdate.go's releaseBinaryName — the
// daemon artifact published alongside SHA256SUMS.txt on every release (#1779).
const githubUpgradeBinaryName = "containariumd-linux-amd64"

// restartAfterGitHubSwap launches the upgrade watchdog and restarts services
// after a successful GitHub-direct binary swap, mirroring the tail of
// AutoUpdater.checkAndUpdate. A package var (not a plain call) so tests can
// stub out the real systemctl/watchdog side effects — see github_upgrade_test.go.
var restartAfterGitHubSwap = func(binaryPath string) {
	(&AutoUpdater{binaryPath: binaryPath}).launchWatchdog()

	go func() {
		time.Sleep(1 * time.Second)
		if exec.Command("systemctl", "is-active", "containarium-tunnel").Run() == nil { // #nosec G204
			log.Printf("[github-upgrade] restarting containarium-tunnel...")
			_ = exec.Command("systemctl", "restart", "containarium-tunnel").Run() // #nosec G204
		}
		log.Printf("[github-upgrade] restarting containarium...")
		if err := exec.Command("systemctl", "restart", "containarium").Run(); err != nil { // #nosec G204
			_ = exec.Command("systemctl", "restart", "containarium-daemon").Run() // #nosec G204
		}
	}()
}

// runGitHubUpgrade downloads containariumd-linux-amd64 for the given GitHub
// release tag directly from GitHub Releases (#1028), verifies it against the
// published SHA256SUMS.txt, smoke-tests it, and atomically swaps it into
// place — the same download/verify/swap sequence AutoUpdater.checkAndUpdate
// uses for the sentinel-served path, but pulling straight from GitHub.
//
// Deliberately NOT sharing checkAndUpdate's body: that method is untested,
// production-critical code every sentinel-connected daemon relies on daily
// (see #1547). Keeping this as its own self-contained function means a bug
// in the GitHub-direct path can't touch the sentinel path, and vice versa.
// Only the risk-free pieces are reused: checksumFile (a pure free function)
// and AutoUpdater.launchWatchdog (via a throwaway struct value, since it
// only reads binaryPath).
//
// Returns whether the binary was swapped (false only on a non-force no-op
// match against the tag's published checksum). On success the daemon
// restarts via restartAfterGitHubSwap, so the caller should treat a nil
// error with changed=true as "upgrade started."
func runGitHubUpgrade(ctx context.Context, binaryPath, tag string, force bool) (bool, error) {
	remoteChecksum, err := releases.FetchSHA256(ctx, tag, githubUpgradeBinaryName)
	if err != nil {
		return false, fmt.Errorf("fetch SHA256SUMS for %s: %w", tag, err)
	}

	localChecksum, err := checksumFile(binaryPath)
	if err != nil {
		return false, fmt.Errorf("checksum local binary: %w", err)
	}

	if remoteChecksum == localChecksum && !force {
		return false, nil
	}
	if remoteChecksum == localChecksum {
		log.Printf("[github-upgrade] forced upgrade; binary already matches %s (%s...)", tag, localChecksum[:12])
	} else {
		log.Printf("[github-upgrade] installing %s (local=%s..., remote=%s...)", tag, localChecksum[:12], remoteChecksum[:12])
	}

	tmpPath := binaryPath + ".new"
	if err := downloadGitHubBinary(ctx, tag, tmpPath); err != nil {
		_ = os.Remove(tmpPath)
		return false, fmt.Errorf("download: %w", err)
	}

	dlChecksum, err := checksumFile(tmpPath)
	if err != nil {
		_ = os.Remove(tmpPath)
		return false, fmt.Errorf("verify download: %w", err)
	}
	if dlChecksum != remoteChecksum {
		_ = os.Remove(tmpPath)
		return false, fmt.Errorf("checksum mismatch after download (got %s, want %s)", dlChecksum[:12], remoteChecksum[:12])
	}

	if err := os.Chmod(tmpPath, 0755); err != nil { // #nosec G302 -- executable binary needs 0755
		_ = os.Remove(tmpPath)
		return false, fmt.Errorf("chmod: %w", err)
	}

	// Smoke-test before committing the swap, same safeguard checkAndUpdate
	// applies: the new binary must at least execute and print its version.
	smokeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	smokeOut, smokeErr := exec.CommandContext(smokeCtx, tmpPath, "version").CombinedOutput() // #nosec G204 -- tmpPath derived from trusted binaryPath
	cancel()
	if smokeErr != nil {
		_ = os.Remove(tmpPath)
		return false, fmt.Errorf("smoke test failed (new binary did not run `version`): %w; output: %s", smokeErr, strings.TrimSpace(string(smokeOut)))
	}

	oldPath := binaryPath + ".old"
	_ = os.Remove(oldPath)
	if err := os.Rename(binaryPath, oldPath); err != nil {
		_ = os.Remove(tmpPath)
		return false, fmt.Errorf("rename old binary: %w", err)
	}
	if err := os.Rename(tmpPath, binaryPath); err != nil {
		_ = os.Rename(oldPath, binaryPath)
		return false, fmt.Errorf("rename new binary: %w", err)
	}

	log.Printf("[github-upgrade] binary replaced with %s, restarting...", tag)
	restartAfterGitHubSwap(binaryPath)

	return true, nil
}

func downloadGitHubBinary(ctx context.Context, tag, destPath string) error {
	url := releases.BinaryDownloadURL(tag, githubUpgradeBinaryName)
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

	f, err := os.Create(destPath) // #nosec G304 -- destPath is a temp file derived from trusted binaryPath config
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return err
	}
	return f.Close()
}
