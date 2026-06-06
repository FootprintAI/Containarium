package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// AutoUpdater periodically checks the sentinel for a newer binary and
// self-updates if a new version is available.
type AutoUpdater struct {
	sentinelURL string // e.g. "http://10.130.0.13:8888"
	binaryPath  string // e.g. "/usr/local/bin/containarium"
	interval    time.Duration
}

// NewAutoUpdater creates a new auto-updater.
func NewAutoUpdater(sentinelURL, binaryPath string, interval time.Duration) *AutoUpdater {
	return &AutoUpdater{
		sentinelURL: sentinelURL,
		binaryPath:  binaryPath,
		interval:    interval,
	}
}

// Run starts the auto-update loop. Blocks until ctx is cancelled.
func (u *AutoUpdater) Run(ctx context.Context) {
	log.Printf("[auto-update] started (check interval: %s, sentinel: %s)", u.interval, u.sentinelURL)

	// Wait before first check to let the daemon fully start
	select {
	case <-time.After(2 * time.Minute):
	case <-ctx.Done():
		return
	}

	ticker := time.NewTicker(u.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("[auto-update] stopped")
			return
		case <-ticker.C:
			if _, err := u.checkAndUpdate(ctx, false); err != nil {
				log.Printf("[auto-update] check failed: %v", err)
			}
		}
	}
}

// TriggerNow runs an upgrade check immediately instead of waiting for the next
// tick. Returns whether the binary was swapped. With force=true it re-pulls and
// swaps even when the sentinel-served binary already matches the running one
// (useful to force a restart onto the sentinel's binary). On success the daemon
// restarts, so callers should treat a nil error as "upgrade started" and
// confirm via the post-restart version. #354 Phase B.
func (u *AutoUpdater) TriggerNow(ctx context.Context, force bool) (bool, error) {
	return u.checkAndUpdate(ctx, force)
}

func (u *AutoUpdater) checkAndUpdate(ctx context.Context, force bool) (bool, error) {
	// 1. Get remote checksum
	remoteChecksum, err := u.getRemoteChecksum(ctx)
	if err != nil {
		return false, fmt.Errorf("get remote checksum: %w", err)
	}

	// 2. Get local checksum
	localChecksum, err := u.getLocalChecksum()
	if err != nil {
		return false, fmt.Errorf("get local checksum: %w", err)
	}

	// 3. Compare
	if remoteChecksum == localChecksum && !force {
		return false, nil // up to date
	}
	if remoteChecksum == localChecksum {
		log.Printf("[auto-update] forced upgrade; binary already matches sentinel (%s...)", localChecksum[:12])
	} else {
		log.Printf("[auto-update] new version detected (local=%s..., remote=%s...)", localChecksum[:12], remoteChecksum[:12])
	}

	// 4. Download new binary
	tmpPath := u.binaryPath + ".new"
	if err := u.downloadBinary(ctx, tmpPath); err != nil {
		_ = os.Remove(tmpPath)
		return false, fmt.Errorf("download: %w", err)
	}

	// 5. Verify downloaded binary checksum
	dlChecksum, err := checksumFile(tmpPath)
	if err != nil {
		_ = os.Remove(tmpPath)
		return false, fmt.Errorf("verify download: %w", err)
	}
	if dlChecksum != remoteChecksum {
		_ = os.Remove(tmpPath)
		return false, fmt.Errorf("checksum mismatch after download (got %s, want %s)", dlChecksum[:12], remoteChecksum[:12])
	}

	// 6. Make executable
	if err := os.Chmod(tmpPath, 0755); err != nil { // #nosec G302 -- executable binary needs 0755
		_ = os.Remove(tmpPath)
		return false, fmt.Errorf("chmod: %w", err)
	}

	// 6b. Smoke-test the downloaded binary before committing the swap: it must
	// at least execute and print its version. Guards against a corrupt or
	// incompatible binary that would otherwise leave the host running a daemon
	// that won't start. The previous binary is kept as .old for manual
	// rollback. #354 — pre-swap safety.
	smokeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	smokeOut, smokeErr := exec.CommandContext(smokeCtx, tmpPath, "version").CombinedOutput() // #nosec G204 -- tmpPath derived from trusted binaryPath
	cancel()
	if smokeErr != nil {
		_ = os.Remove(tmpPath)
		return false, fmt.Errorf("smoke test failed (new binary did not run `version`): %w; output: %s", smokeErr, strings.TrimSpace(string(smokeOut)))
	}

	// 7. Replace: rename running binary to .old, move new one in place
	oldPath := u.binaryPath + ".old"
	_ = os.Remove(oldPath)
	if err := os.Rename(u.binaryPath, oldPath); err != nil {
		_ = os.Remove(tmpPath)
		return false, fmt.Errorf("rename old binary: %w", err)
	}
	if err := os.Rename(tmpPath, u.binaryPath); err != nil {
		// Try to restore old binary
		_ = os.Rename(oldPath, u.binaryPath)
		return false, fmt.Errorf("rename new binary: %w", err)
	}

	log.Printf("[auto-update] binary replaced successfully, restarting...")

	// 8. Restart services via systemd (async — we'll be killed)
	// Restart tunnel first (it also uses the same binary), then the daemon.
	go func() {
		time.Sleep(1 * time.Second)
		// Restart tunnel if it exists (peers only)
		if exec.Command("systemctl", "is-active", "containarium-tunnel").Run() == nil { // #nosec G204
			log.Printf("[auto-update] restarting containarium-tunnel...")
			_ = exec.Command("systemctl", "restart", "containarium-tunnel").Run() // #nosec G204
		}
		// Restart daemon (this kills us)
		log.Printf("[auto-update] restarting containarium...")
		if err := exec.Command("systemctl", "restart", "containarium").Run(); err != nil { // #nosec G204
			_ = exec.Command("systemctl", "restart", "containarium-daemon").Run() // #nosec G204
		}
	}()

	return true, nil
}

func (u *AutoUpdater) getRemoteChecksum(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", u.sentinelURL+"/containarium/checksum", nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func (u *AutoUpdater) getLocalChecksum() (string, error) {
	return checksumFile(u.binaryPath)
}

func (u *AutoUpdater) downloadBinary(ctx context.Context, destPath string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", u.sentinelURL+"/containarium", nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}

	f, err := os.Create(destPath) // #nosec G304 -- destPath is a temp file derived from trusted binaryPath config
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return err
	}
	return f.Close()
}

func checksumFile(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- path is the binary path from trusted config
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
