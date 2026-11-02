package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/footprintai/containarium/internal/auth"
)

// AutoUpdater periodically checks the sentinel for a newer binary and
// self-updates if a new version is available.
type AutoUpdater struct {
	sentinelURL       string // e.g. "http://10.130.0.13:8888"
	binaryPath        string // e.g. "/usr/local/bin/containariumd" (#1779)
	interval          time.Duration
	watchdogHealthURL string // polled by upgrade-watchdog to confirm liveness (#507); defaults to http://localhost:8080/health

	// Short-lived cache of the sentinel-served version (#2171). Callers such
	// as a control plane rendering a host page hit GetLatestRelease often, and
	// each sentinel lookup checksums the served binary.
	servedMu      sync.Mutex
	servedVersion string
	servedAt      time.Time

	// Trust in the sentinel's answers. The checksum decides which binary the
	// daemon downloads and executes, so it must be authenticated, not merely
	// fetched. verifier checks the sentinel's signature on /containarium/checksum
	// and /containarium/version. requireSigned (CONTAINARIUM_AUTO_UPDATE_REQUIRE_SIGNED=1)
	// refuses an unsigned answer; by default (warn-only, first release) an unsigned
	// answer is allowed with a loud log so a fleet can roll sentinels first. A
	// signature that is present but invalid is always refused.
	verifier       auth.SentinelVerifier
	requireSigned  bool
	warnedUnsigned atomic.Bool
}

// servedVersionTTL bounds how stale ServedVersion may be. A fetch-release on
// the sentinel shows up within this window.
const servedVersionTTL = time.Minute

// NewAutoUpdater creates a new auto-updater.
func NewAutoUpdater(sentinelURL, binaryPath string, interval time.Duration) *AutoUpdater {
	return &AutoUpdater{
		sentinelURL:   sentinelURL,
		binaryPath:    binaryPath,
		interval:      interval,
		verifier:      auth.NewSentinelVerifier(loadSentinelPublicKey(), loadSentinelHMACSecret()),
		requireSigned: os.Getenv("CONTAINARIUM_AUTO_UPDATE_REQUIRE_SIGNED") == "1",
	}
}

// SetVerifier overrides how the sentinel's responses are authenticated.
func (u *AutoUpdater) SetVerifier(v auth.SentinelVerifier, requireSigned bool) {
	u.verifier, u.requireSigned = v, requireSigned
}

// noRedirect stops a plaintext sentinel hop from bouncing the daemon elsewhere.
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

var sha256HexRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// authenticate decides whether a sentinel response body may be trusted.
//   - signature present and verifiable: must be valid, else refused
//   - signature present but this host holds no key for its algorithm:
//     "unverifiable" - refused when requireSigned, else warned and allowed
//   - no signature: refused when requireSigned OR when this host has a key
//     (an attacker can strip headers, so a host that can verify must insist);
//     only a host with no key at all is warned and allowed
func (u *AutoUpdater) authenticate(resp *http.Response, body []byte) error {
	sig := resp.Header.Get(auth.SentinelHeaderSignature)
	if sig != "" {
		if !u.verifier.CanVerify(sig) {
			if u.requireSigned {
				return fmt.Errorf("sentinel response is signed but this host has no key to verify it")
			}
			u.warnUnsigned("response is signed with an algorithm this host has no key for; cannot verify")
			return nil
		}
		if err := u.verifier.VerifyResponse(resp, body, time.Now()); err != nil {
			return fmt.Errorf("sentinel response signature invalid: %w", err)
		}
		return nil
	}
	if u.requireSigned || u.verifier.Configured() {
		return fmt.Errorf("sentinel response is unsigned but this host can verify signatures; refusing")
	}
	u.warnUnsigned("response is unsigned and this host has no sentinel key configured")
	return nil
}

func (u *AutoUpdater) warnUnsigned(why string) {
	if u.warnedUnsigned.CompareAndSwap(false, true) {
		log.Printf("[auto-update] WARNING: sentinel %s — the update checksum is not authenticated. Upgrade the sentinel to sign it, then set CONTAINARIUM_AUTO_UPDATE_REQUIRE_SIGNED=1", why)
	}
}

// SetWatchdogHealthURL overrides the health endpoint the upgrade watchdog polls
// to confirm the new binary is live. Defaults to http://localhost:8080/health.
func (u *AutoUpdater) SetWatchdogHealthURL(url string) {
	u.watchdogHealthURL = url
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

	// 8. Launch a detached upgrade watchdog before restarting. The watchdog
	// outlives this process (new session via Setsid) and polls the health
	// endpoint; if the new binary doesn't become healthy within 90s it
	// restores .old and restarts the service automatically (#507).
	u.launchWatchdog()

	// 9. Restart services via systemd (async — we'll be killed)
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

// ServedVersion returns the version of the binary the sentinel currently
// serves — what a sentinel-path upgrade would install — from the sentinel's
// /containarium/version. Errors (including a 404 from an older sentinel
// without the route) mean "unknown"; they are not cached. #2171.
func (u *AutoUpdater) ServedVersion(ctx context.Context) (string, error) {
	u.servedMu.Lock()
	defer u.servedMu.Unlock()
	if u.servedVersion != "" && time.Since(u.servedAt) < servedVersionTTL {
		return u.servedVersion, nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", u.sentinelURL+"/containarium/version", nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	if err := u.authenticate(resp, raw); err != nil {
		return "", err
	}
	var body struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return "", fmt.Errorf("decode: %w", err)
	}
	if body.Version == "" {
		return "", fmt.Errorf("empty version")
	}
	u.servedVersion, u.servedAt = body.Version, time.Now()
	return body.Version, nil
}

func (u *AutoUpdater) getRemoteChecksum(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", u.sentinelURL+"/containarium/checksum", nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: noRedirect}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	if err := u.authenticate(resp, body); err != nil {
		return "", err
	}
	sum := strings.TrimSpace(string(body))
	if !sha256HexRE.MatchString(sum) {
		return "", fmt.Errorf("sentinel returned a malformed checksum")
	}
	return sum, nil
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
	defer func() { _ = f.Close() }()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return err
	}
	return f.Close()
}

// RunUpgradeWatchdog polls healthURL until the daemon is healthy or timeout
// elapses. On success the previous binary (.old) is kept as .prev. On
// timeout, if binaryPath+".old" exists, it restores .old and
// optionally restarts the service. dryRun skips the systemctl restart.
// This is the testable core called by both the daemon and the CLI subcommand.
func RunUpgradeWatchdog(binaryPath, healthURL string, timeout, initialDelay, pollInterval time.Duration, dryRun bool) error {
	oldPath := binaryPath + ".old"

	if initialDelay > 0 {
		time.Sleep(initialDelay)
	}

	log.Printf("[upgrade-watchdog] polling %s (timeout %s, interval %s)", healthURL, timeout, pollInterval)

	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 3 * time.Second}

	for time.Now().Before(deadline) {
		resp, err := client.Get(healthURL) //nolint:noctx
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				log.Printf("[upgrade-watchdog] daemon is healthy — upgrade succeeded")
				// Keep the previous binary as .prev (#3058): /health only
				// proves liveness, so the release may still be broken and
				// this is the only rollback binary. Overwrites the .prev of
				// the previous upgrade.
				if _, err := os.Stat(oldPath); err == nil {
					if err := os.Rename(oldPath, binaryPath+".prev"); err != nil {
						log.Printf("[upgrade-watchdog] WARNING: keep previous binary as .prev: %v", err)
					} else {
						log.Printf("[upgrade-watchdog] previous binary kept as %s.prev", binaryPath)
					}
				}
				return nil
			}
		}
		time.Sleep(pollInterval)
	}

	if _, err := os.Stat(oldPath); os.IsNotExist(err) {
		return fmt.Errorf("[upgrade-watchdog] daemon not healthy after %s and no .old binary; manual intervention required", timeout)
	}

	log.Printf("[upgrade-watchdog] daemon not healthy after %s — rolling back to .old", timeout)
	if err := os.Rename(oldPath, binaryPath); err != nil {
		return fmt.Errorf("[upgrade-watchdog] rename .old back: %w", err)
	}
	log.Printf("[upgrade-watchdog] binary restored")

	if dryRun {
		return nil
	}

	log.Printf("[upgrade-watchdog] restarting containarium service")
	out, err := exec.Command("systemctl", "restart", "containarium").CombinedOutput() // #nosec G204
	if err != nil {
		log.Printf("[upgrade-watchdog] systemctl restart failed (%v; %s) — exiting for service-manager restart", err, string(out))
		os.Exit(1)
	}
	log.Printf("[upgrade-watchdog] rollback complete")
	return nil
}

// WatchdogLogPath is the file the detached upgrade watchdog appends its
// output to: upgrade-watchdog.log in the binary's directory (#3058).
func WatchdogLogPath(binaryPath string) string {
	return filepath.Join(filepath.Dir(binaryPath), "upgrade-watchdog.log")
}

// launchWatchdog spawns the upgrade-watchdog subcommand in a detached process
// (new session via Setsid) so it outlives the current daemon process through
// the systemctl restart (#507). Errors are best-effort logged — a watchdog
// launch failure is not fatal to the upgrade itself.
func (u *AutoUpdater) launchWatchdog() {
	healthURL := u.watchdogHealthURL
	if healthURL == "" {
		healthURL = "http://localhost:8080/health"
	}
	cmd := exec.Command(u.binaryPath, // #nosec G204 -- binaryPath is trusted config
		"upgrade-watchdog",
		"--binary-path", u.binaryPath,
		"--health-url", healthURL,
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // detach from parent process group
	// #3058: the child is detached, so without a file its log output (and
	// any rollback trace) is lost. Append to a 0600 file beside the binary.
	logPath := WatchdogLogPath(u.binaryPath)
	if lf, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err != nil { // #nosec G304 -- derived from trusted binaryPath config
		log.Printf("[auto-update] WARNING: cannot open watchdog log %s: %v — watchdog output will be lost", logPath, err)
	} else {
		_ = lf.Chmod(0o600)
		cmd.Stdout = lf
		cmd.Stderr = lf
		defer func() { _ = lf.Close() }() // child holds its own dup after Start
	}
	if err := cmd.Start(); err != nil {
		log.Printf("[auto-update] WARNING: failed to launch upgrade watchdog: %v — rollback on failure will not be available", err)
		return
	}
	log.Printf("[auto-update] upgrade watchdog launched (pid %d)", cmd.Process.Pid)
	// Do NOT cmd.Wait() — the watchdog outlives this process intentionally.
}

func checksumFile(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- path is the binary path from trusted config
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
