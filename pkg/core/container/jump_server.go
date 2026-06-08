package container

import (
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Note: As of Go 1.20, rand is automatically seeded

// useraddMu serializes useradd invocations within the same daemon
// process. Cloud #163 — two concurrent box creates (CI provisioning
// in parallel) race the /etc/passwd lock; even though we use `flock
// -w 30` for the cross-process case, two in-process goroutines can
// both win flock + both call useradd before the first finishes, at
// which point useradd's own lock contention surfaces as the
// "cannot lock /etc/passwd" retry storm in the logs.
//
// Holding this mutex around the entire flock+useradd path means
// only one useradd at a time per daemon process, regardless of how
// many CI jobs are provisioning boxes concurrently. The cross-process
// case still relies on the existing flock + stale-lock cleanup.
var useraddMu sync.Mutex

// CreateJumpServerAccount creates a proxy-only user account on the jump server
// The account is configured with /usr/sbin/nologin shell, preventing direct shell access
// while still allowing SSH ProxyJump to work for accessing containers.
func CreateJumpServerAccount(username string, sshPublicKey string, verbose bool) error {
	if verbose {
		fmt.Printf("  Creating jump server account: %s (proxy-only)\n", username)
	}

	// Validate inputs
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}
	if sshPublicKey == "" {
		return fmt.Errorf("SSH public key cannot be empty")
	}

	// Sanitize username (allow only alphanumeric, dash, underscore)
	if !isValidUsername(username) {
		return fmt.Errorf("invalid username: must contain only letters, numbers, dash, and underscore")
	}

	// Check if user already exists
	if userExists(username) {
		if verbose {
			fmt.Printf("  Jump server account %s already exists, updating SSH key and shell\n", username)
		}
		// Ensure shell is set to nologin (in case it was created with wrong shell)
		if err := ensureProxyOnlyShell(username, verbose); err != nil {
			return fmt.Errorf("failed to ensure proxy-only shell: %w", err)
		}
		return updateUserSSHKey(username, sshPublicKey, verbose)
	}

	// Create user with nologin shell (proxy-only, no shell access)
	// Wait for lock files to clear and retry useradd if needed
	if err := retryUseraddWithLockWait(username, verbose); err != nil {
		return err
	}

	// Setup SSH key
	if err := setupUserSSHKey(username, sshPublicKey, verbose); err != nil {
		// Cleanup on failure
		_ = exec.Command("userdel", "-r", username).Run()
		return err
	}

	// Sudoers entry for incus access. Required when the user's login shell is
	// containarium-shell (proxies into the container via `sudo incus exec`).
	// Harmless when the shell is nologin (no login = no sudo).
	sudoersEntry := fmt.Sprintf("%s ALL=(root) NOPASSWD: /usr/bin/incus\n", username)
	sudoersPath := fmt.Sprintf("/etc/sudoers.d/containarium-%s", username)
	if err := os.WriteFile(sudoersPath, []byte(sudoersEntry), 0440); err != nil { // #nosec G306 -- sudoers requires 0440
		_ = exec.Command("userdel", "-r", username).Run()
		return fmt.Errorf("failed to write sudoers: %w", err)
	}

	if verbose {
		fmt.Printf("  ✓ Jump server account created: %s\n", username)
	}

	return nil
}

// DeleteJumpServerAccount removes a user account from the jump server
func DeleteJumpServerAccount(username string, verbose bool) error {
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}

	if !userExists(username) {
		if verbose {
			fmt.Printf("  Jump server account %s does not exist, skipping\n", username)
		}
		return nil // Already deleted or never existed
	}

	if verbose {
		fmt.Printf("  Deleting jump server account: %s\n", username)
	}

	// Delete user and home directory - wait for locks to clear
	if err := waitForLocksAndRun(func() error {
		cmd := exec.Command("userdel", "-r", username)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to delete user %s: %w\nOutput: %s", username, err, output)
		}
		return nil
	}, verbose); err != nil {
		return err
	}

	if verbose {
		fmt.Printf("  ✓ Jump server account deleted: %s\n", username)
	}

	return nil
}

// EnsureJumpServerAccount creates a host-level user with containarium-shell
// as the login shell, enabling SSH access through sshpiper into the user's
// Incus container. This is called automatically when a container is created.
// It is idempotent — if the account already exists, it just ensures the shell
// and permissions are correct.
func EnsureJumpServerAccount(username string) error {
	if !isValidUsername(username) {
		return fmt.Errorf("invalid username: %s", username)
	}

	shellPath := "/usr/local/bin/containarium-shell"

	if userExists(username) {
		// Ensure shell is containarium-shell
		// #nosec G204 -- username validated by isValidUsername above (alphanumeric, dash, underscore only)
		_ = exec.Command("usermod", "-s", shellPath, username).Run()
		return nil
	}

	// Create user with containarium-shell
	// #nosec G204 -- username validated by isValidUsername above
	if err := exec.Command("useradd", "-m", "-s", shellPath,
		"-c", fmt.Sprintf("Containarium user - %s", username),
		username).Run(); err != nil {
		return fmt.Errorf("useradd failed: %w", err)
	}

	// Unlock account (useradd creates locked accounts, sshd rejects them).
	// Set password to '*' which means "no valid password" but account is not
	// locked. This allows public key auth while preventing password login.
	// Note: passwd -d sets an empty password which some distros reject;
	// usermod -p '*' is the portable approach.
	// #nosec G204 -- username validated by isValidUsername above
	_ = exec.Command("usermod", "-p", "*", username).Run()

	// Set home dir permissions (sshd requires 755 or stricter)
	_ = os.Chmod(fmt.Sprintf("/home/%s", username), 0755) // #nosec G302 -- sshd requires home dir to be world-readable

	// Create .ssh dir
	sshDir := fmt.Sprintf("/home/%s/.ssh", username)
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return fmt.Errorf("failed to create .ssh dir: %w", err)
	}
	// #nosec G204 -- username validated by isValidUsername above
	_ = exec.Command("chown", "-R", username+":"+username, sshDir).Run()

	// Sudoers entry for incus access (containarium-shell needs it)
	sudoersEntry := fmt.Sprintf("%s ALL=(root) NOPASSWD: /usr/bin/incus\n", username)
	sudoersPath := fmt.Sprintf("/etc/sudoers.d/containarium-%s", username)
	if err := os.WriteFile(sudoersPath, []byte(sudoersEntry), 0440); err != nil { // #nosec G306 -- sudoers requires 0440
		return fmt.Errorf("failed to write sudoers: %w", err)
	}

	return nil
}

// isValidUsername checks if username contains only allowed characters
func isValidUsername(username string) bool {
	if len(username) == 0 || len(username) > 32 {
		return false
	}

	for _, ch := range username {
		if (ch < 'a' || ch > 'z') &&
			(ch < 'A' || ch > 'Z') &&
			(ch < '0' || ch > '9') &&
			ch != '-' && ch != '_' {
			return false
		}
	}

	// Cannot start with digit or dash
	firstChar := rune(username[0])
	if (firstChar >= '0' && firstChar <= '9') || firstChar == '-' {
		return false
	}

	return true
}

// userExists checks if a system user exists
func userExists(username string) bool {
	cmd := exec.Command("id", username)
	return cmd.Run() == nil
}

// UserExists is the exported version of userExists for use by CLI commands
func UserExists(username string) bool {
	return userExists(username)
}

// ExtractSSHKey extracts the SSH public key from inside a container.
// The key is read from /home/{username}/.ssh/authorized_keys inside the container.
func (m *Manager) ExtractSSHKey(containerName, username string, verbose bool) (string, error) {
	// Check if container is running
	info, err := m.incus.GetContainer(containerName)
	if err != nil {
		return "", fmt.Errorf("container not found: %w", err)
	}

	// If container is stopped, try to start it temporarily
	wasStarted := false
	if info.State != "Running" {
		if verbose {
			fmt.Printf("       Starting container %s to extract SSH key...\n", containerName)
		}
		if err := m.incus.StartContainer(containerName); err != nil {
			return "", fmt.Errorf("failed to start container: %w", err)
		}
		wasStarted = true
		// Wait for container to be ready
		time.Sleep(3 * time.Second)
	}

	// Try to read the SSH key from the container
	authorizedKeysPath := fmt.Sprintf("/home/%s/.ssh/authorized_keys", username)

	if verbose {
		fmt.Printf("       Reading SSH key from %s:%s\n", containerName, authorizedKeysPath)
	}

	keyContent, err := m.incus.ReadFile(containerName, authorizedKeysPath)
	if err != nil {
		// Try root's authorized_keys as fallback
		if verbose {
			fmt.Printf("       Primary path failed, trying /root/.ssh/authorized_keys...\n")
		}
		keyContent, err = m.incus.ReadFile(containerName, "/root/.ssh/authorized_keys")
		if err != nil {
			// Stop container if we started it
			if wasStarted {
				_ = m.incus.StopContainer(containerName, false)
			}
			return "", fmt.Errorf("could not read SSH key from container: %w", err)
		}
	}

	// Stop container if we started it
	if wasStarted {
		if verbose {
			fmt.Printf("       Stopping container %s...\n", containerName)
		}
		_ = m.incus.StopContainer(containerName, false)
	}

	// Parse the authorized_keys file - get the first valid SSH key
	lines := strings.Split(string(keyContent), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Validate it looks like an SSH key
		if strings.HasPrefix(line, "ssh-rsa ") ||
			strings.HasPrefix(line, "ssh-ed25519 ") ||
			strings.HasPrefix(line, "ssh-ecdsa ") ||
			strings.HasPrefix(line, "ecdsa-sha2-") ||
			strings.HasPrefix(line, "ssh-dss ") {
			return line, nil
		}
	}

	return "", fmt.Errorf("no valid SSH key found in authorized_keys")
}

// setupUserSSHKey sets up SSH key for a user
func setupUserSSHKey(username, sshPublicKey string, verbose bool) error {
	homeDir := filepath.Join("/home", username)
	sshDir := filepath.Join(homeDir, ".ssh")
	authKeysFile := filepath.Join(sshDir, "authorized_keys")

	// Create .ssh directory
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return fmt.Errorf("failed to create .ssh directory: %w", err)
	}

	// Clean up SSH key (remove extra whitespace, ensure newline)
	cleanKey := strings.TrimSpace(sshPublicKey)

	// Write SSH key
	if err := os.WriteFile(authKeysFile, []byte(cleanKey+"\n"), 0600); err != nil {
		return fmt.Errorf("failed to write authorized_keys: %w", err)
	}

	// Set ownership (must run as root/sudo)
	cmd := exec.Command("chown", "-R", fmt.Sprintf("%s:%s", username, username), sshDir)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set ownership: %w\nOutput: %s", err, output)
	}

	if verbose {
		fmt.Printf("  ✓ SSH key configured for %s\n", username)
	}

	return nil
}

// updateUserSSHKey updates SSH key for existing user
func updateUserSSHKey(username, sshPublicKey string, verbose bool) error {
	homeDir := filepath.Join("/home", username)
	sshDir := filepath.Join(homeDir, ".ssh")
	authKeysFile := filepath.Join(sshDir, "authorized_keys")

	// Ensure .ssh directory exists
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return fmt.Errorf("failed to create .ssh directory: %w", err)
	}

	// Set ownership on .ssh directory
	cmd := exec.Command("chown", fmt.Sprintf("%s:%s", username, username), sshDir)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set .ssh ownership: %w\nOutput: %s", err, output)
	}

	// Read existing keys
	existingKeys := ""
	if data, err := os.ReadFile(authKeysFile); err == nil {
		existingKeys = string(data)
	}

	// Clean up new key
	cleanKey := strings.TrimSpace(sshPublicKey)

	// Check if key already exists
	if strings.Contains(existingKeys, cleanKey) {
		if verbose {
			fmt.Printf("  SSH key already exists for %s\n", username)
		}
		return nil // Key already present
	}

	// Append new key
	f, err := os.OpenFile(authKeysFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return fmt.Errorf("failed to open authorized_keys: %w", err)
	}
	defer func() { _ = f.Close() }()

	if _, err := f.WriteString(cleanKey + "\n"); err != nil {
		return fmt.Errorf("failed to write SSH key: %w", err)
	}

	// Set ownership on authorized_keys
	cmd = exec.Command("chown", fmt.Sprintf("%s:%s", username, username), authKeysFile)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set authorized_keys ownership: %w\nOutput: %s", err, output)
	}

	if verbose {
		fmt.Printf("  ✓ SSH key added for %s\n", username)
	}

	return nil
}

// containerShellPath is the path to the containarium-shell wrapper that
// proxies SSH sessions into Incus containers. When present, it's used
// instead of nologin so that SSH sessions land inside the container.
const containerShellPath = "/usr/local/bin/containarium-shell"

// getUserShell returns the shell to use for containarium host accounts.
// If containarium-shell wrapper exists (standalone/tunnel backends), use it
// so SSH sessions are proxied into the container. Otherwise use nologin
// (sentinel/GCP backends where sshpiper handles routing).
func getUserShell() string {
	if _, err := os.Stat(containerShellPath); err == nil {
		return containerShellPath
	}
	return "/usr/sbin/nologin"
}

// ensureProxyOnlyShell ensures the user's shell is set correctly
func ensureProxyOnlyShell(username string, verbose bool) error {
	shell := getUserShell()
	// Wait for locks to clear before modifying user
	if err := waitForLocksAndRun(func() error {
		cmd := exec.Command("usermod", "-s", shell, username)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to set shell for %s: %w\nOutput: %s", username, err, output)
		}
		return nil
	}, verbose); err != nil {
		return err
	}

	if verbose {
		fmt.Printf("  ✓ Shell set to %s for %s\n", shell, username)
	}

	return nil
}

// waitForLocksAndRun stops google-guest-agent, executes the function, then restarts it.
// On non-GCP hosts the stop/start sequence is meaningless (google-guest-agent
// doesn't exist) and produces misleading errors, so we just run fn directly.
// Issue #351.
func waitForLocksAndRun(fn func() error, verbose bool) error {
	if !isGCPHost() {
		if verbose {
			fmt.Printf("       Skipping google-guest-agent dance: host is not a GCP VM\n")
		}
		return fn()
	}

	if verbose {
		fmt.Printf("       Temporarily stopping google-guest-agent...\n")
	}

	// Stop google-guest-agent
	cmd := exec.Command("systemctl", "stop", "google-guest-agent")
	if output, err := cmd.CombinedOutput(); err != nil && verbose {
		fmt.Printf("       Warning: Failed to stop google-guest-agent: %v\n%s\n", err, output)
	}

	// Ensure we restart it when done
	defer func() {
		if verbose {
			fmt.Printf("       Restarting google-guest-agent...\n")
		}
		cmd := exec.Command("systemctl", "start", "google-guest-agent")
		if output, err := cmd.CombinedOutput(); err != nil && verbose {
			fmt.Printf("       Warning: Failed to restart google-guest-agent: %v\n%s\n", err, output)
		}
	}()

	// Wait a moment for the agent to fully stop
	time.Sleep(2 * time.Second)

	// Execute the operation
	return fn()
}

// retryUseraddWithLockWait stops google-guest-agent, creates user, then restarts it
func retryUseraddWithLockWait(username string, verbose bool) error {
	// Cloud #163 — serialize within-process so two concurrent box
	// creates don't race the /etc/passwd lock. The flock command
	// below handles the cross-process case; this handles
	// goroutine-vs-goroutine.
	useraddMu.Lock()
	defer useraddMu.Unlock()

	const maxRetries = 10 // Bumped from 5 (cloud #163). Combined with the new exponential backoff below, total ceiling is ~6min vs the old 10s — gives stale passwd locks enough room to clear or be force-removed.

	// Pre-useradd dance: stop google-guest-agent, wait for the
	// passwd lock to clear, force-remove if stuck. This is GCP-VM
	// specific — google-guest-agent races with local useradd over
	// /etc/.pwd.lock via OS Login. On a non-GCP backend (VirtualBox
	// lab spot, on-prem, AWS/Azure, …) the service doesn't exist
	// and the lockfile is held by something else legitimately;
	// running this dance just produces misleading "Access denied"
	// stderr and force-removes a lock we shouldn't touch. Issue
	// #351 — gate it on host-class detection.
	lockFiles := []string{"/etc/passwd.lock", "/etc/shadow.lock", "/etc/.pwd.lock", "/etc/group.lock"}
	if isGCPHost() {
		fmt.Printf("       Temporarily stopping google-guest-agent to avoid race condition...\n")

		// Stop google-guest-agent
		cmd := exec.Command("systemctl", "stop", "google-guest-agent")
		if output, err := cmd.CombinedOutput(); err != nil {
			fmt.Printf("       Warning: Failed to stop google-guest-agent: %v\n%s\n", err, output)
			fmt.Printf("       Proceeding anyway...\n")
		} else {
			fmt.Printf("       ✓ google-guest-agent stopped\n")
		}

		// Kill any remaining google processes that might be holding locks
		killGoogleProcesses(verbose)

		// Ensure we restart it when done
		defer func() {
			fmt.Printf("       Restarting google-guest-agent...\n")
			cmd := exec.Command("systemctl", "start", "google-guest-agent")
			if output, err := cmd.CombinedOutput(); err != nil {
				fmt.Printf("       Warning: Failed to restart google-guest-agent: %v\n%s\n", err, output)
			} else {
				fmt.Printf("       ✓ google-guest-agent restarted\n")
			}
		}()

		// Wait for the agent to fully stop and release locks
		fmt.Printf("       Waiting for agent to stop and release locks...\n")
		time.Sleep(2 * time.Second)

		// Check if agent actually stopped
		checkCmd := exec.Command("systemctl", "is-active", "google-guest-agent")
		if statusOutput, _ := checkCmd.CombinedOutput(); len(statusOutput) > 0 {
			fmt.Printf("       Agent status after stop: %s\n", strings.TrimSpace(string(statusOutput)))
		}

		// Wait for lock files to clear (up to 10 seconds)
		locksClear := false
		for attempt := 0; attempt < 10; attempt++ {
			allClear := true
			for _, lockFile := range lockFiles {
				if _, err := os.Stat(lockFile); err == nil {
					allClear = false
					if attempt == 0 {
						fmt.Printf("       Waiting for lock file to clear: %s\n", lockFile)
					}
					break
				}
			}
			if allClear {
				locksClear = true
				break
			}
			time.Sleep(1 * time.Second)
		}

		if !locksClear {
			fmt.Printf("       Warning: Lock files still present after waiting, forcing removal...\n")
			// Since we stopped google-guest-agent, any remaining lock files are stale
			// Forcibly remove them regardless of age
			forceRemoveLockFiles(lockFiles, verbose)
		} else {
			fmt.Printf("       ✓ All lock files cleared\n")
		}
	} else if verbose {
		fmt.Printf("       Skipping google-guest-agent / pwd-lock dance: host is not a GCP VM\n")
	}

	// Retry useradd with flock for serialization
	var lastErr error
	var lastOutput string // Captured stdout/stderr of the last useradd
	// attempt — surfaced in the final error when
	// all retries exhaust. Without this, callers
	// see only "exit status 1", which is actively
	// misleading when the real cause was e.g.
	// /etc/passwd locked by another process.
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			// Cloud #163 — exponential backoff with jitter so concurrent
			// CI provisioning bursts don't dogpile. Cap at 60s per wait.
			// Was previously linear (attempt*1s) → total 10s across 5
			// retries, which the lab observed wasn't enough to outlast
			// stale-lock cleanup by external tools (google_guest_agent).
			baseDelay := time.Duration(1<<uint(attempt-1)) * time.Second
			if baseDelay > 60*time.Second {
				baseDelay = 60 * time.Second
			}
			// #nosec G404 -- jitter for retry backoff; not security-sensitive.
			// math/rand is fine here — we want variance to break up
			// thundering-herd patterns, not unguessable output.
			jitter := time.Duration(float64(baseDelay) * 0.3 * (rand.Float64()*2 - 1))
			delay := baseDelay + jitter
			if delay < time.Second {
				delay = time.Second
			}
			fmt.Printf("       Retry attempt %d/%d after %v...\n", attempt+1, maxRetries, delay)
			time.Sleep(delay)

			// Re-check + force-remove any lock files that appeared
			// during the retry window. The pre-loop forceRemoveLockFiles
			// only handles the initial state; a process that died
			// mid-loop (or google-guest-agent restarting against our
			// defer) can leave a fresh stale lock that the previous
			// useradd attempt just hit. Cleaning here unsticks it
			// before the next attempt rather than burning more retries.
			forceRemoveLockFiles(lockFiles, verbose)
		}

		// Create user using flock for serialization
		// flock -w 30 ensures we wait up to 30 seconds to acquire the lock
		fmt.Printf("       Creating user %s (with flock)...\n", username)
		shell := getUserShell()
		// #nosec G204 -- `username` is validated by isValidUsername at the
		// CreateJumpServerAccount entry point (alphanumeric, dash, underscore
		// only). `shell` is a fixed-path constant from getUserShell(). No
		// untrusted input reaches the subprocess invocation.
		cmd := exec.Command("flock", "-w", "30", "/var/lock/containarium-useradd.lock",
			"useradd", username,
			"-s", shell, // nologin (ProxyJump) or containarium-shell (exec into container)
			"-m",                    // Create home directory
			"-K", "SUB_UID_COUNT=0", // Don't allocate subordinate UIDs
			"-K", "SUB_GID_COUNT=0", // Don't allocate subordinate GIDs
			"-c", fmt.Sprintf("Containarium user - %s", username))

		output, err := cmd.CombinedOutput()
		if err == nil {
			fmt.Printf("       ✓ User %s created successfully\n", username)
			return nil
		}

		lastErr = err
		errMsg := string(output)
		lastOutput = errMsg

		// Permission-denied is a permanent error — fail-fast with a
		// pointed message. useradd emits BOTH "Permission denied" and
		// "cannot lock /etc/passwd; try again later" when run as a
		// non-root user: the privileged read+lock fails first, then
		// useradd's generic fallback prints the lock line. Without
		// this guard the lock-error retry branch below catches both
		// lines and we burn 5 retries on a condition that won't fix
		// itself — observed in cloud CI (containarium-run issue #15)
		// where the cloud-daemon process didn't have the capability
		// to add a system user.
		if strings.Contains(errMsg, "Permission denied") {
			fmt.Printf("       useradd failed with Permission denied — daemon process lacks the privilege to add a system user.\n")
			fmt.Printf("       Output: %s\n", errMsg)
			return fmt.Errorf("failed to create user %s: %w\nuseradd requires root (or CAP_CHOWN+CAP_DAC_OVERRIDE on /etc/passwd). Check the daemon's deploy unit (systemd User= directive) or container privileges. Output: %s", username, err, errMsg)
		}

		// Check if it's a lock-related error (retry) or something else (fail immediately)
		if !strings.Contains(errMsg, "cannot lock") && !strings.Contains(errMsg, "try again later") {
			// Not a lock error - fail immediately
			fmt.Printf("       useradd failed (non-lock error)!\n")
			fmt.Printf("       Error: %v\n", err)
			fmt.Printf("       Output: %s\n", errMsg)
			return fmt.Errorf("failed to create user %s: %w\nOutput: %s", username, err, errMsg)
		}

		// Lock error - will retry
		fmt.Printf("       useradd failed with lock error, will retry...\n")
		fmt.Printf("       Output: %s\n", errMsg)

		// Kill any google processes that might have restarted
		killGoogleProcesses(verbose)
	}

	// All retries exhausted — surface the last attempt's useradd output
	// so the operator sees what actually failed (e.g. "cannot lock
	// /etc/passwd; try again later"), not just "exit status 1".
	fmt.Printf("       useradd failed after %d attempts!\n", maxRetries)
	if trimmed := strings.TrimSpace(lastOutput); trimmed != "" {
		return fmt.Errorf("failed to create user %s after %d attempts: %w\nLast useradd output: %s", username, maxRetries, lastErr, trimmed)
	}
	return fmt.Errorf("failed to create user %s after %d attempts: %w", username, maxRetries, lastErr)
}

// killGoogleProcesses kills any google-related processes that might be holding /etc/passwd locks
func killGoogleProcesses(verbose bool) {
	// Find and kill google_guest_agent and related processes
	processes := []string{"google_guest_ag", "google_osconfig", "google_oslogin"}

	for _, procName := range processes {
		cmd := exec.Command("pkill", "-9", "-f", procName)
		if err := cmd.Run(); err == nil && verbose {
			fmt.Printf("       Killed %s processes\n", procName)
		}
	}

	// Also check for any process holding /etc/passwd.lock
	lsofCmd := exec.Command("lsof", "/etc/passwd.lock")
	if output, err := lsofCmd.CombinedOutput(); err == nil && len(output) > 0 {
		// Parse PIDs from lsof output and kill them
		lines := strings.Split(string(output), "\n")
		for _, line := range lines[1:] { // Skip header
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				pid := fields[1]
				if verbose {
					fmt.Printf("       Killing process %s holding passwd.lock\n", pid)
				}
				if err := exec.Command("kill", "-9", pid).Run(); err != nil && verbose {
					fmt.Printf("       Failed to kill process %s: %v\n", pid, err)
				}
			}
		}
	}

	// Brief pause to let processes die
	time.Sleep(500 * time.Millisecond)
}

// forceRemoveLockFiles forcibly removes lock files (used after stopping google-guest-agent)
func forceRemoveLockFiles(lockFiles []string, verbose bool) {
	for _, lockFile := range lockFiles {
		if _, err := os.Stat(lockFile); err == nil {
			fmt.Printf("       Removing lock file: %s\n", lockFile)
			if err := os.Remove(lockFile); err != nil {
				fmt.Printf("       Warning: Could not remove %s: %v\n", lockFile, err)
			} else {
				fmt.Printf("       ✓ Removed %s\n", lockFile)
			}
		}
	}
}

// authorizedKeysHomeRoot is the host's home-directory root. Overridable
// in tests so the authorized_keys helpers don't touch the real /home.
// Production callers should never set this — they want /home.
var authorizedKeysHomeRoot = "/home"

// authorizedKeysUserExists wraps userExists so tests can opt out of the
// "is this username a real host user?" check (test-side users don't
// exist in the OS's passwd database). Production stays bound to
// userExists — invalid usernames should be rejected.
var authorizedKeysUserExists = userExists

// AddAuthorizedKey appends a single SSH public key to the host-side
// /home/<username>/.ssh/authorized_keys, creating the directory + file
// with correct ownership and 0600 mode if missing. Idempotent —
// returns nil without changes if the exact key is already present.
//
// Scope note: this writes the HOST-side keys file (consumed by the
// sentinel's sshpiper keysync via /authorized-keys), not the
// container-internal authorized_keys. For the demo / prod sshpiper
// architecture, that's the right scope — sshpiper terminates the
// client SSH session at the sentinel using these keys, then opens a
// downstream connection to the backend host using its own upstream
// key. Adding to the container-internal file would have no effect on
// who can SSH in via sshpiper.
func AddAuthorizedKey(username, pubKey string) error {
	if !isValidUsername(username) {
		return fmt.Errorf("invalid username: %s", username)
	}
	pubKey = strings.TrimSpace(pubKey)
	if pubKey == "" {
		return fmt.Errorf("empty public key")
	}
	if err := ValidateSSHPublicKey(pubKey); err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}
	if !authorizedKeysUserExists(username) {
		return fmt.Errorf("host user %q does not exist (was the container created?)", username)
	}

	sshDir := filepath.Join(authorizedKeysHomeRoot, username, ".ssh")
	akPath := filepath.Join(sshDir, "authorized_keys")

	// Ensure .ssh exists with 0700.
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", sshDir, err)
	}

	// Read existing content (file may not exist yet).
	var existing []byte
	if b, err := os.ReadFile(akPath); err == nil {
		existing = b
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", akPath, err)
	}

	// Idempotency: skip if exact key is already a line.
	for _, line := range strings.Split(string(existing), "\n") {
		if strings.TrimSpace(line) == pubKey {
			return nil
		}
	}

	// Append + ensure trailing newline.
	var buf strings.Builder
	buf.Write(existing)
	if len(existing) > 0 && !strings.HasSuffix(string(existing), "\n") {
		buf.WriteString("\n")
	}
	buf.WriteString(pubKey)
	buf.WriteString("\n")

	// Atomic write: temp file in same dir + rename.
	tmp, err := os.CreateTemp(sshDir, ".authorized_keys.tmp.*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod tmp: %w", err)
	}
	if _, err := tmp.WriteString(buf.String()); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close tmp: %w", err)
	}
	if err := os.Rename(tmpPath, akPath); err != nil {
		return fmt.Errorf("rename tmp -> %s: %w", akPath, err)
	}

	// Best-effort chown so sshd reads the file as the user (it normally
	// does, but if we created the file as root, the ownership matters
	// for some configurations). Errors are non-fatal — sshd reads as
	// root and the mode is 0600, so the worst case is a slightly
	// surprising owner the operator may want to fix manually.
	_ = exec.Command("chown", "-R", username+":"+username, sshDir).Run()

	return nil
}

// RemoveAuthorizedKey strips a single SSH public key from the host-side
// /home/<username>/.ssh/authorized_keys. No-op (returns nil) if the
// key isn't there. Pairs with AddAuthorizedKey for the
// container-server's add/remove RPCs.
func RemoveAuthorizedKey(username, pubKey string) error {
	if !isValidUsername(username) {
		return fmt.Errorf("invalid username: %s", username)
	}
	pubKey = strings.TrimSpace(pubKey)
	if pubKey == "" {
		return fmt.Errorf("empty public key")
	}
	if !authorizedKeysUserExists(username) {
		return fmt.Errorf("host user %q does not exist", username)
	}

	akPath := filepath.Join(authorizedKeysHomeRoot, username, ".ssh", "authorized_keys")
	existing, err := os.ReadFile(akPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read %s: %w", akPath, err)
	}

	var out strings.Builder
	changed := false
	for _, line := range strings.Split(string(existing), "\n") {
		if strings.TrimSpace(line) == pubKey {
			changed = true
			continue
		}
		out.WriteString(line)
		out.WriteString("\n")
	}
	if !changed {
		return nil
	}

	// Trim the extra trailing newline our reconstruction adds when the
	// input had no terminating newline. Easier than tracking it.
	result := strings.TrimRight(out.String(), "\n") + "\n"
	if strings.TrimSpace(result) == "" {
		result = ""
	}

	sshDir := filepath.Dir(akPath)
	tmp, err := os.CreateTemp(sshDir, ".authorized_keys.tmp.*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod tmp: %w", err)
	}
	if _, err := tmp.WriteString(result); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close tmp: %w", err)
	}
	if err := os.Rename(tmpPath, akPath); err != nil {
		return fmt.Errorf("rename tmp -> %s: %w", akPath, err)
	}
	return nil
}

// CountAuthorizedKeys returns how many non-empty lines are in the
// host-side authorized_keys file for the user. Used by AddSSHKeyResponse
// so the caller can show "you now have N keys" feedback.
func CountAuthorizedKeys(username string) (int32, error) {
	if !isValidUsername(username) {
		return 0, fmt.Errorf("invalid username: %s", username)
	}
	akPath := filepath.Join(authorizedKeysHomeRoot, username, ".ssh", "authorized_keys")
	b, err := os.ReadFile(akPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("read %s: %w", akPath, err)
	}
	n := int32(0)
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n, nil
}
