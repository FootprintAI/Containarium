package container

import (
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Note: As of Go 1.20, rand is automatically seeded

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
		if !((ch >= 'a' && ch <= 'z') ||
			(ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') ||
			ch == '-' || ch == '_') {
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
	defer f.Close()

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

// waitForLocksAndRun stops google-guest-agent, executes the function, then restarts it
func waitForLocksAndRun(fn func() error, verbose bool) error {
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

// retryUserCommand retries a user management command with exponential backoff and lock file checking
// This handles transient /etc/passwd lock conflicts with google_guest_agent or other system processes
func retryUserCommand(cmdFunc func() error, verbose bool) error {
	const (
		maxRetries            = 20                // Further increased for very aggressive google_guest_agent
		baseDelay             = 2 * time.Second   // Doubled from 1s
		maxDelay              = 15 * time.Second  // Increased from 10s
		lastStandDelay        = 120 * time.Second // Doubled from 60s for final retries
		jitterFraction        = 0.3               // 30% jitter
		lockFileWaitMax       = 30 * time.Second  // Doubled from 15s
		lockFileCheckInterval = 500 * time.Millisecond
	)

	var lastErr error

	// Pre-check: Wait for lock files to clear before first attempt
	if verbose {
		fmt.Printf("       Checking for lock files...\n")
	}

	// Check if google_guest_agent is running
	if isGoogleGuestAgentActive(verbose) && verbose {
		fmt.Printf("       Note: google_guest_agent is active and may be managing users\n")
	}

	if err := waitForLockFilesClear(lockFileWaitMax, lockFileCheckInterval, verbose); err != nil {
		if verbose {
			fmt.Printf("       Warning: Lock files still present after %v, proceeding anyway\n", lockFileWaitMax)
		}
	}

	for attempt := 0; attempt < maxRetries; attempt++ {
		// Execute the command
		err := cmdFunc()

		// Success - return immediately
		if err == nil {
			return nil
		}

		// Check if error is a lock-related error
		errMsg := err.Error()
		isLockError := strings.Contains(errMsg, "cannot lock /etc/passwd") ||
			strings.Contains(errMsg, "cannot lock /etc/shadow") ||
			strings.Contains(errMsg, "try again later") ||
			strings.Contains(errMsg, "Resource temporarily unavailable")

		// If not a lock error, fail immediately (don't retry)
		if !isLockError {
			return err
		}

		lastErr = err

		// If this was the last attempt, don't sleep
		if attempt == maxRetries-1 {
			break
		}

		var delay time.Duration

		// "Last Stand" retries: If we're in the final 5 attempts, wait much longer (120s each)
		if attempt >= maxRetries-5 {
			delay = lastStandDelay
			if verbose {
				fmt.Printf("       Lock conflict persistent, executing last stand retry in %v (attempt %d/%d)...\n",
					delay, attempt+2, maxRetries)
			}
		} else {
			// Calculate exponential backoff delay: baseDelay * 2^attempt
			delay = baseDelay * time.Duration(1<<uint(attempt))
			if delay > maxDelay {
				delay = maxDelay
			}

			// Add jitter: ±30% randomization to prevent thundering herd
			jitter := time.Duration(float64(delay) * jitterFraction * (rand.Float64()*2 - 1))
			delay += jitter

			if verbose {
				fmt.Printf("       Lock conflict detected, retrying in %v (attempt %d/%d)...\n",
					delay.Round(time.Millisecond), attempt+2, maxRetries)
			}
		}

		time.Sleep(delay)
	}

	// All retries exhausted - provide helpful guidance
	return fmt.Errorf("failed after %d retries: %w\n\n"+
		"The google_guest_agent is persistently locking /etc/passwd.\n"+
		"Suggestions:\n"+
		"  1. Check guest agent activity: sudo journalctl -u google-guest-agent -n 50\n"+
		"  2. Wait a few minutes for the guest agent to complete its tasks\n"+
		"  3. Temporarily disable OS Login if not needed: sudo systemctl stop google-guest-agent\n"+
		"  4. Try again - the lock may clear in a few minutes",
		maxRetries, lastErr)
}

// waitForLockFilesClear waits for common lock files to be released
// Returns nil if files clear, error if timeout exceeded (but this is non-fatal)
func waitForLockFilesClear(maxWait time.Duration, checkInterval time.Duration, verbose bool) error {
	lockFiles := []string{
		"/etc/passwd.lock",
		"/etc/shadow.lock",
		"/etc/.pwd.lock",
	}

	start := time.Now()
	for {
		allClear := true
		for _, lockFile := range lockFiles {
			if _, err := os.Stat(lockFile); err == nil {
				allClear = false
				if verbose && time.Since(start) > 2*time.Second {
					fmt.Printf("       Waiting for %s to clear...\n", filepath.Base(lockFile))
				}
				break
			}
		}

		if allClear {
			return nil
		}

		if time.Since(start) >= maxWait {
			return fmt.Errorf("lock files still present after %v", maxWait)
		}

		time.Sleep(checkInterval)
	}
}

// isGoogleGuestAgentActive checks if google_guest_agent is currently running
func isGoogleGuestAgentActive(_ bool) bool {
	cmd := exec.Command("pgrep", "-x", "google_guest_ag")
	err := cmd.Run()
	return err == nil
}

// checkLockFiles checks for the presence of lock files and reports them
func checkLockFiles(stage string) {
	lockFiles := []string{
		"/etc/passwd.lock",
		"/etc/shadow.lock",
		"/etc/.pwd.lock",
		"/etc/group.lock",
	}

	fmt.Printf("       [DEBUG] Lock file check (%s):\n", stage)
	foundLocks := false
	for _, lockFile := range lockFiles {
		if _, err := os.Stat(lockFile); err == nil {
			fmt.Printf("       [DEBUG]   ✗ LOCKED: %s exists\n", lockFile)
			foundLocks = true

			// Try to see what process holds it
			cmd := exec.Command("lsof", lockFile)
			if output, err := cmd.CombinedOutput(); err == nil && len(output) > 0 {
				fmt.Printf("       [DEBUG]     Process holding lock:\n%s\n", string(output))
			}
		} else {
			fmt.Printf("       [DEBUG]   ✓ Free: %s\n", lockFile)
		}
	}
	if !foundLocks {
		fmt.Printf("       [DEBUG]   ✓ All lock files clear\n")
	}
}

// checkGuestAgentStatus checks if google-guest-agent is running
func checkGuestAgentStatus(stage string) {
	fmt.Printf("       [DEBUG] Guest agent status (%s):\n", stage)

	// Check if service is running
	cmd := exec.Command("systemctl", "is-active", "google-guest-agent")
	if output, err := cmd.CombinedOutput(); err == nil {
		fmt.Printf("       [DEBUG]   Service status: %s\n", string(output))
	} else {
		fmt.Printf("       [DEBUG]   Service status: inactive or error\n")
	}

	// Check for running processes
	cmd = exec.Command("pgrep", "-a", "google")
	if output, err := cmd.CombinedOutput(); err == nil && len(output) > 0 {
		fmt.Printf("       [DEBUG]   Running Google processes:\n%s\n", string(output))
	} else {
		fmt.Printf("       [DEBUG]   No Google processes found\n")
	}
}

// retryUseraddWithLockWait stops google-guest-agent, creates user, then restarts it
func retryUseraddWithLockWait(username string, verbose bool) error {
	const maxRetries = 5 // Retry up to 5 times with flock

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
	lockFiles := []string{"/etc/passwd.lock", "/etc/shadow.lock", "/etc/.pwd.lock", "/etc/group.lock"}
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
			fmt.Printf("       Retry attempt %d/%d...\n", attempt+1, maxRetries)
			time.Sleep(time.Duration(attempt) * time.Second) // Increasing backoff
		}

		// Create user using flock for serialization
		// flock -w 30 ensures we wait up to 30 seconds to acquire the lock
		fmt.Printf("       Creating user %s (with flock)...\n", username)
		shell := getUserShell()
		cmd = exec.Command("flock", "-w", "30", "/var/lock/containarium-useradd.lock",
			"useradd", username,
			"-s", shell, // nologin (ProxyJump) or containarium-shell (exec into container)
			"-m",                      // Create home directory
			"-K", "SUB_UID_COUNT=0",   // Don't allocate subordinate UIDs
			"-K", "SUB_GID_COUNT=0",   // Don't allocate subordinate GIDs
			"-c", fmt.Sprintf("Containarium user - %s", username))

		output, err := cmd.CombinedOutput()
		if err == nil {
			fmt.Printf("       ✓ User %s created successfully\n", username)
			return nil
		}

		lastErr = err
		errMsg := string(output)
		lastOutput = errMsg

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
				exec.Command("kill", "-9", pid).Run()
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

// withGuestAgentAccountsDaemonDisabled temporarily disables the google-guest-agent's accounts daemon,
// executes the provided function, then re-enables it.
// This prevents /etc/passwd lock conflicts during user operations.
func withGuestAgentAccountsDaemonDisabled(fn func() error, verbose bool) error {
	const configPath = "/etc/default/instance_configs.cfg"

	fmt.Printf("       [DEBUG] Starting guest agent accounts daemon disable procedure\n")

	// Check if config file exists
	configExists := false
	if _, err := os.Stat(configPath); err == nil {
		configExists = true
		fmt.Printf("       [DEBUG] Config file exists at %s\n", configPath)
	} else {
		fmt.Printf("       [DEBUG] Config file does not exist at %s\n", configPath)
	}

	// Read existing config if it exists
	var existingConfig []byte
	if configExists {
		var err error
		existingConfig, err = os.ReadFile(configPath)
		if err != nil {
			fmt.Printf("       [DEBUG] Warning: Could not read existing config: %v\n", err)
		} else {
			fmt.Printf("       [DEBUG] Read existing config (%d bytes)\n", len(existingConfig))
		}
	}

	// Check lock files before disabling
	checkLockFiles("before disabling")

	// Check if guest agent is running
	checkGuestAgentStatus("before disabling")

	// Disable accounts daemon
	fmt.Printf("       [DEBUG] Calling disableGuestAgentAccountsDaemon...\n")
	if err := disableGuestAgentAccountsDaemon(configPath, verbose); err != nil {
		fmt.Printf("       [DEBUG] Failed to disable accounts daemon: %v\n", err)
		fmt.Printf("       [DEBUG] Proceeding anyway...\n")
	} else {
		fmt.Printf("       [DEBUG] ✓ Accounts daemon disabled successfully\n")
	}

	// Check lock files after disabling
	checkLockFiles("after disabling")

	// Check if guest agent is still running
	checkGuestAgentStatus("after disabling")

	// Ensure we re-enable the daemon when done (defer)
	defer func() {
		fmt.Printf("       [DEBUG] Starting guest agent accounts daemon re-enable procedure\n")

		// Restore original config if it existed, otherwise remove our config
		if configExists && existingConfig != nil {
			fmt.Printf("       [DEBUG] Restoring original config (%d bytes)\n", len(existingConfig))
			if err := os.WriteFile(configPath, existingConfig, 0644); err != nil {
				fmt.Printf("       [DEBUG] Warning: Failed to restore config: %v\n", err)
			} else {
				fmt.Printf("       [DEBUG] ✓ Original config restored\n")
			}
		} else {
			fmt.Printf("       [DEBUG] Removing config file we created\n")
			if err := os.Remove(configPath); err != nil {
				fmt.Printf("       [DEBUG] Warning: Failed to remove config: %v\n", err)
			} else {
				fmt.Printf("       [DEBUG] ✓ Config file removed\n")
			}
		}

		// Restart guest agent to apply changes
		fmt.Printf("       [DEBUG] Restarting google-guest-agent to re-enable accounts daemon\n")
		cmd := exec.Command("systemctl", "restart", "google-guest-agent")
		if output, err := cmd.CombinedOutput(); err != nil {
			fmt.Printf("       [DEBUG] Warning: Failed to restart google-guest-agent: %v\n", err)
			fmt.Printf("       [DEBUG] Output: %s\n", string(output))
		} else {
			fmt.Printf("       [DEBUG] ✓ google-guest-agent restarted\n")
		}

		fmt.Printf("       [DEBUG] ✓ Accounts daemon re-enabled\n")
	}()

	// Execute the user operation
	fmt.Printf("       [DEBUG] Executing user operation...\n")
	err := fn()
	if err != nil {
		fmt.Printf("       [DEBUG] User operation failed: %v\n", err)
	} else {
		fmt.Printf("       [DEBUG] ✓ User operation succeeded\n")
	}
	return err
}

// disableGuestAgentAccountsDaemon writes configuration to disable the accounts daemon
func disableGuestAgentAccountsDaemon(configPath string, _ bool) error {
	// Create configuration content
	config := "[Daemons]\naccounts_daemon = false\n"

	fmt.Printf("       [DEBUG] Writing config to %s\n", configPath)
	fmt.Printf("       [DEBUG] Config content:\n%s\n", config)

	// Write configuration
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		fmt.Printf("       [DEBUG] Failed to write config file: %v\n", err)
		return fmt.Errorf("failed to write config: %w", err)
	}
	fmt.Printf("       [DEBUG] ✓ Config file written successfully\n")

	// Verify the file was written
	if content, err := os.ReadFile(configPath); err == nil {
		fmt.Printf("       [DEBUG] Verified config content (%d bytes):\n%s\n", len(content), string(content))
	}

	// Restart google-guest-agent to apply changes
	fmt.Printf("       [DEBUG] Restarting google-guest-agent service...\n")
	cmd := exec.Command("systemctl", "restart", "google-guest-agent")
	if output, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("       [DEBUG] Failed to restart google-guest-agent: %v\n", err)
		fmt.Printf("       [DEBUG] Output: %s\n", string(output))
		return fmt.Errorf("failed to restart google-guest-agent: %w", err)
	}
	fmt.Printf("       [DEBUG] ✓ google-guest-agent restarted successfully\n")

	// Wait a moment for the daemon to stop its account management
	fmt.Printf("       [DEBUG] Waiting 2 seconds for accounts daemon to stop...\n")
	time.Sleep(2 * time.Second)
	fmt.Printf("       [DEBUG] ✓ Wait complete\n")

	return nil
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
