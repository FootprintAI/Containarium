package container

import (
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/incus"
)

func init() {
	// Seed random number generator for jitter in retry logic
	rand.Seed(time.Now().UnixNano())
}

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

	if verbose {
		fmt.Printf("  ✓ Jump server account created: %s (no shell access, proxy-only)\n", username)
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

// ExtractSSHKeyFromContainer extracts the SSH public key from inside a container
// The key is read from /home/{username}/.ssh/authorized_keys inside the container
func ExtractSSHKeyFromContainer(containerName, username string, verbose bool) (string, error) {
	// Create Incus client
	client, err := incus.New()
	if err != nil {
		return "", fmt.Errorf("failed to connect to Incus: %w", err)
	}

	// Check if container is running
	info, err := client.GetContainer(containerName)
	if err != nil {
		return "", fmt.Errorf("container not found: %w", err)
	}

	// If container is stopped, try to start it temporarily
	wasStarted := false
	if info.State != "Running" {
		if verbose {
			fmt.Printf("       Starting container %s to extract SSH key...\n", containerName)
		}
		if err := client.StartContainer(containerName); err != nil {
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

	keyContent, err := client.ReadFile(containerName, authorizedKeysPath)
	if err != nil {
		// Try root's authorized_keys as fallback
		if verbose {
			fmt.Printf("       Primary path failed, trying /root/.ssh/authorized_keys...\n")
		}
		keyContent, err = client.ReadFile(containerName, "/root/.ssh/authorized_keys")
		if err != nil {
			// Stop container if we started it
			if wasStarted {
				_ = client.StopContainer(containerName, false)
			}
			return "", fmt.Errorf("could not read SSH key from container: %w", err)
		}
	}

	// Stop container if we started it
	if wasStarted {
		if verbose {
			fmt.Printf("       Stopping container %s...\n", containerName)
		}
		_ = client.StopContainer(containerName, false)
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

// ensureProxyOnlyShell ensures the user's shell is set to /usr/sbin/nologin
func ensureProxyOnlyShell(username string, verbose bool) error {
	// Wait for locks to clear before modifying user
	if err := waitForLocksAndRun(func() error {
		cmd := exec.Command("usermod", "-s", "/usr/sbin/nologin", username)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to set shell for %s: %w\nOutput: %s", username, err, output)
		}
		return nil
	}, verbose); err != nil {
		return err
	}

	if verbose {
		fmt.Printf("  ✓ Shell set to /usr/sbin/nologin for %s\n", username)
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
		maxRetries         = 20                      // Further increased for very aggressive google_guest_agent
		baseDelay          = 2 * time.Second         // Doubled from 1s
		maxDelay           = 15 * time.Second        // Increased from 10s
		lastStandDelay     = 120 * time.Second       // Doubled from 60s for final retries
		jitterFraction     = 0.3                     // 30% jitter
		lockFileWaitMax    = 30 * time.Second        // Doubled from 15s
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
func isGoogleGuestAgentActive(verbose bool) bool {
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
	fmt.Printf("       Temporarily stopping google-guest-agent to avoid race condition...\n")

	// Stop google-guest-agent
	cmd := exec.Command("systemctl", "stop", "google-guest-agent")
	if output, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("       Warning: Failed to stop google-guest-agent: %v\n%s\n", err, output)
		fmt.Printf("       Proceeding anyway...\n")
	} else {
		fmt.Printf("       ✓ google-guest-agent stopped\n")
	}

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

	// Wait a moment for the agent to fully stop
	fmt.Printf("       Waiting 3 seconds for agent to stop...\n")
	time.Sleep(3 * time.Second)

	// Check if agent actually stopped
	checkCmd := exec.Command("systemctl", "is-active", "google-guest-agent")
	if statusOutput, _ := checkCmd.CombinedOutput(); len(statusOutput) > 0 {
		fmt.Printf("       Agent status after stop: %s\n", string(statusOutput))
	}

	// Check for and remove any stale lock files (using rm command to bypass systemd restrictions)
	lockFiles := []string{"/etc/passwd.lock", "/etc/shadow.lock", "/etc/.pwd.lock", "/etc/group.lock"}
	for _, lockFile := range lockFiles {
		if _, err := os.Stat(lockFile); err == nil {
			fmt.Printf("       WARNING: Stale lock file exists: %s, removing it...\n", lockFile)
			rmCmd := exec.Command("rm", "-f", lockFile)
			if rmOutput, rmErr := rmCmd.CombinedOutput(); rmErr != nil {
				fmt.Printf("       Warning: Failed to remove %s: %v\n%s\n", lockFile, rmErr, string(rmOutput))
			} else {
				fmt.Printf("       ✓ Removed stale lock file: %s\n", lockFile)
			}
		}
	}

	// Create user
	fmt.Printf("       Creating user %s...\n", username)
	cmd = exec.Command("useradd", username,
		"-s", "/usr/sbin/nologin", // No shell access - ProxyJump only!
		"-m",                        // Create home directory
		"-c", fmt.Sprintf("Containarium user - %s", username))

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Print detailed error info
		fmt.Printf("       useradd failed!\n")
		fmt.Printf("       Error: %v\n", err)
		fmt.Printf("       Output: %s\n", string(output))

		// Check lock files again
		for _, lockFile := range lockFiles {
			if _, statErr := os.Stat(lockFile); statErr == nil {
				fmt.Printf("       Lock file present after failure: %s\n", lockFile)
				// Try to see what's holding it
				lsofCmd := exec.Command("lsof", lockFile)
				if lsofOut, lsofErr := lsofCmd.CombinedOutput(); lsofErr == nil && len(lsofOut) > 0 {
					fmt.Printf("       Process holding lock:\n%s\n", string(lsofOut))
				}
			}
		}

		return fmt.Errorf("failed to create user %s: %w\nOutput: %s", username, err, output)
	}

	// Success!
	fmt.Printf("       ✓ User %s created successfully\n", username)
	return nil
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
func disableGuestAgentAccountsDaemon(configPath string, verbose bool) error {
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
