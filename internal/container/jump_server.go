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
	// Use retry logic to handle transient /etc/passwd lock conflicts with google_guest_agent
	if err := retryUserCommand(func() error {
		cmd := exec.Command("useradd", username,
			"-s", "/usr/sbin/nologin", // No shell access - ProxyJump only!
			"-m",                        // Create home directory
			"-c", fmt.Sprintf("Containarium user - %s", username))

		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to create user %s: %w\nOutput: %s", username, err, output)
		}
		return nil
	}, verbose); err != nil {
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

	// Delete user and home directory with retry logic
	if err := retryUserCommand(func() error {
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
	authKeysFile := filepath.Join("/home", username, ".ssh", "authorized_keys")

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

	if verbose {
		fmt.Printf("  ✓ SSH key added for %s\n", username)
	}

	return nil
}

// ensureProxyOnlyShell ensures the user's shell is set to /usr/sbin/nologin
func ensureProxyOnlyShell(username string, verbose bool) error {
	// Use retry logic to handle transient /etc/passwd lock conflicts
	if err := retryUserCommand(func() error {
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

// retryUserCommand retries a user management command with exponential backoff and lock file checking
// This handles transient /etc/passwd lock conflicts with google_guest_agent or other system processes
func retryUserCommand(cmdFunc func() error, verbose bool) error {
	const (
		maxRetries         = 6                      // Increased from 5 to 6 for "last stand" retry
		baseDelay          = 500 * time.Millisecond
		maxDelay           = 5 * time.Second
		lastStandDelay     = 30 * time.Second // Final retry waits much longer
		jitterFraction     = 0.3              // 30% jitter
		lockFileWaitMax    = 10 * time.Second // Max time to wait for lock file to clear
		lockFileCheckInterval = 250 * time.Millisecond
	)

	var lastErr error

	// Pre-check: Wait for lock files to clear before first attempt
	if verbose {
		fmt.Printf("       Checking for lock files...\n")
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

		// "Last Stand" retry: If this is the second-to-last attempt, wait much longer
		if attempt == maxRetries-2 {
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

	// All retries exhausted
	return fmt.Errorf("failed after %d retries: %w\nHint: The google_guest_agent may be actively managing users. Check 'sudo journalctl -u google-guest-agent' for details", maxRetries, lastErr)
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
