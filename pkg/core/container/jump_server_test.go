package container

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestIsValidUsername(t *testing.T) {
	tests := []struct {
		name     string
		username string
		want     bool
	}{
		// Valid usernames
		{
			name:     "simple lowercase",
			username: "alice",
			want:     true,
		},
		{
			name:     "with numbers",
			username: "alice123",
			want:     true,
		},
		{
			name:     "with hyphen",
			username: "alice-dev",
			want:     true,
		},
		{
			name:     "with underscore",
			username: "alice_dev",
			want:     true,
		},
		{
			name:     "uppercase",
			username: "Alice",
			want:     true,
		},
		{
			name:     "mixed case with numbers",
			username: "Alice123",
			want:     true,
		},
		{
			name:     "single character",
			username: "a",
			want:     true,
		},
		{
			name:     "max length 32",
			username: strings.Repeat("a", 32),
			want:     true,
		},

		// Invalid usernames
		{
			name:     "empty string",
			username: "",
			want:     false,
		},
		{
			name:     "too long",
			username: strings.Repeat("a", 33),
			want:     false,
		},
		{
			name:     "starts with number",
			username: "123alice",
			want:     false,
		},
		{
			name:     "starts with hyphen",
			username: "-alice",
			want:     false,
		},
		{
			name:     "contains space",
			username: "alice dev",
			want:     false,
		},
		{
			name:     "contains special char @",
			username: "alice@dev",
			want:     false,
		},
		{
			name:     "contains special char .",
			username: "alice.dev",
			want:     false,
		},
		{
			name:     "contains special char !",
			username: "alice!",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidUsername(tt.username)
			if got != tt.want {
				t.Errorf("isValidUsername(%q) = %v, want %v", tt.username, got, tt.want)
			}
		})
	}
}

func TestUserExists(t *testing.T) {
	// Test with a user that definitely exists on Unix systems
	t.Run("root user exists", func(t *testing.T) {
		// root should exist on all Unix systems
		if got := UserExists("root"); !got {
			t.Errorf("UserExists(\"root\") = false, want true")
		}
	})

	t.Run("nonexistent user", func(t *testing.T) {
		// This user should not exist
		if got := UserExists("nonexistent_user_12345"); got {
			t.Errorf("UserExists(\"nonexistent_user_12345\") = true, want false")
		}
	})
}

func TestParseSSHKeyFromAuthorizedKeys(t *testing.T) {
	tests := []struct {
		name           string
		content        string
		wantKey        string
		wantErr        bool
	}{
		{
			name:    "single RSA key",
			content: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... user@host",
			wantKey: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... user@host",
			wantErr: false,
		},
		{
			name:    "single ED25519 key",
			content: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGj... user@host",
			wantKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGj... user@host",
			wantErr: false,
		},
		{
			name:    "single ECDSA key",
			content: "ssh-ecdsa AAAAE2VjZHNhLXNoYTItbmlzdHAyN... user@host",
			wantKey: "ssh-ecdsa AAAAE2VjZHNhLXNoYTItbmlzdHAyN... user@host",
			wantErr: false,
		},
		{
			name:    "ecdsa-sha2-nistp256 key",
			content: "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTI... user@host",
			wantKey: "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTI... user@host",
			wantErr: false,
		},
		{
			name: "multiple keys returns first",
			content: `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... first@host
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGj... second@host`,
			wantKey: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... first@host",
			wantErr: false,
		},
		{
			name: "ignores comments",
			content: `# This is a comment
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... user@host`,
			wantKey: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... user@host",
			wantErr: false,
		},
		{
			name: "ignores empty lines",
			content: `

ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGj... user@host

`,
			wantKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGj... user@host",
			wantErr: false,
		},
		{
			name:    "empty content",
			content: "",
			wantKey: "",
			wantErr: true,
		},
		{
			name:    "only comments",
			content: "# This is a comment\n# Another comment",
			wantKey: "",
			wantErr: true,
		},
		{
			name:    "invalid key format",
			content: "not-a-valid-ssh-key some-data",
			wantKey: "",
			wantErr: true,
		},
		{
			name:    "key with leading whitespace",
			content: "  ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... user@host",
			wantKey: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... user@host",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSSHKeyFromContent(tt.content)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSSHKeyFromContent() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.wantKey {
				t.Errorf("parseSSHKeyFromContent() = %q, want %q", got, tt.wantKey)
			}
		})
	}
}

// parseSSHKeyFromContent is a helper function extracted from ExtractSSHKeyFromContainer
// for easier testing. It parses the content of an authorized_keys file and returns
// the first valid SSH public key.
func parseSSHKeyFromContent(content string) (string, error) {
	lines := strings.Split(content, "\n")
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

	return "", errNoValidSSHKey
}

var errNoValidSSHKey = &parseError{"no valid SSH key found in authorized_keys"}

type parseError struct {
	msg string
}

func (e *parseError) Error() string {
	return e.msg
}

func TestContainerNameToUsername(t *testing.T) {
	tests := []struct {
		name          string
		containerName string
		wantUsername  string
		wantValid     bool
	}{
		{
			name:          "standard container name",
			containerName: "alice-container",
			wantUsername:  "alice",
			wantValid:     true,
		},
		{
			name:          "container with hyphenated username",
			containerName: "alice-dev-container",
			wantUsername:  "alice-dev",
			wantValid:     true,
		},
		{
			name:          "non-standard name without suffix",
			containerName: "alice",
			wantUsername:  "alice",
			wantValid:     false, // doesn't follow naming convention
		},
		{
			name:          "system container",
			containerName: "_containarium-core",
			wantUsername:  "_containarium-core",
			wantValid:     false,
		},
		{
			name:          "empty name",
			containerName: "",
			wantUsername:  "",
			wantValid:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUsername, gotValid := containerNameToUsername(tt.containerName)
			if gotUsername != tt.wantUsername {
				t.Errorf("containerNameToUsername() username = %q, want %q", gotUsername, tt.wantUsername)
			}
			if gotValid != tt.wantValid {
				t.Errorf("containerNameToUsername() valid = %v, want %v", gotValid, tt.wantValid)
			}
		})
	}
}

// containerNameToUsername extracts the username from a container name
// following the Containarium naming convention: {username}-container
func containerNameToUsername(containerName string) (username string, valid bool) {
	const suffix = "-container"
	if strings.HasSuffix(containerName, suffix) {
		return strings.TrimSuffix(containerName, suffix), true
	}
	return containerName, false
}

// TestWaitForLockFiles tests the lock file waiting logic
func TestWaitForLockFiles(t *testing.T) {
	// Create a temporary directory for test lock files
	tempDir := t.TempDir()

	t.Run("no lock files - returns immediately", func(t *testing.T) {
		lockFiles := []string{
			tempDir + "/passwd.lock",
			tempDir + "/shadow.lock",
		}
		cleared, iterations := waitForLockFilesCleared(lockFiles, 5, 10*time.Millisecond)
		if !cleared {
			t.Error("expected locks to be cleared when no lock files exist")
		}
		if iterations != 1 {
			t.Errorf("expected 1 iteration, got %d", iterations)
		}
	})

	t.Run("lock file exists then clears", func(t *testing.T) {
		lockFile := tempDir + "/test.lock"
		lockFiles := []string{lockFile}

		// Create lock file
		if err := os.WriteFile(lockFile, []byte("locked"), 0644); err != nil {
			t.Fatalf("failed to create lock file: %v", err)
		}

		// Start a goroutine to remove the lock file after a short delay
		go func() {
			time.Sleep(50 * time.Millisecond)
			os.Remove(lockFile)
		}()

		cleared, iterations := waitForLockFilesCleared(lockFiles, 10, 20*time.Millisecond)
		if !cleared {
			t.Error("expected locks to be cleared after file was removed")
		}
		if iterations < 2 {
			t.Errorf("expected at least 2 iterations, got %d", iterations)
		}
	})

	t.Run("lock file never clears - times out", func(t *testing.T) {
		lockFile := tempDir + "/persistent.lock"
		lockFiles := []string{lockFile}

		// Create lock file that won't be removed
		if err := os.WriteFile(lockFile, []byte("locked"), 0644); err != nil {
			t.Fatalf("failed to create lock file: %v", err)
		}
		defer os.Remove(lockFile)

		cleared, iterations := waitForLockFilesCleared(lockFiles, 3, 10*time.Millisecond)
		if cleared {
			t.Error("expected locks NOT to be cleared when file persists")
		}
		if iterations != 3 {
			t.Errorf("expected 3 iterations (max), got %d", iterations)
		}
	})

	t.Run("multiple lock files - all must clear", func(t *testing.T) {
		lockFile1 := tempDir + "/lock1.lock"
		lockFile2 := tempDir + "/lock2.lock"
		lockFiles := []string{lockFile1, lockFile2}

		// Create both lock files
		os.WriteFile(lockFile1, []byte("locked"), 0644)
		os.WriteFile(lockFile2, []byte("locked"), 0644)

		// Remove first file quickly, second file after delay
		go func() {
			time.Sleep(20 * time.Millisecond)
			os.Remove(lockFile1)
			time.Sleep(40 * time.Millisecond)
			os.Remove(lockFile2)
		}()

		cleared, _ := waitForLockFilesCleared(lockFiles, 10, 20*time.Millisecond)
		if !cleared {
			t.Error("expected locks to be cleared after both files were removed")
		}
	})
}

// waitForLockFilesCleared is a testable version of the lock file waiting logic
// Returns (cleared, iterations) where cleared is true if all locks cleared,
// and iterations is how many times we checked
func waitForLockFilesCleared(lockFiles []string, maxAttempts int, interval time.Duration) (bool, int) {
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		allClear := true
		for _, lockFile := range lockFiles {
			if _, err := os.Stat(lockFile); err == nil {
				allClear = false
				break
			}
		}
		if allClear {
			return true, attempt
		}
		if attempt < maxAttempts {
			time.Sleep(interval)
		}
	}
	return false, maxAttempts
}

// TestLockFileDetection tests lock file existence detection
func TestLockFileDetection(t *testing.T) {
	tempDir := t.TempDir()

	t.Run("detect existing lock file", func(t *testing.T) {
		lockFile := tempDir + "/exists.lock"
		os.WriteFile(lockFile, []byte("locked"), 0644)
		defer os.Remove(lockFile)

		exists := lockFileExists(lockFile)
		if !exists {
			t.Error("expected lock file to be detected as existing")
		}
	})

	t.Run("detect non-existing lock file", func(t *testing.T) {
		lockFile := tempDir + "/not-exists.lock"

		exists := lockFileExists(lockFile)
		if exists {
			t.Error("expected lock file to be detected as NOT existing")
		}
	})

	t.Run("detect lock file in non-existing directory", func(t *testing.T) {
		lockFile := tempDir + "/nonexistent/dir/file.lock"

		exists := lockFileExists(lockFile)
		if exists {
			t.Error("expected lock file to be detected as NOT existing")
		}
	})
}

// lockFileExists checks if a lock file exists
func lockFileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// TestCheckAllLockFilesClear tests the logic for checking multiple lock files
func TestCheckAllLockFilesClear(t *testing.T) {
	tempDir := t.TempDir()

	t.Run("all clear when no files exist", func(t *testing.T) {
		lockFiles := []string{
			tempDir + "/a.lock",
			tempDir + "/b.lock",
			tempDir + "/c.lock",
		}
		if !allLockFilesClear(lockFiles) {
			t.Error("expected all locks to be clear when no files exist")
		}
	})

	t.Run("not clear when one file exists", func(t *testing.T) {
		lockFile := tempDir + "/exists.lock"
		os.WriteFile(lockFile, []byte("locked"), 0644)
		defer os.Remove(lockFile)

		lockFiles := []string{
			tempDir + "/a.lock",
			lockFile,
			tempDir + "/c.lock",
		}
		if allLockFilesClear(lockFiles) {
			t.Error("expected locks NOT to be clear when one file exists")
		}
	})

	t.Run("not clear when all files exist", func(t *testing.T) {
		lockFile1 := tempDir + "/x.lock"
		lockFile2 := tempDir + "/y.lock"
		os.WriteFile(lockFile1, []byte("locked"), 0644)
		os.WriteFile(lockFile2, []byte("locked"), 0644)
		defer os.Remove(lockFile1)
		defer os.Remove(lockFile2)

		lockFiles := []string{lockFile1, lockFile2}
		if allLockFilesClear(lockFiles) {
			t.Error("expected locks NOT to be clear when all files exist")
		}
	})

	t.Run("empty lock file list is clear", func(t *testing.T) {
		if !allLockFilesClear([]string{}) {
			t.Error("expected empty lock file list to be clear")
		}
	})
}

// allLockFilesClear checks if all lock files are cleared
func allLockFilesClear(lockFiles []string) bool {
	for _, lockFile := range lockFiles {
		if _, err := os.Stat(lockFile); err == nil {
			return false
		}
	}
	return true
}

// Benchmark tests
func BenchmarkIsValidUsername(b *testing.B) {
	usernames := []string{
		"alice",
		"alice-dev-123",
		"a",
		strings.Repeat("a", 32),
		"invalid user",
		"123invalid",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, u := range usernames {
			_ = isValidUsername(u)
		}
	}
}

func BenchmarkParseSSHKeyFromContent(b *testing.B) {
	content := `# SSH keys for user
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGjGnWPALDcPQnZaGsYRTjrZQdjU1Q2VmMz1cPEhDrN user@host

# Another comment
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7nZ1cF+Gzox9y8a0g5k2VmGp3qQ user@another
`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = parseSSHKeyFromContent(content)
	}
}
